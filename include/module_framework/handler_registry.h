// include/module_framework/handler_registry.h
// Handler registry for module-level and device-level routing

#ifndef HANDLER_REGISTRY_H
#define HANDLER_REGISTRY_H

#include <functional>
#include <unordered_map>
#include <vector>
#include <string>
#include <string_view>
#include <mutex>
#include "note_messaging.h"
#include "notebytes.h"
#include "error.h"

namespace NoteDaemon {

/**
 * Handler function type - receives NoteBytes::Object messages
 */
using Handler = std::function<void(const NoteBytes::Object&)>;

/**
 * Device-level handler registry
 * 
 * Each module has its own HandlerRegistry for device-specific routing.
 * This handles routing: message + device_id → handler
 * 
 * Design philosophy:
 * - Core routes to module based on module_id only
 * - Each module handles its own message_type routing internally via its own handler registry
 * - Device-specific handlers remain here since devices are external (not internal to modules)
 */
class HandlerRegistry {
public:
    HandlerRegistry() = default;
    ~HandlerRegistry() = default;
    
    // Prevent copying (contains mutex)
    HandlerRegistry(const HandlerRegistry&) = delete;
    HandlerRegistry& operator=(const HandlerRegistry&) = delete;
    
    // Note: Move constructor/assignment are implicitly deleted because std::mutex cannot be moved

    // ===== Registration =====
    
    /**
     * Register a handler for a message type (global handler)
     * Used for messages that aren't specific to any device
     * Uses NoteBytes::Value as key for direct comparison without string conversion
     */
    void register_handler(const NoteBytes::Value& message_type, Handler handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        global_handlers_[message_type] = std::move(handler);
    }
    


    // ===== Dispatch =====
    
    /**
     * Dispatch a message to global handlers
     * 
     * Note: Module-level routing is handled by the module itself.
     * The core routes to the module based on module_id, and the module
     * handles message_type routing internally via its own handler registry.
     */
    Error dispatch(const NoteBytes::Object& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Extract event/cmd from message
        auto* event_val = message.get(NoteMessaging::Keys::EVENT);
        auto* cmd_val = message.get(NoteMessaging::Keys::CMD);
        
        // Get message type as NoteBytes::Value - no string conversion needed
        const NoteBytes::Value* message_type_val = nullptr;
        if (event_val) {
            message_type_val = event_val;
        } else if (cmd_val) {
            message_type_val = cmd_val;
        }
        
        if (!message_type_val) {
            return Error::from_code(ErrorCodes::INVALID_MESSAGE, 
                                    "Message has no EVENT or CMD field");
        }
        

        
        // ROUTING: Check global handlers
        // Use NoteBytes::Value directly for lookup - no string conversion
        auto global_it = global_handlers_.find(*message_type_val);
        if (global_it != global_handlers_.end()) {
            global_it->second(message);
            return Error(ErrorCodes::SUCCESS, "");
        }
        
        return Error::from_code(ErrorCodes::HANDLER_NOT_FOUND,
                                "No handler for message type: " + message_type_val->as_string());
    }
    
    // ===== Query =====
    
    /**
     * Check if a message type has any handler
     */
    bool has_handler(const NoteBytes::Value& message_type) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return global_handlers_.count(message_type) > 0;
    }
    
    /**
     * Get list of registered message types
     */
    std::vector<std::string> get_registered_types() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> types;
        for (const auto& [key, _] : global_handlers_) {
            types.push_back(key.as_string());
        }
        return types;
    }
    
    /**
     * Get count of registered handlers
     */
    size_t handler_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return global_handlers_.size();
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<NoteBytes::Value, Handler> global_handlers_;
};

/**
 * Module routing registry
 * 
 * Maps message types to module IDs for core-level routing.
 * This is owned by the core, not by modules.
 * 
 * This is a separate concern from HandlerRegistry - it maps message_type → module_id
 * for the initial core-level routing decision.
 */
class ModuleRoutingRegistry {
public:
    ModuleRoutingRegistry() = default;
    ~ModuleRoutingRegistry() = default;
    
    // Prevent copying
    ModuleRoutingRegistry(const ModuleRoutingRegistry&) = delete;
    ModuleRoutingRegistry& operator=(const ModuleRoutingRegistry&) = delete;

    /**
     * Register a module as handler for certain message types
     * @param module_id The module's unique identifier (e.g., "note_usb")
     * @param message_types Vector of message types this module handles
     */
    void register_module(const std::string& module_id,
                        const std::vector<std::string>& message_types) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& type : message_types) {
            message_type_to_module_[type] = module_id;
        }
    }
    
    /**
     * Look up which module handles a message type
     * @param message_type The message type to look up
     * @return Module ID, or empty string if not found
     */
    std::string lookup_module(std::string_view message_type) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = message_type_to_module_.find(std::string(message_type));
        if (it != message_type_to_module_.end()) {
            return it->second;
        }
        return "";
    }
    
    /**
     * Check if a message type is registered
     */
    bool has_route(std::string_view message_type) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return message_type_to_module_.count(std::string(message_type)) > 0;
    }
    
    /**
     * Get all registered message types
     */
    std::vector<std::string> get_all_routes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> routes;
        for (const auto& [type, _] : message_type_to_module_) {
            routes.push_back(type);
        }
        return routes;
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> message_type_to_module_;
};

} // namespace NoteDaemon

#endif // HANDLER_REGISTRY_H