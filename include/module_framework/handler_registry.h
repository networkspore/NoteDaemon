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
 * This handles Level 2 routing: message + device_id → handler
 */
class HandlerRegistry {
public:
    HandlerRegistry() = default;
    ~HandlerRegistry() = default;
    
    // Prevent copying (contains mutex)
    HandlerRegistry(const HandlerRegistry&) = delete;
    HandlerRegistry& operator=(const HandlerRegistry&) = delete;
    
    // TODO: ERROR:Explicitly defaulted move constructor is implicitly deleted
   /* handler_registry.h(247, 24): Move constructor of 'HandlerRegistry' is implicitly deleted because field 'mutex_' has a deleted move constructor
std_mutex.h(107, 5): 'mutex' has been explicitly marked deleted here
    */
    HandlerRegistry(HandlerRegistry&&) noexcept = default;
    HandlerRegistry& operator=(HandlerRegistry&&) noexcept = default;

    // ===== Registration =====
    
    /**
     * Register a handler for a specific module (Level 1 routing)
     * @param module_id The module identifier (e.g., "note_usb")
     * @param message_type The message type to handle
     * @param handler The handler function
     */
    void register_module_handler(std::string_view module_id,
                                 std::string_view message_type,
                                 Handler handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(module_id, message_type);
        module_handlers_[std::move(key)] = std::move(handler);
    }
    
    /**
     * Register a handler for a message type (no device/module specificity)
     * Used for global messages like HELLO, PING, etc.
     * Uses NoteBytes::Value as key for direct comparison without string conversion
     */
    void register_handler(const NoteBytes::Value& message_type, Handler handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        global_handlers_[message_type] = std::move(handler);
    }
    
    /**
     * Register a handler for a specific device (Level 2 routing)
     * @param device_id The device identifier (e.g., "1:2" for USB bus:addr)
     * @param message_type The message type to handle
     * @param handler The handler function
     */
    void register_device_handler(std::string_view device_id,
                                std::string_view message_type,
                                Handler handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_device_key(device_id, message_type);
        device_handlers_[std::move(key)] = std::move(handler);
    }

    // ===== Dispatch =====
    
    /**
     * Dispatch a message (routes by module_id first, then device-specific, then global)
     * @param message The NoteBytes message to process
     * @return Error::success() if handled, error if no handler found
     */
    Error dispatch(const NoteBytes::Object& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Extract module_id, device_id, event/cmd from message
        auto* module_id_val = message.get(NoteMessaging::Keys::MODULE_ID);
        auto* device_id_val = message.get(NoteMessaging::Keys::DEVICE_ID);
        auto* event_val = message.get(NoteMessaging::Keys::EVENT);
        auto* cmd_val = message.get(NoteMessaging::Keys::CMD);
        
        std::string module_id = module_id_val ? module_id_val->as_string() : "";
        std::string device_id = device_id_val ? device_id_val->as_string() : "";
        
        // Use NoteBytes::Value directly for message type - no string conversion for global handlers
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
        
        // For Level 1 & 2 routing, we need string keys (compound: module_id:message_type)
        // Level 3 (global handlers) uses NoteBytes::Value directly - no string conversion
        std::string message_type_str = message_type_val->as_string();
        
        // ROUTING LEVEL 1: Module-level routing
        // If module_id is specified, route to that module's handlers
        if (!module_id.empty()) {
            std::string key = make_key(module_id, message_type_str);
            auto it = module_handlers_.find(key);
            if (it != module_handlers_.end()) {
                it->second(message);
                return Error(ErrorCodes::SUCCESS, "");
            }
            
            // Module-specific device routing
            if (!device_id.empty()) {
                std::string device_key = make_key(module_id, device_id, message_type_str);
                auto device_it = device_handlers_.find(device_key);
                if (device_it != device_handlers_.end()) {
                    device_it->second(message);
                    return Error(ErrorCodes::SUCCESS, "");
                }
            }
        }
        
        // ROUTING LEVEL 2: Device-specific routing (legacy format without module_id)
        if (!device_id.empty()) {
            std::string device_key = make_device_key(device_id, message_type_str);
            auto it = device_handlers_.find(device_key);
            if (it != device_handlers_.end()) {
                it->second(message);
                return Error(ErrorCodes::SUCCESS, "");
            }
        }
        
        // ROUTING LEVEL 3: Global handlers
        // Use NoteBytes::Value directly for lookup - no string conversion needed
        auto global_it = global_handlers_.find(*message_type_val);
        if (global_it != global_handlers_.end()) {
            global_it->second(message);
            return Error(ErrorCodes::SUCCESS, "");
        }
        
        return Error::from_code(ErrorCodes::HANDLER_NOT_FOUND,
                                "No handler for message type: " + message_type_val->as_string());
    }
    
    /**
     * Dispatch to a specific device (for internal use)
     */
    Error dispatch_to_device(std::string_view device_id,
                           const NoteBytes::Object& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto* event_val = message.get(NoteMessaging::Keys::EVENT);
        auto* cmd_val = message.get(NoteMessaging::Keys::CMD);
        
        std::string message_type;
        if (event_val) {
            message_type = event_val->as_string();
        } else if (cmd_val) {
            message_type = cmd_val->as_string();
        }
        
        if (message_type.empty()) {
            return Error::from_code(ErrorCodes::INVALID_MESSAGE,
                                    "Message has no EVENT or CMD field");
        }
        
        std::string key = make_device_key(device_id, message_type);
        auto it = device_handlers_.find(key);
        if (it != device_handlers_.end()) {
            it->second(message);
            return Error(ErrorCodes::SUCCESS, "");
        }
        
        return Error::from_code(ErrorCodes::HANDLER_NOT_FOUND,
                                "No handler for device " + std::string(device_id) +
                                " message type: " + message_type);
    }

    // ===== Query =====
    
    /**
     * Check if a message type has any handler (global or device)
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
        // Add device handler types (deduplicated)
        std::vector<std::string> device_types;
        for (const auto& [key, _] : device_handlers_) {
            // Extract message type from key (after second colon)
            size_t colon_pos = key.find(':');
            if (colon_pos != std::string::npos && colon_pos + 1 < key.size()) {
                std::string msg_type = key.substr(colon_pos + 1);
                if (std::find(types.begin(), types.end(), msg_type) == types.end() &&
                    std::find(device_types.begin(), device_types.end(), msg_type) == device_types.end()) {
                    device_types.push_back(msg_type);
                }
            }
        }
        types.insert(types.end(), device_types.begin(), device_types.end());
        return types;
    }
    
    /**
     * Get count of registered handlers
     */
    size_t handler_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return global_handlers_.size() + device_handlers_.size();
    }

private:
    static std::string make_key(std::string_view module_id, std::string_view message_type) {
        return std::string(module_id) + ":" + std::string(message_type);
    }
    
    static std::string make_key(std::string_view module_id, std::string_view device_id, std::string_view message_type) {
        return std::string(module_id) + ":" + std::string(device_id) + ":" + std::string(message_type);
    }
    
    static std::string make_device_key(std::string_view device_id, std::string_view message_type) {
        return std::string(device_id) + ":" + std::string(message_type);
    }
    
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Handler> module_handlers_;
    std::unordered_map<NoteBytes::Value, Handler> global_handlers_;
    std::unordered_map<std::string, Handler> device_handlers_;
};

/**
 * Module routing registry (Level 1)
 * 
 * Maps message types to module IDs for core routing.
 * This is owned by the core, not by modules.
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
