// include/module_framework/imodule.h
// IModule interface - base interface for all loadable modules

#ifndef IMODULE_H
#define IMODULE_H

#include <string_view>
#include <memory>
#include <vector>
#include "error.h"
#include "capability_registry.h"
#include "json.hpp"  // nlohmann/json

namespace NoteDaemon {

class HandlerRegistry;

/**
 * Base interface for all loadable modules
 */
class IModule {
public:
    virtual ~IModule() = default;

    // ===== Identity =====
    
    /**
     * Returns the module's unique identifier (e.g., "note_usb")
     */
    virtual std::string_view name() const = 0;
    
    /**
     * Returns the module's version (e.g., "1.0.0")
     */
    virtual std::string_view version() const = 0;
    
    /**
     * Returns a human-readable description of the module
     */
    virtual std::string_view description() const = 0;

    // ===== Lifecycle =====
    
    /**
     * Initialize the module with its configuration
     * Called after module is loaded and before start()
     * @param config Module-specific configuration (JSON object)
     * @return Error::success() on success, error code on failure
     */
    virtual Error init(const nlohmann::json& config) = 0;
    
    /**
     * Start the module - begin normal operation
     * @return Error::success() on success, error code on failure
     */
    virtual Error start() = 0;
    
    /**
     * Stop the module - gracefully shut down
     * Note: Device monitors may survive stop() - they run independently
     * @return Error::success() on success, error code on failure
     */
    virtual Error stop() = 0;
    
    /**
     * Full shutdown - release all resources
     * Called during daemon shutdown
     */
    virtual void shutdown() = 0;
    
    // ===== Client Connection Handling =====
    
    /**
     * Handle a new client connection
     * Called by core when a client connects.
     * Module should create a session and start handling the connection.
     * @param client_fd Client socket file descriptor
     * @param client_pid Client process ID
     * @return Error::success() on success, error code on failure
     */
    virtual Error handle_client(int client_fd, pid_t client_pid) = 0;
    
    /**
     * Cleanup client session
     * Called when client disconnects.
     * @param client_pid Client process ID
     */
    virtual void cleanup_client(pid_t client_pid) = 0;

    // ===== Health Check =====
    
    /**
     * Check if module is healthy and compatible with core
     * Called by core after loading the module
     * @param core_api_version The core's API version string
     * @return Error::success() if healthy, error code if not
     */
    virtual Error check_health(const std::string& core_api_version) = 0;

    // ===== Capabilities =====
    
    /**
     * Returns the capabilities this module provides
     * Uses bitflags (same system as existing capability_registry)
     */
    virtual cpp_int capabilities() const = 0;

    // ===== Message Types =====
    
    /**
     * Returns list of message types this module handles
     * Used by core for Level 1 routing
     * @return Vector of message type strings (e.g., "claim_item", "release_item")
     */
    virtual std::vector<std::string> get_handled_message_types() = 0;

    // ===== Handler Registry =====
    
    /**
     * Returns this module's handler registry
     * Used by core for Level 2 (device-level) routing
     * Core will pull handlers from this registry after init()
     */
    virtual HandlerRegistry& get_handler_registry() = 0;

    // ===== Error Collection =====
    
    /**
     * Collect errors from this module (pull-based, thread-safe)
     * @param errors Vector to append errors to
     */
    virtual void collect_errors(std::vector<Error>& errors) = 0;

    // ===== Cleanup =====
    
    /**
     * Release all resources - called during cleanup
     */
    virtual void cleanup() = 0;
};

/**
 * Module factory function signature
 * Modules export this symbol for dynamic loading
 * 
 * Example export in module:
 * extern "C" NoteDaemon::IModule* create_module() {
 *     return new MyModule();
 * }
 */
using ModuleFactory = IModule*(*)();

/**
 * Get the module factory symbol name for a given module
 */
inline std::string get_module_factory_symbol(const std::string& module_name) {
    return "create_" + module_name + "_module";
}

} // namespace NoteDaemon

#endif // IMODULE_H