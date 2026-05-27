// include/module_framework/imodule.h
// IModule interface - base interface for all loadable modules.
//
// Changes from previous version:
//   • set_ownership_registry() – core injects DeviceOwnershipRegistry pointer
//     after construction so modules can register/unregister device ownership.
//   • handle_management_message() – new entry point for management-socket
//     commands (claim, release, discovery requests). Carries reply_fd so the
//     module can write responses directly without shared state.
//   • handle_client() is now exclusively called for DEVICE sockets (post-
//     DEVICE_HANDSHAKE routing). Management messages no longer flow through it.

#ifndef IMODULE_H
#define IMODULE_H

#include <string_view>
#include <memory>
#include <vector>
#include "error.h"
#include "capability_registry.h"
#include "device_ownership_registry.h"
#include "json.hpp"  // nlohmann/json

namespace NoteDaemon {

class HandlerRegistry;

/**
 * Base interface for all loadable modules.
 */
class IModule {
public:
    virtual ~IModule() = default;

    // ── Identity ──────────────────────────────────────────────────────────────

    /** Unique identifier, e.g. "note_usb". */
    virtual std::string_view name()        const = 0;
    /** Semver string, e.g. "1.0.0". */
    virtual std::string_view version()     const = 0;
    /** Human-readable description. */
    virtual std::string_view description() const = 0;

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /**
     * init() – called once after the module is loaded, before start().
     * @param config Module-specific JSON configuration.
     */
    virtual Error init(const nlohmann::json& config) = 0;

    /**
     * Core injects the DeviceOwnershipRegistry immediately after init() returns
     * successfully.  Modules that claim devices MUST store this pointer and call
     * register_device() / unregister_device() on claim / release.
     *
     * Default implementation is a no-op so modules that don't claim devices
     * don't need to override it.
     */
    virtual void set_ownership_registry(DeviceOwnershipRegistry* /*registry*/) {}

    /** Begin normal operation (start background threads, etc.). */
    virtual Error start() = 0;

    /** Graceful stop – background threads should exit but resources may remain. */
    virtual Error stop()  = 0;

    /** Full teardown – release all resources.  Called during daemon shutdown. */
    virtual void shutdown() = 0;

    // ── Two-socket connection handling ────────────────────────────────────────

    /**
     * handle_management_message() – process a single management-socket command.
     *
     * Called by the core's management read loop for messages that belong to this
     * module (claim_item, release_item, request_discovery, …).  The module MUST
     * write any response directly to reply_fd before returning.  The core does
     * NOT read from reply_fd after this call.
     *
     * @param message    Fully-parsed NoteBytes object received on management socket.
     * @param reply_fd   File descriptor of the management socket connection. Write
     *                    NoteBytes-framed responses here.  Do NOT close it.
     * @param client_pid Actual client PID from SO_PEERCRED - do NOT trust any pid
     *                    field in the message, always use this actual credential.
     * @return Error     SUCCESS or a descriptive error (logged by the core).
     */
    virtual Error handle_management_message(const NoteBytes::Object& message,
                                            int reply_fd,
                                            pid_t client_pid) {
        (void)message; (void)reply_fd; (void)client_pid;
        return Error::from_code(ErrorCodes::UNKNOWN,
                                "handle_management_message not implemented");
    }

    /**
     * handle_client() – called exclusively for DEVICE sockets.
     *
     * The core calls this after a DEVICE_HANDSHAKE has identified that this
     * module owns the connecting device.  The module takes full ownership of
     * client_fd (including closing it when the session ends).
     *
     * @param client_fd   Device socket fd. Module owns its full lifecycle.
     * @param client_pid  Client process ID (for logging / session keying).
     * @param device_id   Device identifier from the DEVICE_HANDSHAKE message.
     */
    virtual Error handle_client(int client_fd, pid_t client_pid,
                                const std::string& device_id) = 0;

    /**
     * cleanup_client() – called when a client disconnects from a device socket.
     * @param client_pid Client process ID used to look up the session.
     */
    virtual void cleanup_client(pid_t client_pid) = 0;

    // ── Health ───────────────────────────────────────────────────────────────

    /**
     * Verify the module is healthy and compatible with core_api_version.
     * Called by the core after loading and before registering the module.
     */
    virtual Error check_health(const std::string& core_api_version) = 0;

    // ── Capabilities & routing ───────────────────────────────────────────────

    /** Bitfield of capabilities this module provides. */
    virtual cpp_int capabilities() const = 0;

    /**
     * Message types this module handles on the management socket.
     * Used by the core to build the ModuleRoutingRegistry after init().
     * e.g. { "claim_item", "release_item", "request_discovery" }
     */
    virtual std::vector<std::string> get_handled_message_types() = 0;

    // ── Handler registry (device-level internal routing) ──────────────────────

    /**
     * Returns the module's internal HandlerRegistry.
     * Used for in-module message_type → handler routing (not core-level routing).
     */
    virtual HandlerRegistry& get_handler_registry() = 0;

    // ── Error collection ──────────────────────────────────────────────────────

    /** Pull-based error collection.  Append module errors to @p errors. */
    virtual void collect_errors(std::vector<Error>& errors) = 0;

    // ── Cleanup ───────────────────────────────────────────────────────────────

    /** Release all device handles; called during module stop / shutdown. */
    virtual void cleanup() = 0;
};

// ── Factory ──────────────────────────────────────────────────────────────────

/**
 * Every module .so exports a symbol with this signature for dynamic loading.
 *
 * Example:
 *   extern "C" NoteDaemon::IModule* create_example_module() {
 *       static ExampleModule instance;
 *       return &instance;
 *   }
 *
 * Note: concrete modules (such as NoteUSB) may live in separate projects
 * and are loaded through this shared symbol contract.
 */
using ModuleFactory = IModule*(*)();

inline std::string get_module_factory_symbol(const std::string& module_name) {
    return "create_" + module_name + "_module";
}

} // namespace NoteDaemon

#endif // IMODULE_H
