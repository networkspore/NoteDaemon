// include/module_framework/device_ownership_registry.h
// Core-level registry: maps claimed device_id → owning module_id.
//
// Filled by modules on successful claim, read by the core's
// dispatch_new_connection() to route incoming device sockets to the right module.
// Thread-safe; intended to be passed by pointer into each module via IModule::init().

#ifndef DEVICE_OWNERSHIP_REGISTRY_H
#define DEVICE_OWNERSHIP_REGISTRY_H

#include <string>
#include <string_view>
#include <unordered_map>
#include <mutex>
#include <syslog.h>
#include <cstddef>

namespace NoteDaemon {

class DeviceOwnershipRegistry {
public:
    DeviceOwnershipRegistry()  = default;
    ~DeviceOwnershipRegistry() = default;

    // Non-copyable, non-movable (contains mutex)
    DeviceOwnershipRegistry(const DeviceOwnershipRegistry&)            = delete;
    DeviceOwnershipRegistry& operator=(const DeviceOwnershipRegistry&) = delete;

    // ── Ownership metadata ─────────────────────────────────────────────────────

    /**
     * Tracks which module/PID/session currently owns a device.
     * This is the single source of truth for claim metadata.
     */
    struct DeviceOwner {
        std::string module_id;
        pid_t pid = 0;
        std::string session_id;

        bool empty() const { return module_id.empty(); }
    };

    // ── Write side (called by modules) ────────────────────────────────────────

    /**
     * Register that module_id now owns device_id.
     * Called by a module immediately after a successful USB claim.
     *
     * Legacy overload: pid=session_id="". Kept for compatibility; new callers
     * should use the extended overload that includes pid and session_id.
     */
    void register_device(std::string_view device_id, std::string_view module_id) {
        register_device(device_id, module_id, 0, "");
    }

    /**
     * Register ownership with full metadata (preferred form).
     */
    void register_device(std::string_view device_id,
                         std::string_view module_id,
                         pid_t pid,
                         std::string_view session_id) {
        std::lock_guard lock(mutex_);
        device_to_owner_.insert_or_assign(
            std::string(device_id),
            DeviceOwner{
                .module_id   = std::string(module_id),
                .pid         = pid,
                .session_id  = std::string(session_id)
            });
        syslog(LOG_DEBUG,
               "[DeviceOwnershipRegistry] registered device=%s → module=%s pid=%d session=%s",
               std::string(device_id).c_str(),
               std::string(module_id).c_str(),
               static_cast<int>(pid),
               std::string(session_id).c_str());
    }

    /**
     * Unregister a device (called on release or error).
     * No-op if device_id is not present.
     */
    void unregister_device(std::string_view device_id) {
        std::lock_guard lock(mutex_);
        auto erased = device_to_owner_.erase(std::string(device_id));
        if (erased) {
            syslog(LOG_DEBUG, "[DeviceOwnershipRegistry] unregistered device=%s",
                   std::string(device_id).c_str());
        }
    }

    // ── Read side (called by core and modules) ────────────────────────────────

    /**
     * Look up which module owns a device.
     * Returns the module_id string, or "" if not found.
     * Used by main.cpp to route DEVICE_HANDSHAKE connections.
     */
    [[nodiscard]] std::string lookup_module(std::string_view device_id) const {
        std::lock_guard lock(mutex_);
        auto it = device_to_owner_.find(std::string(device_id));
        return it != device_to_owner_.end() ? it->second.module_id : std::string{};
    }

    /**
     * Returns true if any module currently owns device_id.
     */
    [[nodiscard]] bool is_claimed(std::string_view device_id) const {
        std::lock_guard lock(mutex_);
        return device_to_owner_.count(std::string(device_id)) > 0;
    }

    /**
     * Get full ownership info for a device.
     * Returns an empty DeviceOwner if not present.
     */
    [[nodiscard]] DeviceOwner get_owner(std::string_view device_id) const {
        std::lock_guard lock(mutex_);
        auto it = device_to_owner_.find(std::string(device_id));
        return it != device_to_owner_.end() ? it->second : DeviceOwner{};
    }

    /**
     * Returns true if device_id is claimed by the given pid.
     * Used for PID-based conflict checks during claim_device().
     */
    [[nodiscard]] bool is_claimed_by_pid(std::string_view device_id, pid_t pid) const {
        std::lock_guard lock(mutex_);
        auto it = device_to_owner_.find(std::string(device_id));
        return it != device_to_owner_.end() && it->second.pid == pid;
    }

    /**
     * Clear all entries (used during full daemon shutdown).
     */
    void clear() {
        std::lock_guard lock(mutex_);
        device_to_owner_.clear();
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, DeviceOwner> device_to_owner_;
};

} // namespace NoteDaemon

#endif // DEVICE_OWNERSHIP_REGISTRY_H