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

namespace NoteDaemon {

class DeviceOwnershipRegistry {
public:
    DeviceOwnershipRegistry()  = default;
    ~DeviceOwnershipRegistry() = default;

    // Non-copyable, non-movable (contains mutex)
    DeviceOwnershipRegistry(const DeviceOwnershipRegistry&)            = delete;
    DeviceOwnershipRegistry& operator=(const DeviceOwnershipRegistry&) = delete;

    // ── Write side (called by modules) ────────────────────────────────────────

    /**
     * Register that module_id now owns device_id.
     * Called by a module immediately after a successful USB claim.
     */
    void register_device(std::string_view device_id, std::string_view module_id) {
        std::lock_guard lock(mutex_);
        device_to_module_.insert_or_assign(std::string(device_id),
                                           std::string(module_id));
        syslog(LOG_DEBUG, "[DeviceOwnershipRegistry] registered device=%s → module=%s",
               std::string(device_id).c_str(), std::string(module_id).c_str());
    }

    /**
     * Unregister a device (called on release or error).
     * No-op if device_id is not present.
     */
    void unregister_device(std::string_view device_id) {
        std::lock_guard lock(mutex_);
        auto erased = device_to_module_.erase(std::string(device_id));
        if (erased) {
            syslog(LOG_DEBUG, "[DeviceOwnershipRegistry] unregistered device=%s",
                   std::string(device_id).c_str());
        }
    }

    // ── Read side (called by core) ─────────────────────────────────────────────

    /**
     * Look up which module owns a device.
     * Returns the module_id string, or "" if not found.
     */
    [[nodiscard]] std::string lookup_module(std::string_view device_id) const {
        std::lock_guard lock(mutex_);
        auto it = device_to_module_.find(std::string(device_id));
        return it != device_to_module_.end() ? it->second : std::string{};
    }

    /**
     * Returns true if any module currently owns device_id.
     */
    [[nodiscard]] bool is_claimed(std::string_view device_id) const {
        std::lock_guard lock(mutex_);
        return device_to_module_.count(std::string(device_id)) > 0;
    }

    /**
     * Clear all entries (used during full daemon shutdown).
     */
    void clear() {
        std::lock_guard lock(mutex_);
        device_to_module_.clear();
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::string> device_to_module_;
};

} // namespace NoteDaemon

#endif // DEVICE_OWNERSHIP_REGISTRY_H