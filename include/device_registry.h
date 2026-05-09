// include/device_registry.h
// Tracks claimed devices in a JSON file for crash recovery.
// When NoteDaemon crashes, the process monitor reads this file and
// reattaches all devices that belonged to the crashed daemon.

#ifndef DEVICE_REGISTRY_H
#define DEVICE_REGISTRY_H

#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <syslog.h>

/**
 * Represents a claimed device tracked in the registry file.
 * This struct is used both for writing to the registry and for
 * the monitor process to read and reattach devices.
 */
struct ClaimedDevice {
    pid_t pid = 0;
    std::string device_id;       // bus:address (e.g. "1:3")
    int interface_number = 0;
    bool kernel_driver_attached = false;
};

/**
 * Simple JSON-like parser/writer for the device registry file.
 * 
 * File format (array of objects):
 * [
 *   {"pid": 12345, "device_id": "1:3", "interface_number": 0, "kernel_driver_attached": true},
 *   ...
 * ]
 */
class DeviceRegistry {
public:
    static const std::string& path();

    /**
     * Add a claimed device to the registry.
     * Thread-safe — uses a mutex to protect concurrent writes.
     */
    static void add_device(const ClaimedDevice& device);

    /**
     * Remove a claimed device from the registry (e.g. on clean release).
     * Returns true if the device was found and removed.
     */
    static bool remove_device(pid_t pid, const std::string& device_id);

    /**
     * Get all devices claimed by a specific PID.
     * Used by the monitor process to find orphaned devices.
     */
    static std::vector<ClaimedDevice> get_devices_by_pid(pid_t pid);

    /**
     * Get all devices in the registry.
     * Used by the monitor process to clean up everything.
     */
    static std::vector<ClaimedDevice> get_all_devices();

    /**
     * Remove all devices belonging to a PID.
     * Called by the monitor after reattaching.
     */
    static bool remove_all_by_pid(pid_t pid);

private:
    static std::mutex& registry_mutex();
    static std::string& registry_path();

    /**
     * Read the registry file and parse into a vector of ClaimedDevice.
     * Returns empty vector on error.
     */
    static std::vector<ClaimedDevice> read_registry();

    /**
     * Write the registry vector back to the file.
     * Returns false on error.
     */
    static bool write_registry(const std::vector<ClaimedDevice>& devices);

    /**
     * Simple JSON string builder — no external dependencies.
     */
    static std::string json_object(const ClaimedDevice& device);
};

#endif // DEVICE_REGISTRY_H
