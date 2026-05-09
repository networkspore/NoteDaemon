// src/process_monitor.cpp
// Process monitor that watches NoteDaemon and reattaches orphaned devices
// when the daemon terminates unexpectedly.
//
// Usage: process_monitor <pid>
//
// On termination of the watched PID, the monitor:
// 1. Reads the device registry file
// 2. Finds all devices claimed by the watched PID
// 3. Reattaches the kernel driver for each device
// 4. Removes the entries from the registry
// 5. Exits

#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <string>
#include <vector>
#include <cstring>
#include <chrono>
#include <thread>

#include "device_registry.h"

/**
 * Reattach kernel driver for a single device.
 * Called by the monitor process after NoteDaemon crashes.
 */
static bool reattach_kernel_driver(const ClaimedDevice& device) {
    // We need to find the actual libusb_device by bus:address
    libusb_context* ctx = nullptr;
    int rc = libusb_init(&ctx);
    if (rc != LIBUSB_SUCCESS) {
        syslog(LOG_ERR, "Monitor: Failed to init libusb for reattach: %s",
               libusb_error_name(rc));
        return false;
    }
    
    libusb_device** list = nullptr;
    ssize_t cnt = libusb_get_device_list(ctx, &list);
    if (cnt < 0) {
        syslog(LOG_ERR, "Monitor: Failed to get device list for reattach");
        libusb_exit(ctx);
        return false;
    }
    
    // Find the device by bus:address
    libusb_device* target_device = nullptr;
    for (ssize_t i = 0; i < cnt; i++) {
        uint8_t bus = libusb_get_bus_number(list[i]);
        uint8_t address = libusb_get_device_address(list[i]);
        std::string id = std::to_string(bus) + ":" + std::to_string(address);
        
        if (id == device.device_id) {
            target_device = list[i];
            break;
        }
    }
    
    if (!target_device) {
        syslog(LOG_WARNING, "Monitor: Device %s not found — may have been physically disconnected",
               device.device_id.c_str());
        libusb_free_device_list(list, 1);
        libusb_exit(ctx);
        return false;
    }
    
    // Open device handle
    libusb_device_handle* handle = nullptr;
    rc = libusb_open(target_device, &handle);
    if (rc != LIBUSB_SUCCESS) {
        syslog(LOG_WARNING, "Monitor: Cannot open device %s for reattach: %s",
               device.device_id.c_str(), libusb_error_name(rc));
        libusb_free_device_list(list, 1);
        libusb_exit(ctx);
        return false;
    }
    
    // Reattach kernel driver
    rc = libusb_attach_kernel_driver(handle, device.interface_number);
    if (rc == LIBUSB_SUCCESS) {
        syslog(LOG_INFO, "Monitor: Reattached kernel driver for device %s (interface %d)",
               device.device_id.c_str(), device.interface_number);
    } else if (rc == LIBUSB_ERROR_NOT_FOUND) {
        // Kernel driver was never detached — nothing to do
        syslog(LOG_DEBUG, "Monitor: No kernel driver to reattach for device %s",
               device.device_id.c_str());
    } else {
        syslog(LOG_WARNING, "Monitor: Failed to reattach kernel driver for device %s: %s",
               device.device_id.c_str(), libusb_error_name(rc));
    }
    
    libusb_close(handle);
    libusb_free_device_list(list, 1);
    libusb_exit(ctx);
    
    return (rc == LIBUSB_SUCCESS || rc == LIBUSB_ERROR_NOT_FOUND);
}

/**
 * Main monitor process — watches a PID and cleans up orphaned devices.
 * This runs as a child process of NoteDaemon, detached from its process group.
 */
int monitor_main(pid_t watched_pid) {
    // Detach from parent's process group so we survive if parent's group is killed
    setsid();
    
    // Set up signal handlers — we want to survive SIGTERM/SIGINT from parent's group
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    
    // Use prctl so that if the parent dies, we get SIGTERM too
    // (This is a safety net — we also poll for the PID)
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    
    syslog(LOG_INFO, "Monitor started — watching PID %d", watched_pid);
    
    // Poll for the watched PID's termination
    while (true) {
        // Check if the watched process is still alive
        if (kill(watched_pid, 0) != 0) {
            // Process is gone — do cleanup
            syslog(LOG_INFO, "Watched PID %d has terminated, cleaning up orphaned devices",
                   watched_pid);
            
            // Get all devices claimed by this PID
            auto devices = DeviceRegistry::get_all_devices();
            
            int reattached = 0;
            int failed = 0;
            
            for (const auto& device : devices) {
                if (device.pid == watched_pid) {
                    syslog(LOG_INFO, "Monitor: Reattaching device %s (interface %d)",
                           device.device_id.c_str(), device.interface_number);
                    
                    if (reattach_kernel_driver(device)) {
                        reattached++;
                    } else {
                        failed++;
                    }
                }
            }
            
            // Remove all entries from the registry
            DeviceRegistry::remove_all_by_pid(watched_pid);
            
            syslog(LOG_INFO, "Monitor: Reattach complete — %d reattached, %d failed",
                   reattached, failed);
            
            break;
        }
        
        // Sleep before next check
        usleep(200000);  // 200ms
    }
    
    syslog(LOG_INFO, "Monitor exiting");
    return 0;
}

/**
 * Main entry point for the process monitor.
 * Usage: process_monitor <pid>
 */
int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }
    
    pid_t watched_pid = std::atoi(argv[1]);
    if (watched_pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }
    
    openlog("process-monitor", LOG_PID, LOG_DAEMON);
    int result = monitor_main(watched_pid);
    closelog();
    
    return result;
}
