#include "device_session.h"
#include "device_registry.h"
#include <libusb-1.0/libusb.h>

// Lazy-init registry accessors: function-local statics ensure safe, ordered init
std::mutex& DeviceSession::sessions_mutex() {
    static std::mutex m;
    return m;
}

std::vector<DeviceSession*>& DeviceSession::active_sessions() {
    static std::vector<DeviceSession*> v;
    return v;
}

/**
 * Shutdown all active sessions - release devices and reattach kernel drivers.
 * Called on daemon shutdown to ensure cleanup even without the monitor.
 * 
 * Uses the device registry to find all claimed devices and reattaches
 * kernel drivers. This is simpler and safer than iterating through sessions.
 */
void DeviceSession::shutdown_all_sessions() {
    syslog(LOG_INFO, "Shutting down all sessions, cleaning up devices...");
    
    // Get all devices from the registry
    auto devices = DeviceRegistry::get_all_devices();
    
    if (devices.empty()) {
        syslog(LOG_INFO, "No devices to clean up");
        return;
    }
    
    syslog(LOG_INFO, "Cleaning up %zu device(s) from registry", devices.size());
    
    // We need to reattach kernel drivers for all devices
    // Use libusb to find and reattach each device
    libusb_context* ctx = nullptr;
    if (libusb_init(&ctx) != 0) {
        syslog(LOG_ERR, "Failed to init libusb for cleanup");
        return;
    }
    
    for (const auto& device : devices) {
        syslog(LOG_INFO, "Reattaching device %s (interface %d)",
               device.device_id.c_str(), device.interface_number);
        
        // Parse device_id (format: "bus:address")
        int bus = 0, address = 0;
        if (sscanf(device.device_id.c_str(), "%d:%d", &bus, &address) == 2) {
            // Find the device by bus and address
            libusb_device** list;
            ssize_t cnt = libusb_get_device_list(ctx, &list);
            for (ssize_t i = 0; i < cnt; i++) {
                if (libusb_get_bus_number(list[i]) == bus &&
                    libusb_get_device_address(list[i]) == address) {
                    // Found the device, try to reattach kernel driver
                    libusb_device_handle* handle;
                    if (libusb_open(list[i], &handle) == 0) {
                        libusb_release_interface(handle, device.interface_number);
                        if (device.kernel_driver_attached) {
                            libusb_attach_kernel_driver(handle, device.interface_number);
                        }
                        libusb_close(handle);
                    }
                    break;
                }
            }
            libusb_free_device_list(list, 1);
        }
    }
    
    libusb_exit(ctx);
    
    // Clear the registry for our PID
    DeviceRegistry::remove_all_by_pid(getpid());
    
    syslog(LOG_INFO, "All sessions shut down, devices released");
}

/**
 * Register a claimed device in the device registry for crash recovery.
 * Called when a device is successfully claimed.
 * NOTE: We store daemon's PID (getpid()), not client_pid,
 *       because the monitor watches the daemon's PID.
 */
void DeviceSession::register_claimed_device(const std::string& device_id,
                                             int interface_number,
                                             bool kernel_driver_attached) {
    ClaimedDevice device;
    device.pid = getpid();  // Use daemon's PID, not client_pid
    device.device_id = device_id;
    device.interface_number = interface_number;
    device.kernel_driver_attached = kernel_driver_attached;
    DeviceRegistry::add_device(device);
}

/**
 * Remove a device from the registry on clean release.
 * Called when a device is released normally.
 */
void DeviceSession::unregister_device(const std::string& device_id) {
    DeviceRegistry::remove_device(getpid(), device_id);  // Use daemon's PID
}

/**
 * Offer encryption to the client for a device.
 * Starts DH key exchange and sends ENCRYPTION_OFFER.
 */
void DeviceSession::offer_device_encryption(
    const std::string& device_id) {
    auto& enc = NoteDaemon::get_encryption_provider();

    // Start DH key exchange (via the USB provider)
    if (!enc.start_negotiation(device_id)) {
        syslog(LOG_ERR,
               "Failed to start DH negotiation for device %s",
               device_id.c_str());
        send_device_encryption_error(
            device_id, "DH key exchange init failed");
        return;
    }

    // Get our DH public key
    auto public_key = enc.get_public_key(device_id);
    if (public_key.empty()) {
        syslog(LOG_ERR,
               "Failed to get DH public key for device %s",
               device_id.c_str());
        send_device_encryption_error(
            device_id, "failed to generate DH key");
        return;
    }

    // Build and send ENCRYPTION_OFFER
    NoteBytes::Object offer;
    offer.add(NoteMessaging::Keys::CONTROL,
              NoteMessaging::ProtocolMessages::ENCRYPTION_OFFER);
    offer.add(NoteMessaging::Keys::CIPHER, "aes-256-gcm");
    offer.add(NoteMessaging::Keys::PUBLIC_KEY,
              NoteBytes::Value(public_key.data(),
                               public_key.size(),
                               NoteBytes::Type::RAW_BYTES));

    send_routed_control_message(device_id, offer);

    syslog(LOG_INFO,
           "Sent ENCRYPTION_OFFER for device: %s",
           device_id.c_str());
}

void DeviceSession::send_device_encryption_error(
    const std::string& device_id,
    const std::string& reason) {
    NoteBytes::Object error;
    error.add(NoteMessaging::Keys::CONTROL,
              NoteMessaging::ProtocolMessages::ERROR);
    error.add(NoteMessaging::Keys::ERROR,
              NoteMessaging::ErrorCodes::ENCRYPTION_FAILED);
    error.add(NoteMessaging::Keys::MSG, reason);

    send_routed_control_message(device_id, error);

    syslog(LOG_ERR,
           "Encryption error for device %s: %s",
           device_id.c_str(), reason.c_str());

    // Clean up DH context
    device_dh_keys_.erase(device_id);
    NoteDaemon::get_encryption_provider().remove_device(device_id);
}