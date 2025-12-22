// include/device_session.h
// Complete refactor with handler maps and protocol fixes
// Uses pre-serialized NoteBytes::Value for all protocol constants

#ifndef DEVICE_SESSION_H
#define DEVICE_SESSION_H

#include <libusb-1.0/libusb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>
#include <map>
#include <memory>
#include <thread>
#include <string>
#include <vector>
#include <chrono>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <unordered_map>

// Global running flag declared in main.cpp
extern std::atomic<bool> g_running;

#include "bitflag_state_bigint.h"
#include "state.h"
#include "capability_registry.h"
#include "note_messaging.h"
#include "notebytes.h"
#include "notebytes_writer.h"
#include "notebytes_reader.h"
#include "event_bytes.h"
#include "hid_parser.h"
#include "encryption_protocol.h"
#include "input_packet.h"

using namespace State;
using namespace Capabilities;

#include "usb_device_descriptor.h"
#include "device_streaming_thread.h"
#include "hid_device_streaming_thread.h"

/**
 * Device Session - manages protocol and routing
 * Uses handler map pattern for O(1) message dispatch
 */
class DeviceSession {
private:
    using Handler = std::function<void(const NoteBytes::Object&)>;
    
    libusb_context* usb_ctx;
    int client_fd;
    pid_t client_pid = 0;
    cpp_int mode_mask = Masks::mode_mask();
    
    // Device management - keyed by deviceId (string)
    std::map<std::string, std::shared_ptr<DeviceState>> device_states;
    std::map<std::string, std::unique_ptr<DeviceStreamingThread>> streaming_threads;
    std::map<std::string, std::shared_ptr<USBDeviceDescriptor>> available_devices;
    
    // Per-device encryption - keyed by deviceId (string)
    std::map<std::string, std::unique_ptr<EncryptionProtocol::EncryptionHandshake>> device_encryptions_;
    
    // Handler maps - O(1) dispatch
    std::unordered_map<NoteBytes::Value, Handler> control_handlers_;
    std::unordered_map<NoteBytes::Value, Handler> routed_handlers_;
    std::unordered_map<NoteBytes::Value, Handler> routed_cmd_handlers_;
    
public:
    DeviceSession(libusb_context* ctx, int client, pid_t pid) 
        : usb_ctx(ctx), client_fd(client), client_pid(pid) {
        
        syslog(LOG_INFO, "Session created for client pid=%d", client_pid);
        
        // Initialize all handler maps
        initialize_control_handlers();
        initialize_routed_handlers();
        initialize_routed_cmd_handlers();
        
        discover_devices();
    }
    
    ~DeviceSession() {
        // Stop all streaming threads
        for (auto& [device_id, thread] : streaming_threads) {
            thread->stop();
        }
        streaming_threads.clear();
        
        release_all_devices();
    }
    
    /**
     * Main protocol loop - clean dispatch using handler maps
     */
    void readSocket() {
        for (;;) {
            try {
                auto routed = InputPacket::receive_message(client_fd);
                
                if (!routed.isValid()) {
                    syslog(LOG_ERR, "Invalid message received");
                    break;
                }
                
                if (routed.is_routed) {
                    handle_routed_message(routed);
                } else {
                    NoteBytes::Object msg = NoteBytes::Object::deserialize(
                        routed.message.data().data(),
                        routed.message.data().size());
                    dispatch_control_message(msg);
                }
                
            } catch (const std::exception& e) {
                syslog(LOG_ERR, "Error in message loop: %s", e.what());
                break;
            }
        }
    }
    
private:
    // ===== HANDLER INITIALIZATION =====
    
    void initialize_control_handlers() {
        control_handlers_[EventBytes::TYPE_CMD] = [this](const NoteBytes::Object& msg) {
            this->handle_command(msg);
        };
        
        control_handlers_[EventBytes::TYPE_HELLO] = [this](const NoteBytes::Object&) {
            this->send_accept("READY");
        };
        
        control_handlers_[EventBytes::TYPE_PING] = [this](const NoteBytes::Object&) {
            this->send_pong();
        };
        
        control_handlers_[EventBytes::EVENT_RELEASE] = [this](const NoteBytes::Object&) {
            syslog(LOG_INFO, "Client requested disconnect");
            send_accept("Goodbye");
            throw std::runtime_error("Client disconnect");
        };
        
        control_handlers_[EventBytes::TYPE_SHUTDOWN] = [this](const NoteBytes::Object&) {
            syslog(LOG_INFO, "Client requested shutdown");
            send_accept("Goodbye");
            throw std::runtime_error("Client disconnect");
        };
    }
    
    void initialize_routed_handlers() {
        // Encryption negotiation
        routed_handlers_[EventBytes::TYPE_ENCRYPTION_ACCEPT] = [this](const NoteBytes::Object& msg) {
            std::string device_id = msg.get_string(NoteMessaging::Keys::DEVICE_ID, NoteMessaging::Keys::EMPTY);
            this->handle_device_encryption_accept(device_id, msg);
        };
        
        routed_handlers_[EventBytes::TYPE_ENCRYPTION_DECLINE] = [this](const NoteBytes::Object& msg) {
            std::string device_id = msg.get_string(NoteMessaging::Keys::DEVICE_ID, NoteMessaging::Keys::EMPTY);
            this->handle_device_encryption_decline(device_id);
        };
        
        // Handle routed TYPE_CMD messages from client
        routed_handlers_[EventBytes::TYPE_CMD] = [this](const NoteBytes::Object& msg) {
            this->handle_routed_command(msg);
        };
    }
    
    void initialize_routed_cmd_handlers() {
        routed_cmd_handlers_[NoteMessaging::ProtocolMessages::RESUME] = [this](const NoteBytes::Object& msg) {
            this->handle_resume(msg);
        };
        
        routed_cmd_handlers_[NoteMessaging::ProtocolMessages::DEVICE_DISCONNECTED] = [this](const NoteBytes::Object& msg) {
            this->handle_device_disconnected(msg);
        };
    }
    
    // ===== MESSAGE DISPATCH =====
    
    /**
     * Dispatch control message - O(1) lookup
     */
    void dispatch_control_message(const NoteBytes::Object& msg) {
        auto* event_value = msg.get(NoteMessaging::Keys::EVENT);
        if (!event_value) {
            send_error(NoteMessaging::ErrorCodes::INVALID_MESSAGE, 
                      "Missing EVENT field");
            return;
        }
        
        // O(1) hash lookup
        auto it = control_handlers_.find(*event_value);
        if (it != control_handlers_.end()) {
            it->second(msg);
        } else {
            send_error(NoteMessaging::ErrorCodes::INVALID_MESSAGE, 
                      "Unknown message type");
        }
    }
    
    /**
     * Handle routed messages (has deviceId prefix)
     */
    void handle_routed_message(const InputPacket::RoutedMessage& routed) {
        std::string device_id = routed.device_id.as_string();
        
        auto it = device_states.find(device_id);
        if (it == device_states.end()) {
            syslog(LOG_WARNING, "Message for unknown deviceId: %s", device_id.c_str());
            return;
        }
        
        if (routed.isObject()) {
            NoteBytes::Object msg = NoteBytes::Object::deserialize(
                routed.message.data().data(),
                routed.message.data().size());
            
            auto* event_value = msg.get(NoteMessaging::Keys::EVENT);
            if (!event_value) {
                syslog(LOG_WARNING, "Invalid or missing EVENT field");
                return;
            }
            
            // O(1) hash lookup for routed handlers
            auto handler_it = routed_handlers_.find(*event_value);
            if (handler_it != routed_handlers_.end()) {
                handler_it->second(msg);
                return;
            }
            
            syslog(LOG_DEBUG, "Received unknown routed message type %s for device %s", 
                   event_value->as_string().c_str(), device_id.c_str());
        }
        
        if (routed.isEncrypted()) {
            handle_encrypted_routed_message(device_id, routed);
        }
    }
    
    void handle_encrypted_routed_message(const std::string& device_id,
                                        const InputPacket::RoutedMessage& routed) {
        auto enc_it = device_encryptions_.find(device_id);
        if (enc_it == device_encryptions_.end() || !enc_it->second->is_active()) {
            syslog(LOG_ERR, "Received encrypted message but no active encryption");
            return;
        }
        
        std::vector<uint8_t> plaintext;
        if (!enc_it->second->decrypt(routed.message.data(), plaintext)) {
            syslog(LOG_ERR, "Decryption failed for device %s", device_id.c_str());
            return;
        }
        
        NoteBytes::Object event_obj = NoteBytes::Object::deserialize(
            plaintext.data(), plaintext.size());
        
        auto* event_value = event_obj.get(NoteMessaging::Keys::EVENT);
        if (event_value) {
            syslog(LOG_DEBUG, "Received encrypted event type %s for device %s", 
                   event_value->as_string().c_str(), device_id.c_str());
        }
    }
    
    /**
     * Handle routed TYPE_CMD messages (RESUME, DEVICE_DISCONNECTED)
     */
    void handle_routed_command(const NoteBytes::Object& msg) {
        auto* cmd_value = msg.get(NoteMessaging::Keys::CMD);
        if (!cmd_value) {
            syslog(LOG_WARNING, "Routed TYPE_CMD missing CMD field");
            return;
        }
        
        std::string cmd = cmd_value->as_string();
        
        // Dispatch to command-specific handler
        auto it = routed_cmd_handlers_.find(cmd);
        if (it != routed_cmd_handlers_.end()) {
            it->second(msg);
        } else {
            syslog(LOG_WARNING, "Unknown routed command: %s", cmd.c_str());
        }
    }
    
    /**
     * Handle DEVICE_DISCONNECTED from client
     */
    void handle_device_disconnected(const NoteBytes::Object& msg) {
        std::string device_id = msg.get_string(NoteMessaging::Keys::DEVICE_ID, NoteMessaging::Keys::EMPTY);
        
        if (device_id.empty()) {
            syslog(LOG_WARNING, "DEVICE_DISCONNECTED missing device_id");
            return;
        }
        
        syslog(LOG_INFO, "Client released device: %s", device_id.c_str());
        
        auto it = device_states.find(device_id);
        if (it == device_states.end()) {
            syslog(LOG_WARNING, "DEVICE_DISCONNECTED for unknown device: %s", 
                   device_id.c_str());
            return;
        }
        
        auto device_state = it->second;
        
        // Stop streaming thread
        auto thread_it = streaming_threads.find(device_id);
        if (thread_it != streaming_threads.end()) {
            thread_it->second->stop();
            streaming_threads.erase(thread_it);
        }
        
        // Clear encryption
        device_encryptions_.erase(device_id);
        
        // Release USB resources
        for (auto &kv : available_devices) {
            if (kv.second->device_id == device_state->device_id) {
                if (kv.second->handle) {
                    libusb_release_interface(kv.second->handle, kv.second->interface_number);
                    if (kv.second->kernel_driver_attached) {
                        libusb_attach_kernel_driver(kv.second->handle, 
                                                    kv.second->interface_number);
                    }
                    libusb_close(kv.second->handle);
                    kv.second->handle = nullptr;
                }
                break;
            }
        }
        
        it->second->release();
        device_states.erase(it);
        
        syslog(LOG_INFO, "Cleaned up device after client release: %s", device_id.c_str());
    }
    
    // ===== COMMAND HANDLERS =====
    
    void handle_command(const NoteBytes::Object& msg) {
        auto* cmd_value = msg.get(NoteMessaging::Keys::CMD);
        if (!cmd_value) {
            send_error(NoteMessaging::ErrorCodes::INVALID_MESSAGE, "Missing CMD field");
            return;
        }
        
        // Compare with pre-serialized constants - O(1)
        if (*cmd_value == NoteMessaging::ProtocolMessages::REQUEST_DISCOVERY) {
            send_device_list();
        } else if (*cmd_value == NoteMessaging::ProtocolMessages::CLAIM_ITEM) {
            handle_claim_device(msg);
        } else if (*cmd_value == NoteMessaging::ProtocolMessages::RELEASE_ITEM) {
            handle_release_device(msg);
        } else if (*cmd_value == NoteMessaging::ProtocolMessages::RESUME) {
            handle_resume(msg);
        } else {
            send_error(NoteMessaging::ErrorCodes::INVALID_MESSAGE, "Unknown command");
        }
    }
    
    void handle_resume(const NoteBytes::Object& msg) {
        int processed_count = msg.get_int(std::string_view("processed_count"), 0);
        std::string device_id = msg.get_string(NoteMessaging::Keys::DEVICE_ID, NoteMessaging::Keys::EMPTY);

        if (device_id.empty()) {
            syslog(LOG_WARNING, "Resume message missing device_id");
            return;
        }

        syslog(LOG_DEBUG, "Client acknowledged %d messages for device %s", 
               processed_count, device_id.c_str());

        if (processed_count <= 0) return;

        auto it = device_states.find(device_id);
        if (it == device_states.end()) {
            syslog(LOG_WARNING, "Resume for unknown device: %s", device_id.c_str());
            return;
        }

        auto device_state = it->second;
        if (!ensure_owner(device_state)) return;
        
        // Decrement pending_events and notify streaming thread
        for (int i = 0; i < processed_count; ++i) {
            device_state->event_delivered();
        }

        // Wake the streaming thread if it was waiting
        {
            std::lock_guard<std::mutex> lk(device_state->queue_mutex);
            device_state->queue_cv.notify_all();
        }
    }
    
    // ... (rest of the handlers - send_device_list, handle_claim_device, etc.)
    // These remain largely unchanged but use the new constants
    
    void send_device_list() {
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT, EventBytes::TYPE_CMD);
        response.add(NoteMessaging::Keys::SEQUENCE, AtomicSequence64::get_next());
        response.add(NoteMessaging::Keys::CMD, NoteMessaging::ProtocolMessages::ITEM_LIST);
        
        NoteBytes::Array devices_array;
        for (const auto& [id, device] : available_devices) {
            auto device_obj = device->to_notebytes();
            auto device_bytes = device_obj.serialize();
            devices_array.add(NoteBytes::Value(device_bytes, NoteBytes::Type::OBJECT));
        }
        response.add(NoteMessaging::Keys::ITEMS, devices_array.as_value());
        
        send_message(response);
        syslog(LOG_INFO, "Sent device list: %zu devices", available_devices.size());
    }
    
    // ===== MESSAGE SENDING =====
    
    void send_message(const NoteBytes::Object& msg) {
        NoteBytes::Writer writer(client_fd, false);
        writer.write(msg);
        writer.flush();
    }
    
    void send_routed_control_message(const std::string& device_id, 
                                     const NoteBytes::Object& msg) {
        NoteBytes::Writer writer(client_fd, false);
        writer.write(NoteBytes::Value(device_id));
        writer.write(msg);
        writer.flush();
    }
    
    void send_accept(const std::string& status = "ok") {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::EVENT, EventBytes::TYPE_ACCEPT);
        msg.add(NoteMessaging::Keys::SEQUENCE, AtomicSequence64::get_next());
        msg.add(NoteMessaging::Keys::STATUS, status);
        
        send_message(msg);
    }
    
    void send_error(int code, const std::string& message) {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::EVENT, EventBytes::TYPE_ERROR);
        msg.add(NoteMessaging::Keys::SEQUENCE, AtomicSequence64::get_next());
        msg.add(NoteMessaging::Keys::ERROR_CODE, code);
        msg.add(NoteMessaging::Keys::MSG, message);
        
        send_message(msg);
        
        syslog(LOG_ERR, "Error %d: %s", code, message.c_str());
    }
    
    void send_pong() {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::EVENT, EventBytes::TYPE_PONG);
        msg.add(NoteMessaging::Keys::SEQUENCE, AtomicSequence64::get_next());
        
        send_message(msg);
    }
    
    // ===== HELPER FUNCTIONS =====
    
    bool ensure_owner(const std::shared_ptr<DeviceState>& device_state) {
        if (!device_state) return false;
        if (device_state->owner_pid != client_pid) {
            send_error(NoteMessaging::ErrorCodes::PID_MISMATCH, 
                      "PID mismatch: operation not permitted");
            return false;
        }
        return true;
    }
    
    void release_all_devices() {
        for (auto& [device_id, thread] : streaming_threads) {
            thread->stop();
        }
        streaming_threads.clear();
        
        device_encryptions_.clear();
        
        for (auto& [device_id, state] : device_states) {
            state->release();
        }
        device_states.clear();
        
        for (auto& [id, device] : available_devices) {
            if (device->handle) {
                libusb_release_interface(device->handle, device->interface_number);
                if (device->kernel_driver_attached) {
                    libusb_attach_kernel_driver(device->handle, device->interface_number);
                }
                libusb_close(device->handle);
                device->handle = nullptr;
            }
        }
        
        syslog(LOG_INFO, "Released all devices");
    }
    
    void offer_device_encryption(const std::string& device_id);
    void send_device_encryption_error(const std::string& device_id, 
                                      const std::string& reason);

    // ===== IMPLEMENTATIONS =====

    void discover_devices() {
        libusb_device** device_list = nullptr;
        ssize_t count = libusb_get_device_list(usb_ctx, &device_list);

        if (count < 0) {
            syslog(LOG_ERR, "Failed to get USB device list: %s", libusb_error_name((int)count));
            return;
        }

        syslog(LOG_INFO, "Scanning %zd USB devices", count);

        for (ssize_t i = 0; i < count; ++i) {
            libusb_device* device = device_list[i];
            struct libusb_device_descriptor desc;

            int result = libusb_get_device_descriptor(device, &desc);
            if (result != LIBUSB_SUCCESS) {
                syslog(LOG_WARNING, "Failed to get device descriptor: %s", libusb_error_name(result));
                continue;
            }

            // Check if this is a HID device (interface class 3)
            bool is_hid_device = false;
            libusb_config_descriptor* config = nullptr;

            if (libusb_get_active_config_descriptor(device, &config) == LIBUSB_SUCCESS) {
                for (int j = 0; j < config->bNumInterfaces; ++j) {
                    const struct libusb_interface* interface = &config->interface[j];
                    if (interface->num_altsetting > 0) {
                        const struct libusb_interface_descriptor* altsetting = &interface->altsetting[0];
                        if (altsetting->bInterfaceClass == LIBUSB_CLASS_HID) {
                            is_hid_device = true;
                            break;
                        }
                    }
                }
                libusb_free_config_descriptor(config);
            }

            if (is_hid_device) {
                // Create device ID from bus:address
                uint8_t bus = libusb_get_bus_number(device);
                uint8_t address = libusb_get_device_address(device);
                std::string device_id = std::to_string(bus) + ":" + std::to_string(address);

                // Check if we can open the device (for permission check)
                libusb_device_handle* handle = nullptr;
                if (libusb_open(device, &handle) == LIBUSB_SUCCESS) {
                    // Create descriptor
                    auto device_desc = std::make_shared<USBDeviceDescriptor>();
                    device_desc->handle = nullptr; // Will be opened when claimed
                    device_desc->interface_number = 0; // Usually 0 for HID
                    device_desc->kernel_driver_attached = false;
                    device_desc->device_id = device_id;

                    available_devices[device_id] = device_desc;
                    syslog(LOG_INFO, "Discovered HID device: %s (VID:PID %04x:%04x)",
                           device_id.c_str(), desc.idVendor, desc.idProduct);

                    libusb_close(handle);
                } else {
                    syslog(LOG_WARNING, "Cannot open HID device %s (permission issue?)",
                           device_id.c_str());
                }
            }
        }

        libusb_free_device_list(device_list, 1);
        syslog(LOG_INFO, "Device discovery complete. Found %zu HID devices", available_devices.size());
    }

    void handle_claim_device(const NoteBytes::Object& msg) {
        std::string device_id = msg.get_string(NoteMessaging::Keys::DEVICE_ID, NoteMessaging::Keys::EMPTY);
        if (device_id.empty()) {
            send_error(NoteMessaging::ErrorCodes::INVALID_MESSAGE, "Missing device_id");
            return;
        }

        // Check if device exists and is available
        auto device_it = available_devices.find(device_id);
        if (device_it == available_devices.end()) {
            send_error(NoteMessaging::ErrorCodes::ITEM_NOT_FOUND,
                      "Device not found: " + device_id);
            return;
        }

        auto device_desc = device_it->second;

        // Check if already claimed
        if (device_states.find(device_id) != device_states.end()) {
            send_error(NoteMessaging::ErrorCodes::ITEM_NOT_AVAILABLE,
                      "Device already claimed: " + device_id);
            return;
        }

        // Find the actual libusb_device
        libusb_device** device_list = nullptr;
        ssize_t count = libusb_get_device_list(usb_ctx, &device_list);
        libusb_device* usb_device = nullptr;

        for (ssize_t i = 0; i < count; ++i) {
            uint8_t bus = libusb_get_bus_number(device_list[i]);
            uint8_t address = libusb_get_device_address(device_list[i]);
            std::string current_id = std::to_string(bus) + ":" + std::to_string(address);
            if (current_id == device_id) {
                usb_device = device_list[i];
                break;
            }
        }

        if (!usb_device) {
            libusb_free_device_list(device_list, 1);
            send_error(NoteMessaging::ErrorCodes::ITEM_NOT_FOUND,
                      "USB device not found: " + device_id);
            return;
        }

        // Open device handle
        libusb_device_handle* handle = nullptr;
        int result = libusb_open(usb_device, &handle);
        libusb_free_device_list(device_list, 1);

        if (result != LIBUSB_SUCCESS) {
            send_error(NoteMessaging::ErrorCodes::PERMISSION_DENIED,
                      "Cannot open device " + device_id + ": " + libusb_error_name(result));
            return;
        }

        // Claim interface
        result = libusb_claim_interface(handle, device_desc->interface_number);
        if (result != LIBUSB_SUCCESS) {
            libusb_close(handle);
            send_error(NoteMessaging::ErrorCodes::PERMISSION_DENIED,
                      "Cannot claim interface for device " + device_id + ": " + libusb_error_name(result));
            return;
        }

        // Detach kernel driver if attached
        device_desc->kernel_driver_attached = false;
        if (libusb_kernel_driver_active(handle, device_desc->interface_number) == 1) {
            result = libusb_detach_kernel_driver(handle, device_desc->interface_number);
            if (result == LIBUSB_SUCCESS) {
                device_desc->kernel_driver_attached = true;
                syslog(LOG_INFO, "Detached kernel driver for device %s", device_id.c_str());
            } else {
                syslog(LOG_WARNING, "Failed to detach kernel driver for device %s: %s",
                       device_id.c_str(), libusb_error_name(result));
            }
        }

        // Update device descriptor
        device_desc->handle = handle;

        // Create device state
        cpp_int available_caps = Capabilities::Masks::mode_mask();
        auto device_state = std::make_shared<State::DeviceState>(device_id, client_pid, "hid", available_caps);
        device_state->state.add_flag(State::DeviceFlags::CLAIMED);
        device_state->state.add_flag(State::DeviceFlags::INTERFACE_CLAIMED);

        // Create and start streaming thread
        auto streaming_thread = std::make_unique<HIDDeviceStreamingThread>(
            device_desc, device_state, client_fd);
        streaming_thread->start();

        // Store in maps
        device_states[device_id] = device_state;
        streaming_threads[device_id] = std::move(streaming_thread);

        syslog(LOG_INFO, "Successfully claimed device: %s", device_id.c_str());

        // Send success response
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT, EventBytes::TYPE_ACCEPT);
        response.add(NoteMessaging::Keys::SEQUENCE, AtomicSequence64::get_next());
        response.add(NoteMessaging::Keys::DEVICE_ID, device_id);
        response.add(NoteMessaging::Keys::STATUS, "claimed");

        send_message(response);
    }

    void handle_release_device(const NoteBytes::Object& msg) {
        std::string device_id = msg.get_string(NoteMessaging::Keys::DEVICE_ID, NoteMessaging::Keys::EMPTY);
        if (device_id.empty()) {
            send_error(NoteMessaging::ErrorCodes::INVALID_MESSAGE, "Missing device_id");
            return;
        }

        // Check if device is claimed by this client
        auto state_it = device_states.find(device_id);
        if (state_it == device_states.end()) {
            send_error(NoteMessaging::ErrorCodes::ITEM_NOT_FOUND,
                      "Device not claimed: " + device_id);
            return;
        }

        auto device_state = state_it->second;
        if (!ensure_owner(device_state)) return;

        // Stop streaming thread
        auto thread_it = streaming_threads.find(device_id);
        if (thread_it != streaming_threads.end()) {
            thread_it->second->stop();
            streaming_threads.erase(thread_it);
        }

        // Get device descriptor
        auto device_it = available_devices.find(device_id);
        if (device_it != available_devices.end()) {
            auto device_desc = device_it->second;

            if (device_desc->handle) {
                // Release interface
                libusb_release_interface(device_desc->handle, device_desc->interface_number);

                // Reattach kernel driver if it was detached
                if (device_desc->kernel_driver_attached) {
                    int result = libusb_attach_kernel_driver(device_desc->handle, device_desc->interface_number);
                    if (result == LIBUSB_SUCCESS) {
                        syslog(LOG_INFO, "Reattached kernel driver for device %s", device_id.c_str());
                    } else {
                        syslog(LOG_WARNING, "Failed to reattach kernel driver for device %s: %s",
                               device_id.c_str(), libusb_error_name(result));
                    }
                }

                // Close handle
                libusb_close(device_desc->handle);
                device_desc->handle = nullptr;
                device_desc->kernel_driver_attached = false;
            }
        }

        // Clear encryption
        device_encryptions_.erase(device_id);

        // Remove from device states
        device_state->release();
        device_states.erase(state_it);

        syslog(LOG_INFO, "Successfully released device: %s", device_id.c_str());

        // Send success response
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT, EventBytes::TYPE_ACCEPT);
        response.add(NoteMessaging::Keys::SEQUENCE, AtomicSequence64::get_next());
        response.add(NoteMessaging::Keys::DEVICE_ID, device_id);
        response.add(NoteMessaging::Keys::STATUS, "released");

        send_message(response);
    }

    void handle_device_encryption_accept(const std::string& device_id, 
                                        const NoteBytes::Object& msg) {
        (void)msg; // Suppress unused parameter warning
        // TODO: Implement encryption acceptance logic
        syslog(LOG_INFO, "Encryption acceptance not yet implemented for device: %s", device_id.c_str());
        // Should establish encrypted communication channel
    }

    void handle_device_encryption_decline(const std::string& device_id) {
        // TODO: Implement encryption decline logic
        syslog(LOG_INFO, "Encryption decline not yet implemented for device: %s", device_id.c_str());
        // Should handle failed encryption negotiation
    }
};

#endif // DEVICE_SESSION_H