// include/device_session.h
// Refactored: Socket reader routes messages, devices stream independently

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

/**
 * USB Device Descriptor
 */
struct USBDeviceDescriptor {
    std::string device_id;
    int vendor_id;
    int product_id;
    int device_class;
    int device_subclass;
    int device_protocol;
    
    std::string manufacturer;
    std::string product;
    std::string serial_number;
    
    int bus_number;
    int device_address;
    int interface_number = 0;
    int interrupt_endpoint = 0;
    
    std::string device_type;
    cpp_int available_capabilities;
    int default_mode = State::DeviceFlags::RAW_MODE;
    
    bool available;
    bool kernel_driver_attached;
    
    libusb_device_handle* handle = nullptr;
    
    USBDeviceDescriptor() 
        : vendor_id(0), product_id(0), device_class(0), device_subclass(0),
          device_protocol(0), bus_number(0), device_address(0),
          available_capabilities(0), default_mode(State::DeviceFlags::RAW_MODE),
          available(false), kernel_driver_attached(false) {}
    
    void detect_capabilities(libusb_device* device, bool encryption_supported) {
        detect_device_type(device);
        
        if (device_type == "keyboard") {
            available_capabilities = Detection::detect_keyboard_capabilities();
            default_mode = Bits::PARSED_MODE;
        } else if (device_type == "mouse") {
            available_capabilities = Detection::detect_mouse_capabilities();
            default_mode = Bits::PARSED_MODE;
        } else {
            available_capabilities = Detection::detect_unknown_capabilities();
            default_mode = Bits::RAW_MODE;
        }
        
        if (encryption_supported) {
            bit_set(available_capabilities, Bits::ENCRYPTION_SUPPORTED);
        }
        
        std::string caps_str = Capabilities::Names::format_capabilities(available_capabilities);
        syslog(LOG_INFO, "Device '%s' detected as '%s' with capabilities: %s",
            product.c_str(), device_type.c_str(), caps_str.c_str());
    }
    
    void detect_device_type(libusb_device* device) {
        libusb_config_descriptor* config;
        if (libusb_get_config_descriptor(device, 0, &config) != 0) {
            device_type = "unknown";
            return;
        }
        
        for (int i = 0; i < config->bNumInterfaces; i++) {
            const libusb_interface* interface = &config->interface[i];
            for (int j = 0; j < interface->num_altsetting; j++) {
                const libusb_interface_descriptor* altsetting = &interface->altsetting[j];
                
                if (altsetting->bInterfaceClass == 3) {
                    if (altsetting->bInterfaceProtocol == 1) {
                        device_type = "keyboard";
                        libusb_free_config_descriptor(config);
                        return;
                    } else if (altsetting->bInterfaceProtocol == 2) {
                        device_type = "mouse";
                        libusb_free_config_descriptor(config);
                        return;
                    }
                }
            }
        }
        
        libusb_free_config_descriptor(config);
        device_type = "unknown";
    }

    void detect_endpoints(libusb_device* device) {
        libusb_config_descriptor* config;
        if (libusb_get_config_descriptor(device, 0, &config) != 0) {
            return;
        }

        for (int i = 0; i < config->bNumInterfaces; i++) {
            const libusb_interface* interface = &config->interface[i];
            for (int j = 0; j < interface->num_altsetting; j++) {
                const libusb_interface_descriptor* altsetting = &interface->altsetting[j];
                for (int e = 0; e < altsetting->bNumEndpoints; e++) {
                    const libusb_endpoint_descriptor* ep = &altsetting->endpoint[e];
                    if ((ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) == LIBUSB_TRANSFER_TYPE_INTERRUPT &&
                        (ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
                        interface_number = altsetting->bInterfaceNumber;
                        interrupt_endpoint = ep->bEndpointAddress;
                        libusb_free_config_descriptor(config);
                        return;
                    }
                }
            }
        }

        libusb_free_config_descriptor(config);
    }
    
    NoteBytes::Object to_notebytes() const {
        NoteBytes::Object obj;
        obj.add(NoteMessaging::Keys::ITEM_ID, device_id);
        obj.add("vendor_id", vendor_id);
        obj.add("product_id", product_id);
        obj.add("device_class", device_class);
        obj.add("device_subclass", device_subclass);
        obj.add("device_protocol", device_protocol);
        obj.add(NoteMessaging::Keys::ITEM_TYPE, device_type);
        
        obj.add("bus_number", bus_number);
        obj.add("device_address", device_address);
        
        if (!manufacturer.empty()) obj.add("manufacturer", manufacturer);
        if (!product.empty()) obj.add("product", product);
        if (!serial_number.empty()) obj.add("serial_number", serial_number);
        
        obj.add("available", available);
        obj.add("kernel_driver_attached", kernel_driver_attached);
        
        obj.add("available_capabilities", available_capabilities);
        obj.add("default_mode", Names::get_capability_name(default_mode));
        
        NoteBytes::Array caps_array;
        for (int i = 0; i < 128; i++) { 
            if (bit_test(available_capabilities, i)) {
                caps_array.add(NoteBytes::Value(Names::get_capability_name(i)));
            }
        }
        obj.add("capability_names", caps_array.as_value());
        
        return obj;
    }
};

/**
 * Device streaming thread
 * Runs independently, reads USB and sends events (encrypted if device encryption is active)
 */
class DeviceStreamingThread {
private:
    std::shared_ptr<USBDeviceDescriptor> device_desc_;
    std::shared_ptr<DeviceState> device_state_;
    int32_t source_id_;
    int client_fd_;
    std::thread thread_;
    
public:
    DeviceStreamingThread(
        std::shared_ptr<USBDeviceDescriptor> device_desc,
        std::shared_ptr<DeviceState> device_state,
        int32_t source_id,
        int client_fd)
        : device_desc_(device_desc)
        , device_state_(device_state)
        , source_id_(source_id)
        , client_fd_(client_fd) {}
    
    ~DeviceStreamingThread() {
        stop();
    }
    
    void start() {
        thread_ = std::thread([this]() { this->run(); });
    }
    
    void stop() {
        if (device_state_) {
            device_state_->state.remove_flag(DeviceFlags::STREAMING);
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }
    
private:
    void run() {
        int current_mode_bit = device_state_->get_current_mode_bit();
        const char* mode_name = Capabilities::Names::get_capability_name(current_mode_bit);
        
        syslog(LOG_INFO, "Device streaming started: %s (sourceId=%d, mode=%s, encrypted=%d)",
               device_state_->device_id.c_str(), source_id_, mode_name,
               device_state_->state.has_flag(DeviceFlags::ENCRYPTION_ENABLED));
        
        const int MAX_PENDING = 64;
        
        while (g_running && device_state_->state.has_flag(DeviceFlags::STREAMING)) {
            // Backpressure control
            {
                std::unique_lock<std::mutex> lk(device_state_->queue_mutex);
                device_state_->queue_cv.wait(lk, [&]() {
                    return !g_running || 
                           !device_state_->state.has_flag(DeviceFlags::STREAMING) ||
                           device_state_->pending_events < MAX_PENDING;
                });
                
                if (!g_running || !device_state_->state.has_flag(DeviceFlags::STREAMING)) {
                    break;
                }
            }
            
            // Try to read from USB
            if (device_desc_ && device_desc_->handle && device_desc_->interrupt_endpoint != 0) {
                uint8_t buf[512];
                int transferred = 0;
                int rc = libusb_interrupt_transfer(
                    device_desc_->handle,
                    device_desc_->interrupt_endpoint,
                    buf, sizeof(buf), &transferred, 1000);
                
                if (rc == 0 && transferred > 0) {
                    handle_usb_data(buf, transferred);
                } else if (rc == LIBUSB_ERROR_TIMEOUT) {
                    // Normal timeout, continue
                    continue;
                } else {
                    syslog(LOG_ERR, "USB transfer error: %d", rc);
                    device_state_->state.add_flag(DeviceFlags::TRANSFER_ERROR);
                    device_state_->state.remove_flag(DeviceFlags::STREAMING);
                    break;
                }
            } else {
                // Fallback: send synthetic events for testing
                send_synthetic_event();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        
        syslog(LOG_INFO, "Device streaming stopped: %s", device_state_->device_id.c_str());
    }
    
    void handle_usb_data(const uint8_t* data, int length) {
        int current_mode_bit = device_state_->get_current_mode_bit();
        
        if (current_mode_bit == Capabilities::Bits::PARSED_MODE) {
            // Parse HID report into events
            InputPacket::Factory factory(source_id_);
            HIDParser::HIDParser parser(device_desc_->device_type, &factory);
            auto parsed_packets = parser.parse_report(data, length);
            
            for (const auto& pkt : parsed_packets) {
                // Note: Encryption handled by device session, not here
                // Just send with sourceId prefix
                if (!send_event_packet(pkt)) {
                    device_state_->state.remove_flag(DeviceFlags::STREAMING);
                    return;
                }
            }
        } else {
            // RAW_MODE: send raw HID data
            NoteBytes::Object event_obj;
            event_obj.add(NoteMessaging::Keys::TYPE, EventBytes::EVENT_RAW_HID);
            
            uint8_t seq[6];
            AtomicSequence::get_next(seq);
            event_obj.add(NoteMessaging::Keys::SEQUENCE,
                         NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
            
            NoteBytes::Array payload;
            payload.add(NoteBytes::Value(data, length, NoteBytes::Type::RAW_BYTES));
            event_obj.add(NoteMessaging::Keys::PAYLOAD, payload.as_value());
            
            auto event_packet = event_obj.serialize_with_header();
            if (!send_event_packet(event_packet)) {
                device_state_->state.remove_flag(DeviceFlags::STREAMING);
            }
        }
    }
    
    void send_synthetic_event() {
        NoteBytes::Object event_obj;
        event_obj.add(NoteMessaging::Keys::TYPE, EventBytes::EVENT_KEY_DOWN);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        event_obj.add(NoteMessaging::Keys::SEQUENCE,
                     NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        
        NoteBytes::Array payload;
        payload.add(NoteBytes::Value((int32_t)65)); // 'A'
        payload.add(NoteBytes::Value((int32_t)0));
        event_obj.add(NoteMessaging::Keys::PAYLOAD, payload.as_value());
        
        auto event_packet = event_obj.serialize_with_header();
        if (!send_event_packet(event_packet)) {
            device_state_->state.remove_flag(DeviceFlags::STREAMING);
        }
    }
    
    bool send_event_packet(const std::vector<uint8_t>& event_packet) {
        // Send as routed message: [sourceId][event_packet]
        // Encryption is handled at the session level, not here
        NoteBytes::Writer writer(client_fd_, false);
        (void) writer.write(NoteBytes::Value(source_id_));
        (void) writer.write_raw(event_packet);
        
        try {
            (void) writer.flush();
            device_state_->event_queued();
            return true;
        } catch (const std::exception& e) {
            syslog(LOG_ERR, "Failed to send event for device %d: %s", source_id_, e.what());
            return false;
        }
    }
};

/**
 * Device Session - manages protocol and routing
 */
class DeviceSession {
private:
    libusb_context* usb_ctx;
    int client_fd;
    pid_t client_pid = 0;
    cpp_int mode_mask = Masks::mode_mask();
    
    // Device management
    std::map<int32_t, std::shared_ptr<DeviceState>> device_states;
    std::map<int32_t, std::unique_ptr<DeviceStreamingThread>> streaming_threads;
    std::map<std::string, std::shared_ptr<USBDeviceDescriptor>> available_devices;
    
    // Per-device encryption (sourceId -> encryption handshake)
    std::map<int32_t, std::unique_ptr<EncryptionProtocol::EncryptionHandshake>> device_encryptions_;
    
public:
    DeviceSession(libusb_context* ctx, int client, pid_t pid) 
        : usb_ctx(ctx), client_fd(client), client_pid(pid) {
        
        syslog(LOG_INFO, "Session created for client pid=%d", client_pid);
        discover_devices();
    }
    
    ~DeviceSession() {
        // Stop all streaming threads
        for (auto& [source_id, thread] : streaming_threads) {
            thread->stop();
        }
        streaming_threads.clear();
        
        release_all_devices();
    }
    
    /**
     * Main protocol loop
     */
    void readSocket() {
        // Main message routing loop - ALL messages come through here
        for (;;) {
            try {
                // Read next message from socket
                auto routed = InputPacket::receive_message(client_fd);
                
                if (!routed.isValid()) {
                    syslog(LOG_ERR, "Invalid message received");
                    break;
                }
                
                if (routed.is_routed) {
                    // Message has sourceId - route to device (may be encrypted device data OR encryption negotiation)
                    handle_routed_message(routed);
                } else {
                    // Control message - handle protocol (NEVER encrypted)
                    NoteBytes::Object msg = NoteBytes::Object::deserialize(
                        routed.message.data().data(),
                        routed.message.data().size());
                    handle_control_message(msg);
                }
                
            } catch (const std::exception& e) {
                syslog(LOG_ERR, "Error in message loop: %s", e.what());
                break;
            }
        }
    }
    
private:
    /**
     * Handle control messages (no sourceId) - NEVER encrypted
     */
    void handle_control_message(const NoteBytes::Object& msg) {
        uint8_t msg_type = msg.get_byte(NoteMessaging::Keys::TYPE);
        
        switch (msg_type) {
            case EventBytes::TYPE_CMD:
                handle_command(msg);
                break;
                
            case EventBytes::TYPE_HELLO:
                send_accept(NoteMessaging::ProtocolMessages::READY);
                break;
                
            case EventBytes::TYPE_PING:
                send_pong();
                break;
                
            case EventBytes::EVENT_RELEASE:
            case EventBytes::TYPE_SHUTDOWN:
                syslog(LOG_INFO, "Client requested disconnect");
                send_accept("Goodbye");
                throw std::runtime_error("Client disconnect");
                
            default:
                send_error(1, "Unknown message type");
                break;
        }
    }
    
    /**
     * Handle routed messages (has sourceId)
     * Can be: encryption negotiation for device, encrypted data, or plaintext device commands
     */
    void handle_routed_message(const InputPacket::RoutedMessage& routed) {
        auto it = device_states.find(routed.source_id);
        if (it == device_states.end()) {
            syslog(LOG_WARNING, "Message for unknown sourceId: %d", routed.source_id);
            return;
        }
        
        auto device_state = it->second;
        
        // Check if this is an encryption negotiation message
        if (routed.isObject()) {
            NoteBytes::Object msg = NoteBytes::Object::deserialize(
                routed.message.data().data(),
                routed.message.data().size());
            
            uint8_t msg_type = msg.get_byte(NoteMessaging::Keys::TYPE);
            
            // Handle encryption negotiation messages
            if (msg_type == EventBytes::TYPE_ENCRYPTION_ACCEPT) {
                handle_device_encryption_accept(routed.source_id, msg);
                return;
            } else if (msg_type == EventBytes::TYPE_ENCRYPTION_DECLINE) {
                handle_device_encryption_decline(routed.source_id);
                return;
            }
            
            // Other plaintext device commands
            syslog(LOG_DEBUG, "Received plaintext command type %d for device %d", 
                   msg_type, routed.source_id);
        }
        
        // Handle encrypted device data
        if (routed.isEncrypted()) {
            auto enc_it = device_encryptions_.find(routed.source_id);
            if (enc_it == device_encryptions_.end() || !enc_it->second->is_active()) {
                syslog(LOG_ERR, "Received encrypted message for device %d but no active encryption", 
                       routed.source_id);
                return;
            }
            
            std::vector<uint8_t> plaintext;
            if (!enc_it->second->decrypt(routed.message.data(), plaintext)) {
                syslog(LOG_ERR, "Decryption failed for device %d", routed.source_id);
                return;
            }
            
            NoteBytes::Object event_obj = NoteBytes::Object::deserialize(
                plaintext.data(), plaintext.size());
            
            uint8_t event_type = event_obj.get_byte(NoteMessaging::Keys::TYPE);
            syslog(LOG_DEBUG, "Received encrypted event type %d for device %d", 
                   event_type, routed.source_id);
        }
    }
    
    void offer_device_encryption(int32_t source_id) {
        auto encryption = std::make_unique<EncryptionProtocol::EncryptionHandshake>(client_fd);
        
        if (!encryption->start_negotiation()) {
            syslog(LOG_ERR, "Failed to start encryption for device %d", source_id);
            return;
        }
        
        auto server_public_key = encryption->get_public_key();
        if (server_public_key.empty()) {
            syslog(LOG_ERR, "Failed to get public key for device %d", source_id);
            return;
        }
        
        // Build encryption offer
        auto offer_msg = EncryptionProtocol::Messages::build_encryption_offer(
            server_public_key, "aes-256-gcm");
        
        // Send WITH sourceId prefix - this is a routed message
        send_routed_control_message(source_id, offer_msg);
        
        // Store pending encryption for this device
        device_encryptions_[source_id] = std::move(encryption);
        
        syslog(LOG_INFO, "Sent encryption offer for device %d", source_id);
        std::fill(server_public_key.begin(), server_public_key.end(), 0);
    }
    
    void handle_device_encryption_accept(int32_t source_id, const NoteBytes::Object& msg) {
        auto it = device_encryptions_.find(source_id);
        if (it == device_encryptions_.end()) {
            syslog(LOG_ERR, "Received encryption accept for device %d but no pending negotiation", 
                   source_id);
            return;
        }
        
        std::vector<uint8_t> client_public_key;
        if (!EncryptionProtocol::Messages::parse_encryption_accept(msg, client_public_key)) {
            syslog(LOG_ERR, "Failed to parse encryption accept for device %d", source_id);
            send_device_encryption_error(source_id, "Invalid public key");
            device_encryptions_.erase(it);
            return;
        }
        
        if (!it->second->finalize(client_public_key)) {
            syslog(LOG_ERR, "Failed to finalize encryption for device %d", source_id);
            send_device_encryption_error(source_id, "Key exchange failed");
            std::fill(client_public_key.begin(), client_public_key.end(), 0);
            device_encryptions_.erase(it);
            return;
        }
        
        // Mark device as encrypted
        auto dev_it = device_states.find(source_id);
        if (dev_it != device_states.end()) {
            dev_it->second->state.add_flag(DeviceFlags::ENCRYPTION_ENABLED);
            bit_set(dev_it->second->enabled_capabilities, Bits::ENCRYPTION_ENABLED);
        }
        
        // Send ready message (with sourceId prefix)
        auto ready_msg = EncryptionProtocol::Messages::build_encryption_ready(it->second->get_iv());
        send_routed_control_message(source_id, ready_msg);
        
        syslog(LOG_INFO, "Encryption active for device %d", source_id);
        std::fill(client_public_key.begin(), client_public_key.end(), 0);
    }
    
    void handle_device_encryption_decline(int32_t source_id) {
        syslog(LOG_INFO, "Client declined encryption for device %d", source_id);
        device_encryptions_.erase(source_id);
    }
    
    void send_device_encryption_error(int32_t source_id, const std::string& reason) {
        auto error_msg = EncryptionProtocol::Messages::build_encryption_error(reason);
        send_routed_control_message(source_id, error_msg);
    }
    
    void handle_command(const NoteBytes::Object& msg) {
        std::string cmd = msg.get_string(NoteMessaging::Keys::CMD, "");

        if (cmd == NoteMessaging::ProtocolMessages::REQUEST_DISCOVERY) {
            send_device_list();
        } else if (cmd == NoteMessaging::ProtocolMessages::CLAIM_ITEM) {
            handle_claim_device(msg);
        } else if (cmd == NoteMessaging::ProtocolMessages::RELEASE_ITEM) {
            handle_release_device(msg);
        } else if (cmd == NoteMessaging::ProtocolMessages::RESUME) {
            handle_resume(msg);
        } else {
            send_error(NoteMessaging::ErrorCodes::INVALID_MESSAGE, "Unknown command");
        }
    }
    
    void send_device_list() {
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_CMD);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        response.add(NoteMessaging::Keys::SEQUENCE,
                    NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        
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
    
    void handle_claim_device(const NoteBytes::Object& msg) {
        std::string device_id = msg.get_string(NoteMessaging::Keys::ITEM_ID, "");
        int32_t source_id = msg.get_int("source_id", 0);
        std::string requested_mode = msg.get_string("mode", "parsed");
        bool request_encryption = msg.get_bool("encryption", false);
        
        auto it = available_devices.find(device_id);
        if (it == available_devices.end()) {
            send_error(NoteMessaging::ErrorCodes::ITEM_NOT_FOUND, "Item not found");
            return;
        }
        
        auto device_desc = it->second;
        if (!device_desc->available) {
            send_error(NoteMessaging::ErrorCodes::ITEM_NOT_AVAILABLE, "Item not available");
            return;
        }
        
        if (!Validation::validate_mode_compatibility(device_desc->device_type, requested_mode)) {
            send_error(NoteMessaging::ErrorCodes::MODE_INCOMPATIBLE, 
                      "Mode not compatible with item type");
            return;
        }
        
        int requested_mode_bit = Names::get_capability_bit(requested_mode);
        if (!has_any_bits(device_desc->available_capabilities & mode_mask, 
                        cpp_int(1) << requested_mode_bit)) {
            send_error(NoteMessaging::ErrorCodes::MODE_NOT_SUPPORTED, 
                    "Item does not support requested mode");
            return;
        }
        
        // Check if encryption requested but not available in daemon
        if (request_encryption && !EncryptionProtocol::EncryptionHandshake::is_available()) {
            send_error(NoteMessaging::ErrorCodes::ENCRYPTION_FAILED,
                     "Encryption requested but not available (OpenSSL not compiled)");
            return;
        }
        
        for (const auto& kv : device_states) {
            if (kv.second->device_id == device_id) {
                send_error(NoteMessaging::ErrorCodes::ALREADY_CLAIMED, "Item already claimed");
                return;
            }
        }

        if (msg.contains(NoteMessaging::Keys::PID)) {
            int supplied_pid = msg.get_int(NoteMessaging::Keys::PID, 0);
            if (supplied_pid != 0 && supplied_pid != client_pid) {
                send_error(NoteMessaging::ErrorCodes::PID_MISMATCH, 
                          "PID mismatch: claim must come from the owning process");
                return;
            }
        }

        auto device_state = std::make_shared<DeviceState>(
            device_id, source_id, client_pid,
            device_desc->device_type,
            device_desc->available_capabilities);
           
        device_state->hardware_info.vendor_id = device_desc->vendor_id;
        device_state->hardware_info.product_id = device_desc->product_id;
        device_state->hardware_info.manufacturer = device_desc->manufacturer;
        device_state->hardware_info.product = device_desc->product;
        device_state->hardware_info.bus_number = device_desc->bus_number;
        device_state->hardware_info.device_address = device_desc->device_address;
        
        if (!device_state->enable_mode(requested_mode)) {
            send_error(NoteMessaging::ErrorCodes::FEATURE_NOT_SUPPORTED, 
                     "Failed to enable requested mode");
            return;
        }
        
        if (claim_usb_device(device_desc)) {
            syslog(LOG_INFO, "USB device claimed successfully");
            device_state->state.add_flag(DeviceFlags::INTERFACE_CLAIMED);
            device_state->state.add_flag(DeviceFlags::CLAIMED);
            device_state->state.add_flag(DeviceFlags::STREAMING);
            
            device_states[source_id] = device_state;
            
            // Start independent streaming thread
            auto streaming_thread = std::make_unique<DeviceStreamingThread>(
                device_desc, device_state, source_id, client_fd);
            streaming_thread->start();
            streaming_threads[source_id] = std::move(streaming_thread);
            
            send_accept(NoteMessaging::ProtocolMessages::ITEM_CLAIMED);
            
            int current_mode_bit = device_state->get_current_mode_bit();
            const char* currentModeName = Capabilities::Names::get_capability_name(current_mode_bit);
            
            syslog(LOG_INFO, "Device claimed: %s (sourceId=%d, mode=%s)",
                device_state->device_id.c_str(), source_id, currentModeName);
            
            // If encryption requested, offer it now (client negotiates per-device)
            if (request_encryption) {
                offer_device_encryption(source_id);
            }
        } else {
            send_error(NoteMessaging::ErrorCodes::CLAIM_FAILED, 
                     "Failed to claim USB device");
        }
    }
    
    void handle_release_device(const NoteBytes::Object& msg) {
        int32_t source_id = msg.get_int("source_id", 0);
        
        auto it = device_states.find(source_id);
        if (it != device_states.end()) {
            auto device_state = it->second;
            if (!ensure_owner(device_state)) return;

            // Stop streaming thread
            auto thread_it = streaming_threads.find(source_id);
            if (thread_it != streaming_threads.end()) {
                thread_it->second->stop();
                streaming_threads.erase(thread_it);
            }

            // Release USB resources
            for (auto &kv : available_devices) {
                if (kv.second->device_id == device_state->device_id) {
                    if (kv.second->handle) {
                        libusb_release_interface(kv.second->handle, kv.second->interface_number);
                        if (kv.second->kernel_driver_attached) {
                            libusb_attach_kernel_driver(kv.second->handle, kv.second->interface_number);
                        }
                        libusb_close(kv.second->handle);
                        kv.second->handle = nullptr;
                    }
                    break;
                }
            }

            it->second->release();
            device_states.erase(it);
            send_accept(NoteMessaging::ProtocolMessages::ITEM_RELEASED);
        }
    }
    
    void handle_resume(const NoteBytes::Object& msg) {
        int processed_count = msg.get_int(NoteMessaging::Keys::PROCESSED_COUNT, 0);
        int32_t src = 0;
        try {
            src = msg.get_int(NoteMessaging::Keys::SOURCE_ID, 0);
        } catch (...) {
            src = 0;
        }

        syslog(LOG_INFO, "Client acknowledged %d messages for source %d", processed_count, src);

        if (processed_count <= 0) return;

        auto it = device_states.find(src);
        if (it == device_states.end()) return;

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
    
    void discover_devices() {
        libusb_device** devices;
        ssize_t count = libusb_get_device_list(usb_ctx, &devices);
        
        if (count < 0) {
            syslog(LOG_ERR, "Failed to get device list");
            return;
        }
        
        // Encryption support is purely a daemon capability (OpenSSL availability)
        // No config override - if OpenSSL is available, encryption is possible
        bool encryption_supported = EncryptionProtocol::EncryptionHandshake::is_available();
        
        for (ssize_t i = 0; i < count; i++) {
            auto device_desc = create_device_descriptor(devices[i], encryption_supported);
            if (device_desc && device_desc->available) {
                available_devices[device_desc->device_id] = device_desc;
            }
        }
        
        libusb_free_device_list(devices, 1);
        syslog(LOG_INFO, "Discovered %zu devices (encryption %s)", 
               available_devices.size(), 
               encryption_supported ? "available" : "not available");
    }
    
    std::shared_ptr<USBDeviceDescriptor> create_device_descriptor(
        libusb_device* device, bool encryption_supported) {
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(device, &desc) < 0) {
            return nullptr;
        }
        
        auto device_desc = std::make_shared<USBDeviceDescriptor>();
        device_desc->vendor_id = desc.idVendor;
        device_desc->product_id = desc.idProduct;
        device_desc->device_class = desc.bDeviceClass;
        device_desc->device_subclass = desc.bDeviceSubClass;
        device_desc->device_protocol = desc.bDeviceProtocol;
        device_desc->bus_number = libusb_get_bus_number(device);
        device_desc->device_address = libusb_get_device_address(device);
        
        char id_buf[64];
        snprintf(id_buf, sizeof(id_buf), "%04x:%04x-%d-%d",
                desc.idVendor, desc.idProduct,
                device_desc->bus_number, device_desc->device_address);
        device_desc->device_id = id_buf;
        
        // Get string descriptors
        libusb_device_handle* handle;
        if (libusb_open(device, &handle) == 0) {
            char str_buf[256];
            if (desc.iManufacturer) {
                if (libusb_get_string_descriptor_ascii(handle, desc.iManufacturer,
                                                      (unsigned char*)str_buf, sizeof(str_buf)) > 0) {
                    device_desc->manufacturer = str_buf;
                }
            }
            if (desc.iProduct) {
                if (libusb_get_string_descriptor_ascii(handle, desc.iProduct,
                                                      (unsigned char*)str_buf, sizeof(str_buf)) > 0) {
                    device_desc->product = str_buf;
                }
            }
            libusb_close(handle);
        }
        
        device_desc->detect_capabilities(device, encryption_supported);
        device_desc->detect_endpoints(device);
        device_desc->available = true;
        
        return device_desc;
    }
    
    bool claim_usb_device(std::shared_ptr<USBDeviceDescriptor> device_desc) {
        if (!device_desc) return false;

        libusb_device** list = nullptr;
        ssize_t cnt = libusb_get_device_list(usb_ctx, &list);
        if (cnt < 0) {
            syslog(LOG_ERR, "libusb_get_device_list failed: %zd", cnt);
            return false;
        }

        libusb_device_handle* handle = nullptr;
        for (ssize_t i = 0; i < cnt; ++i) {
            libusb_device* dev = list[i];
            int bus = libusb_get_bus_number(dev);
            int addr = libusb_get_device_address(dev);
            if (bus == device_desc->bus_number && addr == device_desc->device_address) {
                if (libusb_open(dev, &handle) == 0) {
                    break;
                } else {
                    handle = nullptr;
                }
            }
        }

        libusb_free_device_list(list, 1);

        if (!handle) {
            syslog(LOG_ERR, "Failed to open USB device %s by bus/addr %d/%d",
                   device_desc->device_id.c_str(), device_desc->bus_number, device_desc->device_address);
            return false;
        }

        // Detach kernel driver if active
        if (handle && device_desc->interface_number >= 0) {
            if (libusb_kernel_driver_active(handle, device_desc->interface_number) == 1) {
                if (libusb_detach_kernel_driver(handle, device_desc->interface_number) == 0) {
                    device_desc->kernel_driver_attached = true;
                    syslog(LOG_INFO, "Detached kernel driver for %s", device_desc->device_id.c_str());
                }
            }
        }

        // Claim interface
        int rc = libusb_claim_interface(handle, device_desc->interface_number);
        if (rc != 0) {
            syslog(LOG_ERR, "Failed to claim interface %d for %s: %d",
                   device_desc->interface_number, device_desc->device_id.c_str(), rc);
            libusb_close(handle);
            return false;
        }

        device_desc->handle = handle;
        device_desc->available = true;
        syslog(LOG_INFO, "Claimed USB device %s (iface=%d, ep=0x%02x)",
               device_desc->device_id.c_str(), device_desc->interface_number,
               device_desc->interrupt_endpoint);

        return true;
    }

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
        for (auto& [source_id, thread] : streaming_threads) {
            thread->stop();
        }
        streaming_threads.clear();
        
        for (auto& [source_id, state] : device_states) {
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
    }
    
    // Message sending helpers
    void send_message(const NoteBytes::Object& msg) {
        // Control messages (no sourceId) - never encrypted
        NoteBytes::Writer writer(client_fd, false);
        (void) writer.write(msg);
        (void) writer.flush();
    }
    
    void send_routed_control_message(int32_t source_id, const NoteBytes::Object& msg) {
        // Routed control messages (encryption negotiation) - NOT encrypted
        NoteBytes::Writer writer(client_fd, false);
        (void) writer.write(NoteBytes::Value(source_id));
        (void) writer.write(msg);
        (void) writer.flush();
    }
    
    void send_accept(const std::string& status = "ok") {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ACCEPT);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        msg.add(NoteMessaging::Keys::SEQUENCE, 
               NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        msg.add(NoteMessaging::Keys::STATUS, status);
        
        send_message(msg);
    }
    
    void send_error(int code, const std::string& message) {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ERROR);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        msg.add(NoteMessaging::Keys::SEQUENCE,
               NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        msg.add(NoteMessaging::Keys::ERROR_CODE, code);
        msg.add(NoteMessaging::Keys::MSG, message);
        
        send_message(msg);
    }
    
    void send_pong() {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_PONG);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        msg.add(NoteMessaging::Keys::SEQUENCE,
               NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        
        send_message(msg);
    }
};

#endif // DEVICE_SESSION_H