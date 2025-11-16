// include/device_session.h
// Device session with encryption support

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
#include "input_packet.h"
#include "hid_parser.h"
#include "encryption_protocol.h"

using namespace State;
using namespace Capabilities;

/**
 * USB Device Descriptor (with encryption capability)
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
        
        // Detect base capabilities
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
        
        // Add encryption capability if supported by daemon
        if (encryption_supported) {
            bit_set(available_capabilities, Bits::ENCRYPTION_SUPPORTED);
        }
        std::string caps_str = Capabilities::Names::format_capabilities(available_capabilities);
        
        syslog(LOG_INFO,
            "Device '%s' detected as '%s' with capabilities: %s",
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
                const libusb_interface_descriptor* altsetting = 
                    &interface->altsetting[j];
                
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
                    // Look for interrupt IN endpoint
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
        
        // Add capability names
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
 * Device Session with encryption support
 */
class DeviceSession {
private:
    libusb_context* usb_ctx;
    libusb_device_handle* device_handle = nullptr;
    int client_fd;
    pid_t client_pid = 0;
    cpp_int mode_mask = Masks::mode_mask();
    // Device states
    std::map<int32_t, std::shared_ptr<DeviceState>> device_states;
    std::map<std::string, std::shared_ptr<USBDeviceDescriptor>> available_devices;
    
    // Encryption
    std::unique_ptr<EncryptionProtocol::EncryptionHandshake> encryption_;
    std::unique_ptr<EncryptionProtocol::EncryptedMessageWrapper> message_wrapper_;
    bool encryption_enabled_in_config = false;
    
public:
    DeviceSession(libusb_context* ctx, int client, pid_t pid, 
                 bool encryption_enabled = false) 
        : usb_ctx(ctx), client_fd(client), client_pid(pid),
          encryption_enabled_in_config(encryption_enabled) {
        
        // Initialize encryption if enabled
        if (encryption_enabled_in_config && 
            EncryptionProtocol::EncryptionHandshake::is_available()) {
            encryption_ = std::make_unique<EncryptionProtocol::EncryptionHandshake>(client_fd);
            message_wrapper_ = std::make_unique<EncryptionProtocol::EncryptedMessageWrapper>(*encryption_);
            syslog(LOG_INFO, "Session created with encryption support");
        } else {
            syslog(LOG_INFO, "Session created without encryption");
        }
        
        discover_devices();
    }
    
    ~DeviceSession() {
        release_device();
    }
    
    /**
     * Handle protocol negotiation with encryption support
     */
    void handle_client_protocol_negotiation() {
        std::vector<uint8_t> packet_buffer;
        
        // First, check if client wants encryption
        if (encryption_ && offer_encryption()) {
            syslog(LOG_INFO, "Encryption handshake completed");
        }
        
        // Main protocol loop
        for (;;) {
            try {
                NoteBytes::Object msg;

                // If encryption is active, use the wrapper which performs the
                // read + decrypt and returns a RoutedMessage (may be routed or
                // a control OBJECT). This prevents double-reading the socket.
                if (encryption_ && encryption_->is_active() && message_wrapper_) {
                    auto routed = message_wrapper_->receive_message(client_fd, packet_buffer);
                    // routed.message contains the parsed NoteBytes::Object
                    msg = routed.message;
                } else {
                    // Non-encrypted path: read raw packet then parse
                    if (!InputPacket::read_packet(client_fd, packet_buffer)) {
                        break; // socket closed or error
                    }

                    if (packet_buffer.empty() || packet_buffer[0] != NoteBytes::Type::OBJECT) {
                        // Only expect control OBJECT messages during negotiation
                        continue;
                    }

                    msg = InputPacket::parse_packet(packet_buffer);
                }

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
                        syslog(LOG_INFO, "Client requested release");
                        send_accept("Release acknowledged");
                        return;
                        
                    default:
                        send_error(1, "Unknown message type");
                        break;
                }
            } catch (const std::exception& e) {
                syslog(LOG_ERR, "Error parsing message: %s", e.what());
                send_error(2, "Parse error");
                break;
            }
        }
    }
    
private:
    /**
     * Offer encryption to client
     * Returns true if encryption was enabled
     */
    bool offer_encryption() {
        if (!encryption_) {
            return false;
        }
        
        // Start key exchange
        if (!encryption_->start_negotiation()) {
            syslog(LOG_ERR, "Failed to start encryption negotiation");
            return false;
        }
        
        // Get our public key
        auto server_public_key = encryption_->get_public_key();
        if (server_public_key.empty()) {
            syslog(LOG_ERR, "Failed to get server public key");
            return false;
        }
        
        // Send encryption offer
        auto offer_msg = EncryptionProtocol::Messages::build_encryption_offer(
            server_public_key, "aes-256-gcm"
        );
        
        auto packet = offer_msg.serialize_with_header();
        if (!InputPacket::write_packet(client_fd, packet)) {
            syslog(LOG_ERR, "Failed to send encryption offer");
            // zero sensitive key material before returning
            std::fill(server_public_key.begin(), server_public_key.end(), 0);
            return false;
        }
        
        syslog(LOG_INFO, "Sent encryption offer");
        
        // Wait for response
        std::vector<uint8_t> response_buffer;
        if (!InputPacket::read_packet(client_fd, response_buffer)) {
            syslog(LOG_ERR, "No response to encryption offer");
            std::fill(server_public_key.begin(), server_public_key.end(), 0);
            return false;
        }
        
        NoteBytes::Object response = InputPacket::parse_packet(response_buffer);
        uint8_t response_type = response.get_byte(NoteMessaging::Keys::TYPE);
        
        if (response_type == EventBytes::TYPE_ENCRYPTION_DECLINE) {
            syslog(LOG_INFO, "Client declined encryption");
            encryption_.reset();
            message_wrapper_.reset();
            return false;
        }
        
        if (response_type != EventBytes::TYPE_ENCRYPTION_ACCEPT) {
            syslog(LOG_ERR, "Unexpected response to encryption offer: %d", response_type);
            return false;
        }
        
        // Parse client's public key
        std::vector<uint8_t> client_public_key;
        if (!EncryptionProtocol::Messages::parse_encryption_accept(response, client_public_key)) {
            syslog(LOG_ERR, "Failed to parse encryption accept");
            send_encryption_error("Invalid public key");
            std::fill(server_public_key.begin(), server_public_key.end(), 0);
            return false;
        }
        
        // Finalize encryption
        if (!encryption_->finalize(client_public_key)) {
            syslog(LOG_ERR, "Failed to finalize encryption");
            send_encryption_error("Key exchange failed");
            // zero client key material
            std::fill(client_public_key.begin(), client_public_key.end(), 0);
            std::fill(server_public_key.begin(), server_public_key.end(), 0);
            return false;
        }
        
        // Send encryption ready with IV
        auto ready_msg = EncryptionProtocol::Messages::build_encryption_ready(
            encryption_->get_iv()
        );
        
        packet = ready_msg.serialize_with_header();
        if (!InputPacket::write_packet(client_fd, packet)) {
            syslog(LOG_ERR, "Failed to send encryption ready");
            return false;
        }
        
        syslog(LOG_INFO, "Encryption active");
        // zero client public key and server public key buffers
        std::fill(client_public_key.begin(), client_public_key.end(), 0);
        std::fill(server_public_key.begin(), server_public_key.end(), 0);
        return true;
    }
    
    void send_encryption_error(const std::string& reason) {
        auto error_msg = EncryptionProtocol::Messages::build_encryption_error(reason);
        auto packet = error_msg.serialize_with_header();
        InputPacket::write_packet(client_fd, packet);
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
        

        NoteBytes::Writer writer(client_fd, false);
        (void) writer.write(response);
        (void) writer.flush();
        
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
     
        // Validate mode
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
        
        // Check encryption request
        if (request_encryption && (!encryption_ || !encryption_->is_active())) {
            send_error(NoteMessaging::ErrorCodes::ENCRYPTION_FAILED,
                     "Encryption requested but not active");
            return;
        }
        
        // Check if already claimed by other client
        for (const auto& kv : device_states) {
            if (kv.second->device_id == device_id) {
                send_error(NoteMessaging::ErrorCodes::ALREADY_CLAIMED, "Item already claimed");
                return;
            }
        }

        // If caller supplied a pid field, ensure it matches the peer PID
        if (msg.contains(NoteMessaging::Keys::PID)) {
            int supplied_pid = msg.get_int(NoteMessaging::Keys::PID, 0);
            if (supplied_pid != 0 && supplied_pid != client_pid) {
                send_error(NoteMessaging::ErrorCodes::PID_MISMATCH, "PID mismatch: claim must come from the owning process");
                return;
            }
        }

        // Create device state
        auto device_state = std::make_shared<DeviceState>(
            device_id, source_id, client_pid,
            device_desc->device_type,
            device_desc->available_capabilities
        );
           
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
        
        // Enable encryption for device if requested
        if (request_encryption && encryption_->is_active()) {
            device_state->state.add_flag(DeviceFlags::ENCRYPTION_ENABLED);
            bit_set(device_state->enabled_capabilities, Bits::ENCRYPTION_ENABLED);
        }
        
        if (claim_usb_device(device_desc)) {
            syslog(LOG_INFO, "USB device claimed successfully");
            // mark interface claimed flag
            device_state->state.add_flag(DeviceFlags::INTERFACE_CLAIMED);
            device_state->state.add_flag(DeviceFlags::CLAIMED);
            device_state->state.add_flag(DeviceFlags::STREAMING);
            
            device_states[source_id] = device_state;
            start_device_streaming(device_desc, device_state);
            
            send_accept(NoteMessaging::ProtocolMessages::ITEM_CLAIMED);
            
            int current_mode_bit = device_state->get_current_mode_bit();
            const char* currentModeName = Capabilities::Names::get_capability_name(current_mode_bit);
            
            syslog(LOG_INFO, "Starting event stream for %s in mode: %s (encrypted=%d)",
                device_state->device_id.c_str(),
                currentModeName,
                device_state->state.has_flag(DeviceFlags::ENCRYPTION_ENABLED));
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

            // Release USB resources if claimed
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
        // Decrement pending_events and notify any waiting streamer
        for (int i = 0; i < processed_count; ++i) {
            device_state->event_delivered();
        }

        // Wake the streaming thread if it was waiting due to backpressure
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
        
        bool encryption_supported = (encryption_ != nullptr);
        
        for (ssize_t i = 0; i < count; i++) {
            auto device_desc = create_device_descriptor(devices[i], encryption_supported);
            if (device_desc && device_desc->available) {
                available_devices[device_desc->device_id] = device_desc;
            }
        }
        
        libusb_free_device_list(devices, 1);
        syslog(LOG_INFO, "Discovered %zu devices", available_devices.size());
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
        // Attempt to open device by bus/address (strict match) and claim the discovered interface
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
                    break; // handle set
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

    // Ensure that the current client is the owner of the device state
    bool ensure_owner(const std::shared_ptr<DeviceState>& device_state) {
        if (!device_state) return false;
        if (device_state->owner_pid != client_pid) {
            send_error(NoteMessaging::ErrorCodes::PID_MISMATCH, "PID mismatch: operation not permitted");
            return false;
        }
        return true;
    }
    
    void start_device_streaming(std::shared_ptr<USBDeviceDescriptor> device_desc,
                               std::shared_ptr<DeviceState> device_state) {
        std::thread([this, device_desc, device_state]() {
            stream_device_events(device_desc, device_state);
        }).detach();
    }
    
    void stream_device_events(std::shared_ptr<USBDeviceDescriptor> device_desc,
                             std::shared_ptr<DeviceState> device_state) {
        int current_mode_bit = device_state->get_current_mode_bit();
        const char* currentModeName = Capabilities::Names::get_capability_name(current_mode_bit);
        
        syslog(LOG_INFO, "Starting event stream for %s in mode: %s (encrypted=%d)",
               device_state->device_id.c_str(),
               currentModeName,
               device_state->state.has_flag(DeviceFlags::ENCRYPTION_ENABLED));
        const int MAX_PENDING = 64;

        // Streaming loop: prefer real USB interrupt transfers when available
        while (g_running && device_state->state.has_flag(DeviceFlags::STREAMING)) {
            // Backpressure: wait while too many pending events
            {
                std::unique_lock<std::mutex> lk(device_state->queue_mutex);
                device_state->queue_cv.wait(lk, [&]() {
                    return !g_running || !device_state->state.has_flag(DeviceFlags::STREAMING) ||
                           device_state->pending_events < MAX_PENDING;
                });

                if (!g_running || !device_state->state.has_flag(DeviceFlags::STREAMING)) break;
            }
            bool sent = false;

            if (device_desc && device_desc->handle && device_desc->interrupt_endpoint != 0) {
                // Read from USB interrupt endpoint
                uint8_t buf[512];
                int transferred = 0;
                int rc = libusb_interrupt_transfer(device_desc->handle,
                                                   device_desc->interrupt_endpoint,
                                                   buf, sizeof(buf), &transferred, 1000);
                if (rc == 0 && transferred > 0) {
                    // If device is in parsed mode, run HID parser to create parsed events
                     if (current_mode_bit == Capabilities::Bits::PARSED_MODE) {
                        InputPacket::Factory factory(device_state->source_id);
                        HIDParser::HIDParser parser(device_desc->device_type, &factory);
                        auto parsed_packets = parser.parse_report(buf, transferred);

                        for (const auto& pkt : parsed_packets) {
                            bool local_sent = false;
                            bool encrypt = device_state->state.has_flag(DeviceFlags::ENCRYPTION_ENABLED);

                            if (message_wrapper_) {
                                // Send pre-serialized packet directly to wrapper to avoid re-parsing
                                local_sent = message_wrapper_->send_routed_serialized(client_fd, device_state->source_id, pkt, encrypt);
                            } else {
                                // Prefix sourceId integer and write raw packet
                                NoteBytes::Value sid_val(device_state->source_id);
                                std::vector<uint8_t> packet(sid_val.serialized_size() + pkt.size());
                                size_t off = 0;
                                sid_val.write_to(packet.data(), off);
                                memcpy(packet.data() + off, pkt.data(), pkt.size());
                                local_sent = InputPacket::write_packet(client_fd, packet);
                            }

                            if (local_sent) {
                                device_state->event_queued();
                            } else {
                                syslog(LOG_ERR, "Failed to send parsed HID event for source %d", device_state->source_id);
                                device_state->state.remove_flag(DeviceFlags::STREAMING);
                                sent = false;
                                break;
                            }
                        }

                        // If we dropped out due to send failure, break outer loop
                        if (!device_state->state.has_flag(DeviceFlags::STREAMING)) break;
                        sent = true;
                    } else {
                        NoteBytes::Object event_obj;
                        event_obj.add(NoteMessaging::Keys::SOURCE_ID, device_state->source_id);
                        event_obj.add(NoteMessaging::Keys::TYPE, EventBytes::EVENT_RAW_HID);

                        uint8_t seq[6];
                        AtomicSequence::get_next(seq);
                        event_obj.add(NoteMessaging::Keys::SEQUENCE,
                                      NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));

                        NoteBytes::Array payload;
                        payload.add(NoteBytes::Value(buf, transferred, NoteBytes::Type::RAW_BYTES));
                        event_obj.add(NoteMessaging::Keys::PAYLOAD, payload.as_value());

                        bool encrypt = device_state->state.has_flag(DeviceFlags::ENCRYPTION_ENABLED);

                        
                        if (message_wrapper_) {
                            auto event_packet = event_obj.serialize_with_header();
                            sent = message_wrapper_->send_routed_serialized(client_fd, device_state->source_id,
                                                                            event_packet, encrypt);
                        } else {
                            NoteBytes::Writer writer(client_fd, false);
                            (void) writer.write(NoteBytes::Value(device_state->source_id));
                            (void) writer.write(event_obj);
                            try {
                                (void) writer.flush();
                                sent = true;
                            } catch (const std::exception& e) {
                                sent = false;
                            }
                        }

                        if (sent) {
                            device_state->event_queued();
                        } else {
                            syslog(LOG_ERR, "Failed to send routed HID event for source %d", device_state->source_id);
                            device_state->state.remove_flag(DeviceFlags::STREAMING);
                            break;
                        }
                    }
                } else if (rc == LIBUSB_ERROR_TIMEOUT) {
                    // Nothing this iteration; continue
                } else {
                    // Transfer error
                    syslog(LOG_ERR, "USB transfer error for %s: %d", device_state->device_id.c_str(), rc);
                    device_state->state.add_flag(DeviceFlags::TRANSFER_ERROR);
                    device_state->state.remove_flag(DeviceFlags::STREAMING);
                    break;
                }
            } else {
                // Fallback synthetic event when no USB access
                NoteBytes::Object event_obj;
                event_obj.add(NoteMessaging::Keys::SOURCE_ID, device_state->source_id);
                event_obj.add(NoteMessaging::Keys::TYPE, EventBytes::EVENT_KEY_DOWN);

                uint8_t seq[6];
                AtomicSequence::get_next(seq);
                event_obj.add(NoteMessaging::Keys::SEQUENCE,
                              NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));

                NoteBytes::Array payload;
                payload.add(NoteBytes::Value((int32_t)65)); // 'A'
                payload.add(NoteBytes::Value((int32_t)0));
                event_obj.add(NoteMessaging::Keys::PAYLOAD, payload.as_value());

                bool encrypt = device_state->state.has_flag(DeviceFlags::ENCRYPTION_ENABLED);

                if (message_wrapper_) {
                    sent = message_wrapper_->send_routed_message(client_fd, device_state->source_id,
                                                                event_obj, encrypt);
                } else {
                    auto event_packet = event_obj.serialize_with_header();
                    NoteBytes::Value sid_val(device_state->source_id);
                    std::vector<uint8_t> packet(sid_val.serialized_size() + event_packet.size());
                    size_t off = 0;
                    sid_val.write_to(packet.data(), off);
                    memcpy(packet.data() + off, event_packet.data(), event_packet.size());
                    sent = InputPacket::write_packet(client_fd, packet);
                }

                if (sent) {
                    device_state->event_queued();
                } else {
                    syslog(LOG_ERR, "Failed to send synthetic routed event for source %d", device_state->source_id);
                    device_state->state.remove_flag(DeviceFlags::STREAMING);
                    break;
                }

                // Sleep a bit to avoid a tight loop
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }

        syslog(LOG_INFO, "Stopping event stream for %s", device_state->device_id.c_str());
    }
    
    // Message sending helpers (use encryption if active)
    void send_message(const NoteBytes::Object& msg) {
        if (message_wrapper_) {
            // For control (non-routed) messages use send_control_message
            message_wrapper_->send_control_message(client_fd, msg);
        } else {
            NoteBytes::Writer writer(client_fd, false);
            (void) writer.write(msg);
            (void) writer.flush();
        }
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
    
    void release_device() {
        if (device_handle) {
            libusb_release_interface(device_handle, 0);
            libusb_attach_kernel_driver(device_handle, 0);
            libusb_close(device_handle);
            device_handle = nullptr;
        }
    }
};

#endif // DEVICE_SESSION_H