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

#include "bitflag_state.h"
#include "capability_registry.h"
#include "note_messaging.h"
#include "notebytes.h"
#include "event_bytes.h"
#include "input_packet.h"

using namespace State;
using namespace Capabilities;

// ===== USB DEVICE DESCRIPTOR (WITH CAPABILITIES) =====

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
    
    std::string device_type;  // "keyboard", "mouse", "unknown"
    uint64_t available_capabilities;  // Detected capabilities
    uint64_t default_mode;            // Default enabled mode
    
    bool available;
    bool kernel_driver_attached;
    
    libusb_device_handle* handle = nullptr;
    
    USBDeviceDescriptor() 
        : vendor_id(0), product_id(0), device_class(0), device_subclass(0),
          device_protocol(0), bus_number(0), device_address(0),
          available_capabilities(0), default_mode(0),
          available(false), kernel_driver_attached(false) {}
    
    /**
     * Detect device type and capabilities from USB descriptors
     */
    void detect_capabilities(libusb_device* device) {
        detect_device_type(device);
        
        // Detect capabilities based on device type
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
        
        syslog(LOG_INFO, "Device '%s' detected as '%s' with capabilities 0x%lx",
               product.c_str(), device_type.c_str(), available_capabilities);
    }
    
    /**
     * Detect device type from USB class codes
     */
    void detect_device_type(libusb_device* device) {
        libusb_config_descriptor* config;
        if (libusb_get_config_descriptor(device, 0, &config) != 0) {
            device_type = "unknown";
            return;
        }
        
        // Check interfaces for HID devices
        for (int i = 0; i < config->bNumInterfaces; i++) {
            const libusb_interface* interface = &config->interface[i];
            for (int j = 0; j < interface->num_altsetting; j++) {
                const libusb_interface_descriptor* altsetting = 
                    &interface->altsetting[j];
                
                // HID class (3)
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
    
    /**
     * Convert to NoteBytesObject for transmission (WITH CAPABILITIES)
     */
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
        
        // Add capabilities as uint64
        obj.add("available_capabilities", (int64_t)available_capabilities);
        obj.add("default_mode", Names::get_capability_name(default_mode));
        
        // Add capability names for debugging
        NoteBytes::Array caps_array;
        for (int i = 0; i < 64; i++) {
            uint64_t bit = 1ULL << i;
            if (available_capabilities & bit) {
                caps_array.add(NoteBytes::Value(Names::get_capability_name(bit)));
            }
        }
        obj.add("capability_names", caps_array.as_value());
        
        return obj;
    }
};

// ===== DEVICE SESSION (WITH CAPABILITY VALIDATION) =====

class DeviceSession {
private:
    libusb_context* usb_ctx;
    libusb_device_handle* device_handle = nullptr;
    int client_fd;
    pid_t client_pid = 0;
    
    // Device states: sourceId -> DeviceState
    std::map<int32_t, std::shared_ptr<DeviceState>> device_states;
    
    // Available devices: device_id -> descriptor
    std::map<std::string, std::shared_ptr<USBDeviceDescriptor>> available_devices;
    
public:
    DeviceSession(libusb_context* ctx, int client, pid_t pid) 
        : usb_ctx(ctx), client_fd(client), client_pid(pid) {
        
        discover_devices();
    }
    
    ~DeviceSession() {
        release_device();
    }
    
    /**
     * Handle protocol negotiation
     */
    void handle_client_protocol_negotiation() {
        std::vector<uint8_t> packet_buffer;
        
        while (InputPacket::read_packet(client_fd, packet_buffer)) {
            try {
                if (packet_buffer[0] != NoteBytes::Type::OBJECT) {
                    continue;
                }
                
                NoteBytes::Object msg = InputPacket::parse_packet(packet_buffer);
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
    
    /**
     * Handle command messages
     */
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
    
    /**
     * Send device list WITH CAPABILITIES
     */
    void send_device_list() {
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_CMD);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        response.add(NoteMessaging::Keys::SEQUENCE,
                    NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        
    response.add(NoteMessaging::Keys::CMD, NoteMessaging::ProtocolMessages::ITEM_LIST);
        
        // Build device array with capabilities
        NoteBytes::Array devices_array;
        for (const auto& [id, device] : available_devices) {
            auto device_obj = device->to_notebytes();
            auto device_bytes = device_obj.serialize();
            devices_array.add(NoteBytes::Value(device_bytes, NoteBytes::Type::OBJECT));
        }
    response.add(NoteMessaging::Keys::ITEMS, devices_array.as_value());
        
        auto packet = response.serialize_with_header();
        InputPacket::write_packet(client_fd, packet);
        
        syslog(LOG_INFO, "Sent device list with capabilities: %zu devices", 
               available_devices.size());
    }
    
    /**
     * Handle device claim WITH CAPABILITY/MODE VALIDATION
     */
    void handle_claim_device(const NoteBytes::Object& msg) {
    std::string device_id = msg.get_string(NoteMessaging::Keys::ITEM_ID, "");
        int32_t source_id = msg.get_int("source_id", 0);
        std::string requested_mode = msg.get_string("mode", "parsed");
        
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
        
        // Validate mode compatibility
        if (!Validation::validate_mode_compatibility(device_desc->device_type, requested_mode)) {
            send_error(NoteMessaging::ErrorCodes::MODE_INCOMPATIBLE, "Mode not compatible with item type");
            return;
        }
        
        // Check if requested mode is available
        uint64_t requested_mode_bit = Names::get_capability_bit(requested_mode);
        if (!(device_desc->available_capabilities & requested_mode_bit)) {
            send_error(NoteMessaging::ErrorCodes::MODE_NOT_SUPPORTED, "Item does not support requested mode");
            return;
        }
        
        // Create device state WITH capabilities
        auto device_state = std::make_shared<DeviceState>(
            device_id,
            source_id,
            client_pid,
            device_desc->device_type,
            device_desc->available_capabilities
        );
        
        // Store hardware info
        device_state->set_hardware_info("vendor_id", std::to_string(device_desc->vendor_id));
        device_state->set_hardware_info("product_id", std::to_string(device_desc->product_id));
        device_state->set_hardware_info("manufacturer", device_desc->manufacturer);
        device_state->set_hardware_info("product", device_desc->product);
        
        // Enable requested mode
        if (!device_state->enable_mode(requested_mode)) {
            send_error(NoteMessaging::ErrorCodes::FEATURE_NOT_SUPPORTED, "Failed to enable requested mode");
            return;
        }
        
        // Claim USB device
        if (claim_usb_device(device_desc)) {
            device_state->state.add_flag(DeviceFlags::CLAIMED);
            device_state->state.add_flag(DeviceFlags::STREAMING);
            
            device_states[source_id] = device_state;
            
            // Start streaming thread
            start_device_streaming(device_desc, device_state);
            
            send_accept(NoteMessaging::ProtocolMessages::ITEM_CLAIMED);
            
            syslog(LOG_INFO, "Device claimed: %s (type=%s, mode=%s, sourceId=%d)",
                   device_id.c_str(), 
                   device_desc->device_type.c_str(),
                   device_state->get_current_mode().c_str(),
                   source_id);
        } else {
            send_error(NoteMessaging::ErrorCodes::CLAIM_FAILED, "Failed to claim USB device");
        }
    }
    
    /**
     * Handle device release
     */
    void handle_release_device(const NoteBytes::Object& msg) {
        int32_t source_id = msg.get_int("source_id", 0);
        
        auto it = device_states.find(source_id);
        if (it != device_states.end()) {
            it->second->release();
            device_states.erase(it);
            send_accept(NoteMessaging::ProtocolMessages::ITEM_RELEASED);
        }
    }
    
    /**
     * Handle resume (backpressure acknowledgment)
     */
    void handle_resume(const NoteBytes::Object& msg) {
        int processed_count = msg.get_int("processed_count", 0);
        syslog(LOG_INFO, "Client acknowledged %d messages", processed_count);
        // Backpressure manager would track this
    }
    
private:
    /**
     * Discover USB devices and detect their capabilities
     */
    void discover_devices() {
        libusb_device** devices;
        ssize_t count = libusb_get_device_list(usb_ctx, &devices);
        
        if (count < 0) {
            syslog(LOG_ERR, "Failed to get device list");
            return;
        }
        
        for (ssize_t i = 0; i < count; i++) {
            auto device_desc = create_device_descriptor(devices[i]);
            if (device_desc && device_desc->available) {
                available_devices[device_desc->device_id] = device_desc;
            }
        }
        
        libusb_free_device_list(devices, 1);
        
        syslog(LOG_INFO, "Discovered %zu devices", available_devices.size());
    }
    
    /**
     * Create device descriptor from libusb device
     */
    std::shared_ptr<USBDeviceDescriptor> create_device_descriptor(libusb_device* device) {
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
        
        // Generate device ID
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
        
        // Detect device type and capabilities
        device_desc->detect_capabilities(device);
        
        device_desc->available = true;
        device_desc->kernel_driver_attached = 
            (libusb_kernel_driver_active(device_handle, 0) == 1);
        
        return device_desc;
    }
    
    /**
     * Claim USB device
     */
    bool claim_usb_device(std::shared_ptr<USBDeviceDescriptor> /* device_desc */) {
        // Implementation similar to existing code
        // TODO: Actual USB claiming logic
        return true;
    }
    
    /**
     * Start device streaming thread
     */
    void start_device_streaming(std::shared_ptr<USBDeviceDescriptor> device_desc,
                               std::shared_ptr<DeviceState> device_state) {
        std::thread([this, device_desc, device_state]() {
            stream_device_events(device_desc, device_state);
        }).detach();
    }
    
    /**
     * Stream device events (uses current mode to determine processing)
     */
    void stream_device_events(std::shared_ptr<USBDeviceDescriptor> /* device_desc */,
                             std::shared_ptr<DeviceState> device_state) {
        
        uint64_t current_mode = device_state->get_current_mode_bit();
        
        syslog(LOG_INFO, "Starting event stream for %s in mode: %s",
               device_state->device_id.c_str(),
               device_state->get_current_mode().c_str());
        
        // Choose processing based on mode
        if (current_mode == Bits::RAW_MODE) {
            stream_raw_events(device_state);
        } else if (current_mode == Bits::PARSED_MODE) {
            stream_parsed_events(device_state);
        } else if (current_mode == Bits::FILTERED_MODE) {
            stream_filtered_events(device_state);
        }
    }
    
    void stream_raw_events(std::shared_ptr<DeviceState> /* device_state */) {
        syslog(LOG_INFO, "Streaming RAW HID reports");
        // TODO: Send raw HID reports
    }
    
    void stream_parsed_events(std::shared_ptr<DeviceState> /* device_state */) {
        syslog(LOG_INFO, "Streaming PARSED keyboard events");
        // TODO: Parse HID reports into keyboard events
    }
    
    void stream_filtered_events(std::shared_ptr<DeviceState> /* device_state */) {
        syslog(LOG_INFO, "Streaming FILTERED events");
        // TODO: Apply filters then send
    }
    
    void send_accept(const std::string& status = "ok") {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ACCEPT);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        msg.add(NoteMessaging::Keys::SEQUENCE, NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        msg.add(NoteMessaging::Keys::STATUS, status);
        
        auto packet = msg.serialize_with_header();
        InputPacket::write_packet(client_fd, packet);
    }
    
    void send_error(int code, const std::string& message) {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ERROR);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        msg.add(NoteMessaging::Keys::SEQUENCE, NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        msg.add(NoteMessaging::Keys::ERROR_CODE, code);
        msg.add(NoteMessaging::Keys::MSG, message);
        
        auto packet = msg.serialize_with_header();
        InputPacket::write_packet(client_fd, packet);
    }
    
    void send_pong() {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_PONG);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        msg.add(NoteMessaging::Keys::SEQUENCE, NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        
        auto packet = msg.serialize_with_header();
        InputPacket::write_packet(client_fd, packet);
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
