// include/input_packet.h
// Updated to use NoteBytes::Value for event types
// No more string comparisons at runtime!

#ifndef INPUT_PACKET_H
#define INPUT_PACKET_H

#include "note_messaging.h"
#include "notebytes.h"
#include "notebytes_reader.h"
#include "event_bytes.h"
#include "utils.h"
#include <cstdint>
#include <string>
#include <vector>
#include <cstring>

namespace InputPacket {

/**
 * Receive and route message
 */
struct RoutedMessage {
    bool is_routed;
    NoteBytes::Value device_id;
    NoteBytes::Value message;

    RoutedMessage() : is_routed(false), device_id(0) {}

    inline bool isEncrypted() const { 
        return message.type() == NoteBytes::Type::ENCRYPTED; 
    }
    
    inline bool isObject() const { 
        return message.type() == NoteBytes::Type::OBJECT; 
    }
    
    inline bool isValid() const { 
        return (isEncrypted() && device_id.type() == NoteBytes::Type::STRING) 
            || isObject(); 
    }
};

/**
 * Factory for creating input event packets
 * Uses pre-serialized NoteBytes::Value for event types
 */
class Factory {
private:
    std::string device_id_;
    
public:
    explicit Factory(const std::string& device_id) : device_id_(device_id) {}
    
    std::string get_device_id() const { return device_id_; }
    void set_device_id(const std::string& device_id) { device_id_ = device_id; }
    
    /**
     * Core packet creation method
     * Uses pre-serialized NoteBytes::Value for event types
     * 
     * Body structure:
     * - device_id: device ID (string)
     * - event: event type (NoteBytes::Value - pre-serialized)
     * - seq_id: atomic sequence (8 bytes LONG)
     * - state_flags: state flags (int) [optional, if non-zero]
     * - payload: payload array [optional, if provided]
     */
    std::vector<uint8_t> create(const NoteBytes::Value& event_type, 
                                int state_flags = 0,
                                const std::vector<NoteBytes::Value>* payload = nullptr) {
        NoteBytes::Object packet;
        
        // Add required fields
        packet.add(NoteMessaging::Keys::DEVICE_ID, device_id_);
        packet.add(NoteMessaging::Keys::EVENT, event_type);
        
        // Add state flags if non-zero
        if (state_flags != 0) {
            packet.add(NoteMessaging::Keys::STATE_FLAGS, state_flags);
        }
        
        // Add payload array if provided
        if (payload && !payload->empty()) {
            NoteBytes::Array arr;
            for (const auto& val : *payload) {
                arr.add(val);
            }
            packet.add(NoteMessaging::Keys::PAYLOAD, arr.as_value());
        }
        
        return packet.serialize_with_header();
    }
    
    // ===== Keyboard Event Creators =====
    
    std::vector<uint8_t> create_key_down(int key, int scancode, int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(key),
            NoteBytes::Value(scancode)
        };
        return create(EventBytes::EVENT_KEY_DOWN, state_flags, &payload);
    }
    
    std::vector<uint8_t> create_key_up(int key, int scancode, int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(key),
            NoteBytes::Value(scancode)
        };
        return create(EventBytes::EVENT_KEY_UP, state_flags, &payload);
    }
    
    std::vector<uint8_t> create_key_repeat(int key, int scancode, int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(key),
            NoteBytes::Value(scancode)
        };
        return create(EventBytes::EVENT_KEY_REPEAT, state_flags, &payload);
    }
    
    std::vector<uint8_t> create_key_char(int codepoint, int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(codepoint)
        };
        return create(EventBytes::EVENT_KEY_CHAR, state_flags, &payload);
    }
    
    // ===== Mouse Event Creators =====
    
    std::vector<uint8_t> create_mouse_move(double x, double y, int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(x),
            NoteBytes::Value(y)
        };
        return create(EventBytes::EVENT_MOUSE_MOVE_ABSOLUTE, state_flags, &payload);
    }
    
    std::vector<uint8_t> create_mouse_move_relative(double dx, double dy, int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(dx),
            NoteBytes::Value(dy)
        };
        return create(EventBytes::EVENT_MOUSE_MOVE_RELATIVE, state_flags, &payload);
    }
    
    std::vector<uint8_t> create_mouse_button_down(int button, double x, double y, 
                                                  int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(button),
            NoteBytes::Value(x),
            NoteBytes::Value(y)
        };
        return create(EventBytes::EVENT_MOUSE_BUTTON_DOWN, state_flags, &payload);
    }
    
    std::vector<uint8_t> create_mouse_button_up(int button, double x, double y, 
                                                int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(button),
            NoteBytes::Value(x),
            NoteBytes::Value(y)
        };
        return create(EventBytes::EVENT_MOUSE_BUTTON_UP, state_flags, &payload);
    }
    
    std::vector<uint8_t> create_scroll(double x_offset, double y_offset, 
                                       double mouse_x, double mouse_y, 
                                       int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(x_offset),
            NoteBytes::Value(y_offset),
            NoteBytes::Value(mouse_x),
            NoteBytes::Value(mouse_y)
        };
        return create(EventBytes::EVENT_SCROLL, state_flags, &payload);
    }
    
    // ===== Focus Events =====
    
    std::vector<uint8_t> create_focus_gained() {
        return create(EventBytes::EVENT_FOCUS_GAINED);
    }
    
    std::vector<uint8_t> create_focus_lost() {
        return create(EventBytes::EVENT_FOCUS_LOST);
    }
    
    // ===== Window Events =====
    
    std::vector<uint8_t> create_framebuffer_resize(int width, int height) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(width),
            NoteBytes::Value(height)
        };
        return create(EventBytes::EVENT_FRAMEBUFFER_RESIZE, 0, &payload);
    }
    
    // ===== Protocol Control Messages =====
    
    std::vector<uint8_t> create_disconnected() {
        return create(EventBytes::TYPE_DISCONNECTED);
    }
    
    std::vector<uint8_t> create_error(int error_code, const std::string& message) {
        NoteBytes::Object packet;
        packet.add(NoteMessaging::Keys::DEVICE_ID, device_id_);
        packet.add(NoteMessaging::Keys::EVENT, EventBytes::TYPE_ERROR);
        packet.add(NoteMessaging::Keys::ERROR_CODE, error_code);
        packet.add(NoteMessaging::Keys::MSG, message);
        
        return packet.serialize_with_header();
    }
    
    std::vector<uint8_t> create_accept(const std::string& status = "ok") {
        NoteBytes::Object packet;
        packet.add(NoteMessaging::Keys::DEVICE_ID, device_id_);
        packet.add(NoteMessaging::Keys::EVENT, EventBytes::TYPE_ACCEPT);
        packet.add(NoteMessaging::Keys::STATUS, status);
        
        return packet.serialize_with_header();
    }
    
    // ===== Encrypted Packet Wrapper =====
    
    std::vector<uint8_t> create_encrypted(const uint8_t* ciphertext, size_t len) {
        NoteBytes::Object packet;
        packet.add(NoteMessaging::Keys::DEVICE_ID, device_id_);
        packet.add(NoteMessaging::Keys::EVENT, EventBytes::EVENT_KEY_DOWN);
        packet.add(NoteMessaging::Keys::ENCRYPTION, true);
        packet.add(NoteMessaging::Keys::CIPHER, 
                  NoteBytes::Value(ciphertext, len, NoteBytes::Type::RAW_BYTES));
        
        return packet.serialize_with_header();
    }
};

/**
 * Receive message from socket and parse routing
 */
inline RoutedMessage receive_message(int client_fd) {
    InputPacket::RoutedMessage result;
    
    NoteBytes::Reader reader = NoteBytes::Reader(client_fd, false);
    NoteBytes::Value firstValue = reader.read_value();
    
    if (firstValue.type() == NoteBytes::Type::STRING) {
        // Routed message: [STRING:deviceId][OBJECT/ENCRYPTED:payload]
        result.is_routed = true;
        result.device_id = firstValue;
        result.message = reader.read_value();
        
        if (!result.isValid()) {
            throw std::runtime_error("Invalid message type after deviceId: " + 
                                   std::to_string(static_cast<int>(result.message.type())));
        }
        
    } else if (firstValue.type() == NoteBytes::Type::OBJECT) {
        // Non-routed control message: [OBJECT:message]
        result.is_routed = false;
        result.device_id = NoteBytes::Value(0);
        result.message = firstValue;
        
    } else {
        throw std::runtime_error("Invalid first value type: " + 
                               std::to_string(static_cast<int>(firstValue.type())));
    }
    
    return result;
}

/**
 * Helper function to write a packet to socket
 */
inline bool write_packet(int fd, const std::vector<uint8_t>& packet) {
    ssize_t written = write(fd, packet.data(), packet.size());
    return written == static_cast<ssize_t>(packet.size());
}

/**
 * Parse an incoming packet
 */
inline NoteBytes::Object parse_packet(const std::vector<uint8_t>& packet) {
    return NoteBytes::Object::deserialize_from_packet(packet.data());
}

} // namespace InputPacket

#endif // INPUT_PACKET_H