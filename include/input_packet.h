// include/input_packet.h
// Input packet factory matching Java InputPacket.java
// Creates structured event packets with atomic sequencing

#ifndef INPUT_PACKET_H
#define INPUT_PACKET_H

#include "note_messaging.h"
#include "notebytes.h"
#include "event_bytes.h"
#include "atomic_sequence.h"
#include "utils.h"
#include <cstdint>
#include <vector>
#include <cstring>

namespace InputPacket {

/**
 * Factory for creating input event packets
 * Matches Java InputPacket.Factory
 */
class Factory {
private:
    int32_t source_id_;
    
public:
    explicit Factory(int32_t source_id) : source_id_(source_id) {}
    
    int32_t get_source_id() const { return source_id_; }
    void set_source_id(int32_t source_id) { source_id_ = source_id; }
    /**
     * Core packet creation method
     * Creates packet with: [5-byte header][NoteBytesObject body]
     * 
     * Body structure:
     * - src: source ID (int)
     * - typ: event type (byte)
     * - seq: atomic sequence (6 bytes raw)
     * - stF: state flags (int) [optional, if non-zero]
     * - pld: payload array [optional, if provided]
     */
    std::vector<uint8_t> create(uint8_t event_type, 
                                int state_flags = 0,
                                const std::vector<NoteBytes::Value>* payload = nullptr) {
        NoteBytes::Object packet;
        
        // Always include these fields
        packet.add(NoteMessaging::Keys::SOURCE_ID, source_id_);
        packet.add(NoteMessaging::Keys::TYPE, event_type);
        
        // Add atomic sequence (6 bytes)
        uint8_t seq_bytes[6];
        AtomicSequence::get_next(seq_bytes);
        packet.add(NoteMessaging::Keys::SEQUENCE, 
                  NoteBytes::Value(seq_bytes, 6, NoteBytes::Type::RAW_BYTES));
        
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
    
    // Keyboard event creators
    std::vector<uint8_t> create_key_event(uint8_t type, int key, int scancode, int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(key),
            NoteBytes::Value(scancode)
        };
        return create(type, state_flags, &payload);
    }
    
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
    
    // Mouse event creators
    
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
    
    std::vector<uint8_t> create_mouse_button_down(int button, double x, double y, int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(button),
            NoteBytes::Value(x),
            NoteBytes::Value(y)
        };
        return create(EventBytes::EVENT_MOUSE_BUTTON_DOWN, state_flags, &payload);
    }
    
    std::vector<uint8_t> create_mouse_button_up(int button, double x, double y, int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(button),
            NoteBytes::Value(x),
            NoteBytes::Value(y)
        };
        return create(EventBytes::EVENT_MOUSE_BUTTON_UP, state_flags, &payload);
    }
    
    std::vector<uint8_t> create_scroll(double x_offset, double y_offset, 
                                       double mouse_x, double mouse_y, int state_flags) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(x_offset),
            NoteBytes::Value(y_offset),
            NoteBytes::Value(mouse_x),
            NoteBytes::Value(mouse_y)
        };
        return create(EventBytes::EVENT_SCROLL, state_flags, &payload);
    }
    
    // Focus events
    
    std::vector<uint8_t> create_focus_gained() {
        return create(EventBytes::EVENT_FOCUS_GAINED);
    }
    
    std::vector<uint8_t> create_focus_lost() {
        return create(EventBytes::EVENT_FOCUS_LOST);
    }
    
    // Window events
    
    std::vector<uint8_t> create_framebuffer_resize(int width, int height) {
        std::vector<NoteBytes::Value> payload = {
            NoteBytes::Value(width),
            NoteBytes::Value(height)
        };
        return create(EventBytes::EVENT_FRAMEBUFFER_RESIZE, 0, &payload);
    }
    
    // Protocol control messages
    
    std::vector<uint8_t> create_disconnected() {
        return create(EventBytes::TYPE_DISCONNECTED);
    }
    
    std::vector<uint8_t> create_error(int error_code, const std::string& message) {
        NoteBytes::Object packet;
        packet.add(NoteMessaging::Keys::SOURCE_ID, source_id_);
        packet.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ERROR);
        
        uint8_t seq_bytes[6];
        AtomicSequence::get_next(seq_bytes);
        packet.add(NoteMessaging::Keys::SEQUENCE, 
                  NoteBytes::Value(seq_bytes, 6, NoteBytes::Type::RAW_BYTES));
        
        packet.add(NoteMessaging::Keys::ERROR_CODE, error_code);
        packet.add(NoteMessaging::Keys::MSG, message);
        
        return packet.serialize_with_header();
    }
    
    std::vector<uint8_t> create_accept(const std::string& status = "ok") {
        NoteBytes::Object packet;
        packet.add(NoteMessaging::Keys::SOURCE_ID, source_id_);
        packet.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ACCEPT);
        
        uint8_t seq_bytes[6];
        AtomicSequence::get_next(seq_bytes);
        packet.add(NoteMessaging::Keys::SEQUENCE, 
                  NoteBytes::Value(seq_bytes, 6, NoteBytes::Type::RAW_BYTES));
        
        packet.add(NoteMessaging::Keys::STATUS, status);
        
        return packet.serialize_with_header();
    }
    
    // Encrypted packet wrapper
    std::vector<uint8_t> create_encrypted(const uint8_t* ciphertext, size_t len) {
        NoteBytes::Object packet;
        packet.add(NoteMessaging::Keys::SOURCE_ID, source_id_);
        packet.add(NoteMessaging::Keys::TYPE, EventBytes::EVENT_KEY_DOWN); // Type embedded in encrypted data
        
        uint8_t seq_bytes[6];
        AtomicSequence::get_next(seq_bytes);
        packet.add(NoteMessaging::Keys::SEQUENCE, 
                  NoteBytes::Value(seq_bytes, 6, NoteBytes::Type::RAW_BYTES));
        
        packet.add(NoteMessaging::Keys::ENCRYPTION, true);
        packet.add(NoteMessaging::Keys::CIPHER, 
                  NoteBytes::Value(ciphertext, len, NoteBytes::Type::RAW_BYTES));
        
        return packet.serialize_with_header();
    }
};

/**
 * Helper function to read a packet from socket
 * Reads 5-byte header, then body
 */
inline bool read_packet(int fd, std::vector<uint8_t>& buffer) {
    // Read 5-byte header
    uint8_t header[5];
    ssize_t n = read(fd, header, 5);
    if (n != 5) {
        return false;
    }
    
    uint8_t type = header[0];
    uint32_t len = (header[1] << 24) | (header[2] << 16) | 
                   (header[3] << 8) | header[4];
    
    if (type != NoteBytes::Type::OBJECT || len == 0 || len > 1024 * 1024) {
        return false;
    }
    
    // Read body
    buffer.resize(5 + len);
    memcpy(buffer.data(), header, 5);
    
    size_t total_read = 0;
    while (total_read < len) {
        n = read(fd, buffer.data() + 5 + total_read, len - total_read);
        if (n <= 0) {
            return false;
        }
        total_read += n;
    }
    
    return true;
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