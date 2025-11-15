// include/hid_parser.h
// HID report parser for converting raw USB reports to parsed events
// Supports keyboard boot protocol (6KRO standard format)

#ifndef HID_PARSER_H
#define HID_PARSER_H

#include <cstdint>
#include <vector>
#include <set>
#include <map>
#include <memory>
#include "event_bytes.h"
#include "input_packet.h"
#include "notebytes.h"
#include "atomic_sequence.h"
#include <syslog.h>

namespace HIDParser {

/**
 * USB HID Usage IDs for keyboard keys
 * From USB HID Usage Tables specification
 */
namespace KeyboardUsage {
    // Modifier keys (used in modifier byte)
    constexpr uint8_t MOD_LEFT_CTRL   = 0x01;
    constexpr uint8_t MOD_LEFT_SHIFT  = 0x02;
    constexpr uint8_t MOD_LEFT_ALT    = 0x04;
    constexpr uint8_t MOD_LEFT_GUI    = 0x08;  // Windows/Super key
    constexpr uint8_t MOD_RIGHT_CTRL  = 0x10;
    constexpr uint8_t MOD_RIGHT_SHIFT = 0x20;
    constexpr uint8_t MOD_RIGHT_ALT   = 0x40;
    constexpr uint8_t MOD_RIGHT_GUI   = 0x80;
    
    // Common key codes (HID usage IDs)
    constexpr uint8_t KEY_A = 0x04;
    constexpr uint8_t KEY_Z = 0x1D;
    constexpr uint8_t KEY_1 = 0x1E;
    constexpr uint8_t KEY_9 = 0x26;
    constexpr uint8_t KEY_0 = 0x27;
    constexpr uint8_t KEY_ENTER = 0x28;
    constexpr uint8_t KEY_ESCAPE = 0x29;
    constexpr uint8_t KEY_BACKSPACE = 0x2A;
    constexpr uint8_t KEY_TAB = 0x2B;
    constexpr uint8_t KEY_SPACE = 0x2C;
    constexpr uint8_t KEY_MINUS = 0x2D;
    constexpr uint8_t KEY_EQUAL = 0x2E;
    constexpr uint8_t KEY_LEFT_BRACKET = 0x2F;
    constexpr uint8_t KEY_RIGHT_BRACKET = 0x30;
    constexpr uint8_t KEY_BACKSLASH = 0x31;
    constexpr uint8_t KEY_SEMICOLON = 0x33;
    constexpr uint8_t KEY_APOSTROPHE = 0x34;
    constexpr uint8_t KEY_GRAVE = 0x35;
    constexpr uint8_t KEY_COMMA = 0x36;
    constexpr uint8_t KEY_PERIOD = 0x37;
    constexpr uint8_t KEY_SLASH = 0x38;
    constexpr uint8_t KEY_CAPS_LOCK = 0x39;
    
    // Function keys
    constexpr uint8_t KEY_F1 = 0x3A;
    constexpr uint8_t KEY_F12 = 0x45;
    
    // Arrow keys
    constexpr uint8_t KEY_RIGHT = 0x4F;
    constexpr uint8_t KEY_LEFT = 0x50;
    constexpr uint8_t KEY_DOWN = 0x51;
    constexpr uint8_t KEY_UP = 0x52;
}

/**
 * Convert HID modifier byte to EventBytes state flags
 */
inline int hid_modifiers_to_state_flags(uint8_t modifiers) {
    int flags = 0;
    
    if (modifiers & (KeyboardUsage::MOD_LEFT_SHIFT | KeyboardUsage::MOD_RIGHT_SHIFT)) {
        flags |= EventBytes::StateFlags::MOD_SHIFT;
    }
    if (modifiers & (KeyboardUsage::MOD_LEFT_CTRL | KeyboardUsage::MOD_RIGHT_CTRL)) {
        flags |= EventBytes::StateFlags::MOD_CONTROL;
    }
    if (modifiers & (KeyboardUsage::MOD_LEFT_ALT | KeyboardUsage::MOD_RIGHT_ALT)) {
        flags |= EventBytes::StateFlags::MOD_ALT;
    }
    if (modifiers & (KeyboardUsage::MOD_LEFT_GUI | KeyboardUsage::MOD_RIGHT_GUI)) {
        flags |= EventBytes::StateFlags::MOD_SUPER;
    }
    
    return flags;
}

/**
 * Convert HID usage ID to character (US layout, basic mapping)
 * Returns 0 if no printable character
 */
inline int hid_usage_to_char(uint8_t usage, bool shift) {
    // Letters A-Z
    if (usage >= KeyboardUsage::KEY_A && usage <= KeyboardUsage::KEY_Z) {
        int offset = usage - KeyboardUsage::KEY_A;
        return shift ? ('A' + offset) : ('a' + offset);
    }
    
    // Numbers 1-9, 0
    if (usage >= KeyboardUsage::KEY_1 && usage <= KeyboardUsage::KEY_9) {
        if (shift) {
            // Shifted number row: !@#$%^&*()
            const char shifted[] = "!@#$%^&*(";
            return shifted[usage - KeyboardUsage::KEY_1];
        }
        return '1' + (usage - KeyboardUsage::KEY_1);
    }
    if (usage == KeyboardUsage::KEY_0) {
        return shift ? ')' : '0';
    }
    
    // Special characters
    switch (usage) {
        case KeyboardUsage::KEY_SPACE: return ' ';
        case KeyboardUsage::KEY_ENTER: return '\n';
        case KeyboardUsage::KEY_TAB: return '\t';
        case KeyboardUsage::KEY_MINUS: return shift ? '_' : '-';
        case KeyboardUsage::KEY_EQUAL: return shift ? '+' : '=';
        case KeyboardUsage::KEY_LEFT_BRACKET: return shift ? '{' : '[';
        case KeyboardUsage::KEY_RIGHT_BRACKET: return shift ? '}' : ']';
        case KeyboardUsage::KEY_BACKSLASH: return shift ? '|' : '\\';
        case KeyboardUsage::KEY_SEMICOLON: return shift ? ':' : ';';
        case KeyboardUsage::KEY_APOSTROPHE: return shift ? '"' : '\'';
        case KeyboardUsage::KEY_GRAVE: return shift ? '~' : '`';
        case KeyboardUsage::KEY_COMMA: return shift ? '<' : ',';
        case KeyboardUsage::KEY_PERIOD: return shift ? '>' : '.';
        case KeyboardUsage::KEY_SLASH: return shift ? '?' : '/';
        default: return 0;
    }
}

/**
 * Convert HID usage ID to a virtual key code
 * This is a simple 1:1 mapping for now (HID usage = virtual key)
 */
inline int hid_usage_to_virtual_key(uint8_t usage) {
    return usage;
}

/**
 * Get scancode for HID usage (simplified - use usage as scancode)
 */
inline int hid_usage_to_scancode(uint8_t usage) {
    return usage;
}

/**
 * Keyboard HID Report Parser
 * Handles standard USB keyboard boot protocol (8-byte reports)
 * 
 * Boot Protocol Format:
 * Byte 0: Modifier keys bitmap
 * Byte 1: Reserved (usually 0)
 * Bytes 2-7: Up to 6 simultaneous key codes (6KRO)
 */
class KeyboardParser {
private:
    std::set<uint8_t> pressed_keys_;     // Currently pressed keys
    uint8_t last_modifiers_ = 0;          // Last modifier state
    bool caps_lock_state_ = false;        // Caps lock LED state
    
    InputPacket::Factory* factory_;
    
public:
    explicit KeyboardParser(InputPacket::Factory* factory) 
        : factory_(factory) {}
    
    /**
     * Parse keyboard boot protocol report
     * Returns vector of event packets to send
     */
    std::vector<std::vector<uint8_t>> parse_report(const uint8_t* data, size_t len) {
        std::vector<std::vector<uint8_t>> events;
        
        // Validate report length (must be at least 8 bytes for boot protocol)
        if (len < 8) {
            syslog(LOG_WARNING, "Invalid keyboard report length: %zu", len);
            return events;
        }
        
        uint8_t modifiers = data[0];
        // data[1] is reserved
        
        // Extract pressed keys from report (bytes 2-7)
        std::set<uint8_t> current_keys;
        for (size_t i = 2; i < 8 && i < len; i++) {
            uint8_t usage = data[i];
            if (usage != 0x00) {  // 0x00 = no key
                current_keys.insert(usage);
            }
        }
        
        // Convert modifiers to state flags
        int state_flags = hid_modifiers_to_state_flags(modifiers);
        
        // Check for caps lock state
        if (caps_lock_state_) {
            state_flags |= EventBytes::StateFlags::MOD_CAPS_LOCK;
        }
        
        // Detect modifier changes (generate modifier key events)
        if (modifiers != last_modifiers_) {
            generate_modifier_events(events, last_modifiers_, modifiers, state_flags);
        }
        
        // Detect released keys
        for (uint8_t old_key : pressed_keys_) {
            if (current_keys.find(old_key) == current_keys.end()) {
                // Key was released
                generate_key_up_event(events, old_key, state_flags);
            }
        }
        
        // Detect newly pressed keys
        for (uint8_t new_key : current_keys) {
            if (pressed_keys_.find(new_key) == pressed_keys_.end()) {
                // Key was pressed
                generate_key_down_event(events, new_key, state_flags);
                
                // Check for caps lock toggle
                if (new_key == KeyboardUsage::KEY_CAPS_LOCK) {
                    caps_lock_state_ = !caps_lock_state_;
                }
            }
        }
        
        // Update state
        pressed_keys_ = current_keys;
        last_modifiers_ = modifiers;
        
        return events;
    }
    
    /**
     * Reset parser state (call when device is released)
     */
    void reset() {
        // Generate key up events for all currently pressed keys
        pressed_keys_.clear();
        last_modifiers_ = 0;
        caps_lock_state_ = false;
    }
    
private:
    /**
     * Generate key down event + optional character event
     */
    void generate_key_down_event(std::vector<std::vector<uint8_t>>& events,
                                 uint8_t usage, int state_flags) {
        int virtual_key = hid_usage_to_virtual_key(usage);
        int scancode = hid_usage_to_scancode(usage);
        
        // Generate KEY_DOWN event
        auto key_down = factory_->create_key_down(virtual_key, scancode, state_flags);
        events.push_back(key_down);
        
        // Generate KEY_CHAR event if key produces a character
        bool shift = (state_flags & EventBytes::StateFlags::MOD_SHIFT) != 0;
        bool caps = caps_lock_state_;
        
        // Apply caps lock to letters only
        if (caps && usage >= KeyboardUsage::KEY_A && usage <= KeyboardUsage::KEY_Z) {
            shift = !shift;  // Invert shift for letters when caps is on
        }
        
        int codepoint = hid_usage_to_char(usage, shift);
        if (codepoint != 0) {
            auto key_char = factory_->create_key_char(codepoint, state_flags);
            events.push_back(key_char);
        }
    }
    
    /**
     * Generate key up event
     */
    void generate_key_up_event(std::vector<std::vector<uint8_t>>& events,
                               uint8_t usage, int state_flags) {
        int virtual_key = hid_usage_to_virtual_key(usage);
        int scancode = hid_usage_to_scancode(usage);
        
        auto key_up = factory_->create_key_up(virtual_key, scancode, state_flags);
        events.push_back(key_up);
    }
    
    /**
     * Generate events for modifier key changes
     */
    void generate_modifier_events(std::vector<std::vector<uint8_t>>& events,
                                  uint8_t old_mods, uint8_t new_mods,
                                  int state_flags) {
        // Check each modifier bit
        const struct {
            uint8_t bit;
            uint8_t usage;
        } modifiers[] = {
            {KeyboardUsage::MOD_LEFT_CTRL, 0xE0},
            {KeyboardUsage::MOD_LEFT_SHIFT, 0xE1},
            {KeyboardUsage::MOD_LEFT_ALT, 0xE2},
            {KeyboardUsage::MOD_LEFT_GUI, 0xE3},
            {KeyboardUsage::MOD_RIGHT_CTRL, 0xE4},
            {KeyboardUsage::MOD_RIGHT_SHIFT, 0xE5},
            {KeyboardUsage::MOD_RIGHT_ALT, 0xE6},
            {KeyboardUsage::MOD_RIGHT_GUI, 0xE7},
        };
        
        for (const auto& mod : modifiers) {
            bool was_pressed = (old_mods & mod.bit) != 0;
            bool is_pressed = (new_mods & mod.bit) != 0;
            
            if (is_pressed && !was_pressed) {
                // Modifier pressed
                generate_key_down_event(events, mod.usage, state_flags);
            } else if (!is_pressed && was_pressed) {
                // Modifier released
                generate_key_up_event(events, mod.usage, state_flags);
            }
        }
    }
};

/**
 * Mouse HID Report Parser (placeholder for future implementation)
 * Standard boot protocol: 4-byte reports
 * Byte 0: Button states
 * Byte 1: X movement (signed)
 * Byte 2: Y movement (signed)
 * Byte 3: Wheel movement (signed)
 */
class MouseParser {
private:
    InputPacket::Factory* factory_;
    uint8_t last_buttons_ = 0;
    
public:
    explicit MouseParser(InputPacket::Factory* factory) 
        : factory_(factory) {}
    
    std::vector<std::vector<uint8_t>> parse_report(const uint8_t* data, size_t len) {
        std::vector<std::vector<uint8_t>> events;
        
        if (len < 4) {
            return events;
        }
        
        uint8_t buttons = data[0];
        int8_t dx = static_cast<int8_t>(data[1]);
        int8_t dy = static_cast<int8_t>(data[2]);
        int8_t wheel = static_cast<int8_t>(data[3]);
        
        // Convert button states to state flags
        int state_flags = 0;
        if (buttons & 0x01) state_flags |= EventBytes::StateFlags::MOUSE_BUTTON_1;
        if (buttons & 0x02) state_flags |= EventBytes::StateFlags::MOUSE_BUTTON_2;
        if (buttons & 0x04) state_flags |= EventBytes::StateFlags::MOUSE_BUTTON_3;
        
        // Generate button events
        for (int i = 0; i < 3; i++) {
            uint8_t bit = 1 << i;
            bool was_pressed = (last_buttons_ & bit) != 0;
            bool is_pressed = (buttons & bit) != 0;
            
            if (is_pressed && !was_pressed) {
                auto btn_down = factory_->create_mouse_button_down(i + 1, 0, 0, state_flags);
                events.push_back(btn_down);
            } else if (!is_pressed && was_pressed) {
                auto btn_up = factory_->create_mouse_button_up(i + 1, 0, 0, state_flags);
                events.push_back(btn_up);
            }
        }
        
        // Generate movement event
        if (dx != 0 || dy != 0) {
            auto move = factory_->create_mouse_move_relative(dx, dy, state_flags);
            events.push_back(move);
        }
        
        // Generate scroll event
        if (wheel != 0) {
            auto scroll = factory_->create_scroll(0, wheel, 0, 0, state_flags);
            events.push_back(scroll);
        }
        
        last_buttons_ = buttons;
        return events;
    }
    
    void reset() {
        last_buttons_ = 0;
    }
};

/**
 * Generic HID parser that routes to specific device type parsers
 */
class HIDParser {
private:
    std::unique_ptr<KeyboardParser> keyboard_parser_;
    std::unique_ptr<MouseParser> mouse_parser_;
    std::string device_type_;
    
public:
    HIDParser(const std::string& device_type, InputPacket::Factory* factory)
        : device_type_(device_type) {
        
        if (device_type == "keyboard") {
            keyboard_parser_ = std::make_unique<KeyboardParser>(factory);
        } else if (device_type == "mouse") {
            mouse_parser_ = std::make_unique<MouseParser>(factory);
        }
    }
    
    /**
     * Parse HID report and return vector of event packets
     */
    std::vector<std::vector<uint8_t>> parse_report(const uint8_t* data, size_t len) {
        if (keyboard_parser_) {
            return keyboard_parser_->parse_report(data, len);
        } else if (mouse_parser_) {
            return mouse_parser_->parse_report(data, len);
        }
        
        // Unknown device type - return empty
        return std::vector<std::vector<uint8_t>>();
    }
    
    /**
     * Reset parser state
     */
    void reset() {
        if (keyboard_parser_) {
            keyboard_parser_->reset();
        } else if (mouse_parser_) {
            mouse_parser_->reset();
        }
    }
};

} // namespace HIDParser

#endif // HID_PARSER_H