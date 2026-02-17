// include/hid_parser.h
// HID report parser for converting raw USB reports to parsed events
// Supports keyboard boot protocol (6KRO standard format)
// PARSED mode generates NanoVG/GLFW-compatible event sequences

#ifndef HID_PARSER_H
#define HID_PARSER_H

#include <cstdint>
#include <vector>
#include <set>
#include <map>
#include <memory>
#include <chrono>
#include <syslog.h>
#include "event_bytes.h"
#include "input_packet.h"
#include "key_code.h"


namespace HIDParser {


/**
 * Keyboard HID Report Parser - PARSED MODE
 * Generates NanoVG/GLFW-compatible event sequences:
 * 
 * Normal key press sequence:
 *   1. EVENT_KEY_DOWN (physical key, scancode, modifiers)
 *   2. EVENT_KEY_CHAR_MODS (Unicode codepoint, modifiers) [if printable]
 * 
 * Key repeat (while held):
 *   1. EVENT_KEY_REPEAT (physical key, scancode, modifiers)
 *   2. EVENT_KEY_CHAR_MODS (Unicode codepoint, modifiers) [if printable]
 * 
 * Key release:
 *   1. EVENT_KEY_UP (physical key, scancode, modifiers)
 * 
 * Boot Protocol Format:
 * Byte 0: Modifier keys bitmap
 * Byte 1: Reserved (usually 0)
 * Bytes 2-7: Up to 6 simultaneous key codes (6KRO)
 */
class KeyboardParser {
private:
    std::set<uint8_t> pressed_keys_;           // Currently pressed keys
    uint8_t last_modifiers_ = 0;                // Last modifier state
    bool caps_lock_state_ = false;              // Caps lock LED state
    
    // Key repeat tracking
    struct KeyRepeatState {
        uint8_t usage = 0;
        std::chrono::steady_clock::time_point press_time;
        std::chrono::steady_clock::time_point last_repeat;
        bool repeating = false;
    };
    std::map<uint8_t, KeyRepeatState> repeat_states_;
    
    // Repeat timing (matching typical OS behavior)
    static constexpr int REPEAT_DELAY_MS = 500;   // Initial delay before repeat
    static constexpr int REPEAT_RATE_MS = 33;      // ~30 Hz repeat rate
    
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
        
        // Validate report length
        if (len < 8) {
            syslog(LOG_WARNING, "Invalid keyboard report length: %zu", len);
            return events;
        }
        
        uint8_t modifiers = data[0];
        
        // Extract pressed keys from report (bytes 2-7)
        std::set<uint8_t> current_keys;
        for (size_t i = 2; i < 8 && i < len; i++) {
            uint8_t usage = data[i];
            if (usage != 0x00 && usage != 0x01) {  // 0x00 = no key, 0x01 = error rollover
                current_keys.insert(usage);
            }
        }
        
        // Convert modifiers to state flags
        int state_flags = KeyCode::hid_modifiers_to_state_flags(modifiers);
        
        // Apply caps lock flag
        if (caps_lock_state_) {
            state_flags |= EventBytes::StateFlags::MOD_CAPS_LOCK;
        }
        
        // 1. Handle modifier key changes (generate KEY_DOWN/KEY_UP for modifier keys)
        if (modifiers != last_modifiers_) {
            generate_modifier_events(events, last_modifiers_, modifiers, state_flags);
        }
        
        // 2. Handle released keys
        for (uint8_t old_key : pressed_keys_) {
            if (current_keys.find(old_key) == current_keys.end()) {
                // Key was released
                generate_key_up_event(events, old_key, state_flags);
                repeat_states_.erase(old_key);
            }
        }
        
        // 3. Handle newly pressed keys
        for (uint8_t new_key : current_keys) {
            if (pressed_keys_.find(new_key) == pressed_keys_.end()) {
                // Key was pressed
                generate_key_down_event(events, new_key, state_flags);
                
                // Initialize repeat state
                KeyRepeatState repeat;
                repeat.usage = new_key;
                repeat.press_time = std::chrono::steady_clock::now();
                repeat.last_repeat = repeat.press_time;
                repeat.repeating = false;
                repeat_states_[new_key] = repeat;
                
                // Handle caps lock toggle
                if (new_key == KeyCode::KEY_CAPS_LOCK) {
                    caps_lock_state_ = !caps_lock_state_;
                }
            } else {
                // Key is still pressed - check for repeat
                generate_key_repeat_if_needed(events, new_key, state_flags);
            }
        }
        
        // Update state
        pressed_keys_ = current_keys;
        last_modifiers_ = modifiers;
        
        return events;
    }
    
    /**
     * Reset parser state
     */
    void reset() {
        pressed_keys_.clear();
        repeat_states_.clear();
        last_modifiers_ = 0;
        caps_lock_state_ = false;
    }
    
private:
    /**
     * Generate KEY_DOWN + KEY_CHAR_MODS sequence
     */
    void generate_key_down_event(std::vector<std::vector<uint8_t>>& events,
                                 uint8_t usage, int state_flags) {
        int virtual_key = KeyCode::hid_usage_to_virtual_key(usage);
        int scancode = KeyCode::hid_usage_to_scancode(usage);
        
        // 1. Generate KEY_DOWN event (physical key press)
        auto key_down = factory_->create_key_down(virtual_key, scancode, state_flags);
        events.push_back(key_down);
        
        // 2. Generate KEY_CHAR_MODS event if key produces a character
        if ( KeyCode::is_printable_key(usage)) {
            int codepoint = calculate_codepoint(usage, state_flags);
            if (codepoint != 0) {
                // Use EVENT_KEY_CHAR_MODS which includes modifier flags
                auto key_char = factory_->create_key_char(codepoint, state_flags);
                events.push_back(key_char);
            }
        }
    }
    
    /**
     * Generate KEY_UP event
     */
    void generate_key_up_event(std::vector<std::vector<uint8_t>>& events,
                               uint8_t usage, int state_flags) {
        int virtual_key =  KeyCode::hid_usage_to_virtual_key(usage);
        int scancode =  KeyCode::hid_usage_to_scancode(usage);
        
        auto key_up = factory_->create_key_up(virtual_key, scancode, state_flags);
        events.push_back(key_up);
    }
    
    /**
     * Generate KEY_REPEAT + KEY_CHAR_MODS sequence (if repeat timing met)
     */
    void generate_key_repeat_if_needed(std::vector<std::vector<uint8_t>>& events,
                                       uint8_t usage, int state_flags) {
        auto it = repeat_states_.find(usage);
        if (it == repeat_states_.end()) {
            return;
        }
        
        auto& repeat = it->second;
        auto now = std::chrono::steady_clock::now();
        
        // Calculate time since press and last repeat
        auto time_since_press = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - repeat.press_time).count();
        auto time_since_repeat = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - repeat.last_repeat).count();
        
        // Check if we should generate repeat
        bool should_repeat = false;
        if (!repeat.repeating) {
            // Initial repeat after delay
            if (time_since_press >= REPEAT_DELAY_MS) {
                should_repeat = true;
                repeat.repeating = true;
            }
        } else {
            // Continuous repeat at rate
            if (time_since_repeat >= REPEAT_RATE_MS) {
                should_repeat = true;
            }
        }
        
        if (should_repeat) {
            int virtual_key =  KeyCode::hid_usage_to_virtual_key(usage);
            int scancode =  KeyCode::hid_usage_to_scancode(usage);
            
            // 1. Generate KEY_REPEAT event
            auto key_repeat = factory_->create_key_repeat(virtual_key, scancode, state_flags);
            events.push_back(key_repeat);
            
            // 2. Generate KEY_CHAR event if printable
            if (KeyCode::is_printable_key(usage)) {
                int codepoint = calculate_codepoint(usage, state_flags);
                if (codepoint != 0) {
                    auto key_char = factory_->create_key_char(codepoint, state_flags);
                    events.push_back(key_char);
                }
            }
            
            repeat.last_repeat = now;
        }
    }
    
    /**
     * Generate events for modifier key changes
     */
    void generate_modifier_events(std::vector<std::vector<uint8_t>>& events,
                                  uint8_t old_mods, uint8_t new_mods,
                                  int state_flags) {
        // Map modifier bits to HID usage IDs
        const struct {
            uint8_t bit;
            uint8_t usage;
        } modifiers[] = {
            {KeyCode::MOD_LEFT_CTRL,KeyCode::KEY_LEFT_CTRL_USAGE},
            {KeyCode::MOD_LEFT_SHIFT,KeyCode::KEY_LEFT_SHIFT_USAGE},
            {KeyCode::MOD_LEFT_ALT,KeyCode::KEY_LEFT_ALT_USAGE},
            {KeyCode::MOD_LEFT_GUI,KeyCode::KEY_LEFT_GUI_USAGE},
            {KeyCode::MOD_RIGHT_CTRL,KeyCode::KEY_RIGHT_CTRL_USAGE},
            {KeyCode::MOD_RIGHT_SHIFT,KeyCode::KEY_RIGHT_SHIFT_USAGE},
            {KeyCode::MOD_RIGHT_ALT,KeyCode::KEY_RIGHT_ALT_USAGE},
            {KeyCode::MOD_RIGHT_GUI,KeyCode::KEY_RIGHT_GUI_USAGE},
        };
        
        for (const auto& mod : modifiers) {
            bool was_pressed = (old_mods & mod.bit) != 0;
            bool is_pressed = (new_mods & mod.bit) != 0;
            
            if (is_pressed && !was_pressed) {
                // Modifier pressed
                int virtual_key = KeyCode::hid_usage_to_virtual_key(mod.usage);
                int scancode = KeyCode::hid_usage_to_scancode(mod.usage);
                auto key_down = factory_->create_key_down(virtual_key, scancode, state_flags);
                events.push_back(key_down);
            } else if (!is_pressed && was_pressed) {
                // Modifier released
                int virtual_key = KeyCode::hid_usage_to_virtual_key(mod.usage);
                int scancode = KeyCode::hid_usage_to_scancode(mod.usage);
                auto key_up = factory_->create_key_up(virtual_key, scancode, state_flags);
                events.push_back(key_up);
            }
        }
    }
    
    /**
     * Calculate codepoint with caps lock and shift handling
     */
    int calculate_codepoint(uint8_t usage, int state_flags) {
        bool shift = (state_flags & EventBytes::StateFlags::MOD_SHIFT) != 0;
        bool caps = caps_lock_state_;
        
        // Apply caps lock to letters only (inverts shift)
        if (caps && usage >=KeyCode::KEY_A && usage <=KeyCode::KEY_Z) {
            shift = !shift;
        }
        
        return KeyCode::hid_usage_to_codepoint(usage, shift);
    }
};

/**
 * Mouse HID Report Parser
 * Standard boot protocol: 4-byte reports
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
        
        // Convert button states to flags
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
 * Generic HID parser dispatcher
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
    
    std::vector<std::vector<uint8_t>> parse_report(const uint8_t* data, size_t len) {
        if (keyboard_parser_) {
            return keyboard_parser_->parse_report(data, len);
        } else if (mouse_parser_) {
            return mouse_parser_->parse_report(data, len);
        }
        
        return std::vector<std::vector<uint8_t>>();
    }
    
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