// include/key_code.h
// C++ KeyCode - standardized keyboard keycodes

#ifndef KEY_CODE_H
#define KEY_CODE_H

#include <cstdint>
#include "event_bytes.h"

namespace KeyCode {
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
    constexpr uint8_t KEY_B = 0x05;
    constexpr uint8_t KEY_C = 0x06;
    constexpr uint8_t KEY_D = 0x07;
    constexpr uint8_t KEY_E = 0x08;
    constexpr uint8_t KEY_F = 0x09;
    constexpr uint8_t KEY_G = 0x0A;
    constexpr uint8_t KEY_H = 0x0B;
    constexpr uint8_t KEY_I = 0x0C;
    constexpr uint8_t KEY_J = 0x0D;
    constexpr uint8_t KEY_K = 0x0E;
    constexpr uint8_t KEY_L = 0x0F;
    constexpr uint8_t KEY_M = 0x10;
    constexpr uint8_t KEY_N = 0x11;
    constexpr uint8_t KEY_O = 0x12;
    constexpr uint8_t KEY_P = 0x13;
    constexpr uint8_t KEY_Q = 0x14;
    constexpr uint8_t KEY_R = 0x15;
    constexpr uint8_t KEY_S = 0x16;
    constexpr uint8_t KEY_T = 0x17;
    constexpr uint8_t KEY_U = 0x18;
    constexpr uint8_t KEY_V = 0x19;
    constexpr uint8_t KEY_W = 0x1A;
    constexpr uint8_t KEY_X = 0x1B;
    constexpr uint8_t KEY_Y = 0x1C;
    constexpr uint8_t KEY_Z = 0x1D;

    // Number row
    constexpr uint8_t KEY_1 = 0x1E;
    constexpr uint8_t KEY_2 = 0x1F;
    constexpr uint8_t KEY_3 = 0x20;
    constexpr uint8_t KEY_4 = 0x21;
    constexpr uint8_t KEY_5 = 0x22;
    constexpr uint8_t KEY_6 = 0x23;
    constexpr uint8_t KEY_7 = 0x24;
    constexpr uint8_t KEY_8 = 0x25;
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
    constexpr uint8_t F1 = 0x3A;
    constexpr uint8_t F2 = 0x3B;
    constexpr uint8_t F3 = 0x3C;
    constexpr uint8_t F4 = 0x3D;
    constexpr uint8_t F5 = 0x3E;
    constexpr uint8_t F6 = 0x3F;
    constexpr uint8_t F7 = 0x40;
    constexpr uint8_t F8 = 0x41;
    constexpr uint8_t F9 = 0x42;
    constexpr uint8_t F10 = 0x43;
    constexpr uint8_t F11 = 0x44;
    constexpr uint8_t F12 = 0x45;

    constexpr uint8_t PRINT_SCREEN = 0x46;
    constexpr uint8_t SCROLL_LOCK  = 0x47;
    constexpr uint8_t PAUSE = 0x48;

    // Navigation block
    constexpr uint8_t INSERT = 0x49;
    constexpr uint8_t HOME = 0x4A;
    constexpr uint8_t PAGE_UP = 0x4B;
    constexpr uint8_t DELETE = 0x4C;
    constexpr uint8_t END = 0x4D;
    constexpr uint8_t PAGE_DOWN = 0x4E;

    
    // Arrow keys
    constexpr uint8_t KEY_RIGHT = 0x4F;
    constexpr uint8_t KEY_LEFT = 0x50;
    constexpr uint8_t KEY_DOWN = 0x51;
    constexpr uint8_t KEY_UP = 0x52;

    // Keypad
    constexpr uint8_t NUM_LOCK = 0x53;
    constexpr uint8_t KP_SLASH = 0x54;
    constexpr uint8_t KP_ASTERISK = 0x55;
    constexpr uint8_t KP_MINUS = 0x56;
    constexpr uint8_t KP_PLUS = 0x57;
    constexpr uint8_t KP_ENTER = 0x58;
    constexpr uint8_t KP_1 = 0x59;
    constexpr uint8_t KP_2 = 0x5A;
    constexpr uint8_t KP_3 = 0x5B;
    constexpr uint8_t KP_4 = 0x5C;
    constexpr uint8_t KP_5 = 0x5D;
    constexpr uint8_t KP_6 = 0x5E;
    constexpr uint8_t KP_7 = 0x5F;
    constexpr uint8_t KP_8 = 0x60;
    constexpr uint8_t KP_9 = 0x61;
    constexpr uint8_t KP_0 = 0x62;
    constexpr uint8_t KP_PERIOD = 0x63;

    // Extended keys
    constexpr uint8_t NON_US_BACKSLASH = 0x64;
    constexpr uint8_t APPLICATION = 0x65;
    constexpr uint8_t POWER = 0x66;
    constexpr uint8_t KP_EQUALS = 0x67;

    // F13–F24
    constexpr uint8_t F13 = 0x68;
    constexpr uint8_t F14 = 0x69;
    constexpr uint8_t F15 = 0x6A;
    constexpr uint8_t F16 = 0x6B;
    constexpr uint8_t F17 = 0x6C;
    constexpr uint8_t F18 = 0x6D;
    constexpr uint8_t F19 = 0x6E;
    constexpr uint8_t F20 = 0x6F;
    constexpr uint8_t F21 = 0x70;
    constexpr uint8_t F22 = 0x71;
    constexpr uint8_t F23 = 0x72;
    constexpr uint8_t F24 = 0x73;

    // Media keys
    constexpr uint8_t EXECUTE = 0x74;
    constexpr uint8_t HELP = 0x75;
    constexpr uint8_t MENU = 0x76;
    constexpr uint8_t SELECT = 0x77;
    constexpr uint8_t STOP = 0x78;
    constexpr uint8_t AGAIN = 0x79;
    constexpr uint8_t UNDO = 0x7A;
    constexpr uint8_t CUT = 0x7B;
    constexpr uint8_t COPY = 0x7C;
    constexpr uint8_t PASTE = 0x7D;
    constexpr uint8_t FIND = 0x7E;
    constexpr uint8_t MUTE = 0x7F;
    constexpr uint8_t VOLUME_UP = 0x80;
    constexpr uint8_t VOLUME_DOWN = 0x81;
    
    // Modifier key usages (for generating modifier key events)
    constexpr uint8_t KEY_LEFT_CTRL_USAGE = 0xE0;
    constexpr uint8_t KEY_LEFT_SHIFT_USAGE = 0xE1;
    constexpr uint8_t KEY_LEFT_ALT_USAGE = 0xE2;
    constexpr uint8_t KEY_LEFT_GUI_USAGE = 0xE3;
    constexpr uint8_t KEY_RIGHT_CTRL_USAGE = 0xE4;
    constexpr uint8_t KEY_RIGHT_SHIFT_USAGE = 0xE5;
    constexpr uint8_t KEY_RIGHT_ALT_USAGE = 0xE6;
    constexpr uint8_t KEY_RIGHT_GUI_USAGE = 0xE7;

    /**
    * Convert HID usage ID to virtual key code
    * Virtual keys are used in KEY_DOWN/KEY_UP events for physical key tracking
    */
    inline int hid_usage_to_virtual_key(uint8_t usage) {
        // For now, use HID usage ID directly as virtual key
        // Can be extended to map to platform-specific virtual key codes
        return usage;
    }

    /**
    * Get scancode for HID usage (platform-specific scan codes)
    */
    inline int hid_usage_to_scancode(uint8_t usage) {
        // For now, use HID usage ID as scancode
        // Could map to X11 keycodes, Windows scan codes, etc.
        return usage;
    }

    /**
    * Convert HID modifier byte to EventBytes state flags
    */
    inline int hid_modifiers_to_state_flags(uint8_t modifiers) {
        int flags = 0;
        
        if (modifiers & (MOD_LEFT_SHIFT | MOD_RIGHT_SHIFT)) {
            flags |= EventBytes::StateFlags::MOD_SHIFT;
        }
        if (modifiers & (MOD_LEFT_CTRL | MOD_RIGHT_CTRL)) {
            flags |= EventBytes::StateFlags::MOD_CONTROL;
        }
        if (modifiers & (MOD_LEFT_ALT | MOD_RIGHT_ALT)) {
            flags |= EventBytes::StateFlags::MOD_ALT;
        }
        if (modifiers & (MOD_LEFT_GUI | MOD_RIGHT_GUI)) {
            flags |= EventBytes::StateFlags::MOD_SUPER;
        }
        
        return flags;
    }

    /**
    * Check if key produces printable character
    */
    inline bool is_printable_key(uint8_t usage) {
        // Letters, numbers, and punctuation
        return (usage >= KEY_A && usage <= KEY_SLASH) ||
            usage == KEY_SPACE;
    }

    /**
    * Convert HID usage ID to character codepoint (US layout)
    * Returns 0 if no printable character
    * This handles shift state for character generation
    */
    inline int hid_usage_to_codepoint(uint8_t usage, bool shift) {
        // Letters A-Z
        if (usage >= KEY_A && usage <= KEY_Z) {
            int offset = usage - KEY_A;
            return shift ? ('A' + offset) : ('a' + offset);
        }
        
        // Numbers 1-9, 0
        if (usage >= KEY_1 && usage <= KEY_9) {
            if (shift) {
                // Shifted number row: !@#$%^&*()
                const char shifted[] = "!@#$%^&*(";
                return shifted[usage - KEY_1];
            }
            return '1' + (usage - KEY_1);
        }
        if (usage == KEY_0) {
            return shift ? ')' : '0';
        }
        
        // Special characters
        switch (usage) {
            case KEY_SPACE: return ' ';
            case KEY_ENTER: return '\n';
            case KEY_TAB: return '\t';
            case KEY_MINUS: return shift ? '_' : '-';
            case KEY_EQUAL: return shift ? '+' : '=';
            case KEY_LEFT_BRACKET: return shift ? '{' : '[';
            case KEY_RIGHT_BRACKET: return shift ? '}' : ']';
            case KEY_BACKSLASH: return shift ? '|' : '\\';
            case KEY_SEMICOLON: return shift ? ':' : ';';
            case KEY_APOSTROPHE: return shift ? '"' : '\'';
            case KEY_GRAVE: return shift ? '~' : '`';
            case KEY_COMMA: return shift ? '<' : ',';
            case KEY_PERIOD: return shift ? '>' : '.';
            case KEY_SLASH: return shift ? '?' : '/';
            default: return 0;
        }
    }

}// namespace KeyCode

#endif // KEY_CODE_H