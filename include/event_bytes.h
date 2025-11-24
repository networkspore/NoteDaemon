// include/event_bytes.h
// Event type constants matching Java EventBytes.java
// Organized by category for consistency across protocol

#ifndef EVENT_BYTES_H
#define EVENT_BYTES_H

#include <cstdint>

namespace EventBytes {

   
// Mouse events (1-14)
constexpr uint8_t EVENT_MOUSE_MOVE_RELATIVE = 1;
constexpr uint8_t EVENT_MOUSE_BUTTON_DOWN = 2;
constexpr uint8_t EVENT_MOUSE_BUTTON_UP = 3;
constexpr uint8_t EVENT_MOUSE_CLICK = 4;
constexpr uint8_t EVENT_MOUSE_DOUBLE_CLICK = 5;
constexpr uint8_t EVENT_SCROLL = 6;
constexpr uint8_t EVENT_MOUSE_ENTER = 7;
constexpr uint8_t EVENT_MOUSE_EXIT = 8;
constexpr uint8_t EVENT_MOUSE_DRAG_START = 9;
constexpr uint8_t EVENT_MOUSE_DRAG = 10;
constexpr uint8_t EVENT_MOUSE_DRAG_END = 11;
constexpr uint8_t EVENT_MOUSE_MOVE_ABSOLUTE = 12;


// Keyboard events (15-19)
constexpr uint8_t EVENT_KEY_DOWN = 15;
constexpr uint8_t EVENT_KEY_UP = 16;
constexpr uint8_t EVENT_KEY_REPEAT = 17;
constexpr uint8_t EVENT_KEY_CHAR = 18;
constexpr uint8_t EVENT_KEY_CHAR_MODS = 19;

// Focus events (50-51)
constexpr uint8_t EVENT_FOCUS_GAINED = 50;
constexpr uint8_t EVENT_FOCUS_LOST = 51;

// Window events (52-55)
constexpr uint8_t EVENT_WINDOW_RESIZE = 52;
constexpr uint8_t EVENT_WINDOW_MOVE = 53;
constexpr uint8_t EVENT_WINDOW_CLOSE = 54;
constexpr uint8_t EVENT_FRAMEBUFFER_RESIZE = 55;

constexpr uint8_t EVENT_RAW_HID        = 60;

constexpr uint8_t TYPE_ENCRYPTION_OFFER   = 225;
constexpr uint8_t TYPE_ENCRYPTION_ACCEPT  = 226;
constexpr uint8_t TYPE_ENCRYPTION_READY   = 227;
constexpr uint8_t TYPE_ENCRYPTED          = 228;
constexpr uint8_t TYPE_ENCRYPTION_DECLINE = 229;

// State change events (242-247)
constexpr uint8_t EVENT_RELEASE = 242;
constexpr uint8_t EVENT_REMOVED = 243;
constexpr uint8_t EVENT_CHANGED = 244;
constexpr uint8_t EVENT_CHECKED = 245;
constexpr uint8_t EVENT_UPDATED = 246;
constexpr uint8_t EVENT_ADDED = 247;

// Protocol control messages (248-255)
constexpr uint8_t TYPE_ERROR = 248;
constexpr uint8_t TYPE_DISCONNECTED = 249;
constexpr uint8_t TYPE_PONG = 250;
constexpr uint8_t TYPE_PING = 251;
constexpr uint8_t TYPE_ACCEPT = 252;       // trust ack
constexpr uint8_t TYPE_HELLO = 253;        // identity bootstrap
constexpr uint8_t TYPE_CMD = 254;
constexpr uint8_t TYPE_SHUTDOWN = 255;

inline bool requires_encryption(uint8_t type) {
    // Only event messages (0x30+) should be encrypted
    // Protocol/control messages are sent in plaintext
    return type >= 0x30;
}
/**
 * State flags for input events
 * Matches Java EventBytes.StateFlags
 */
namespace StateFlags {
    // Modifier keys (bits 0-7)
    constexpr int MOD_SHIFT = 0x0001;
    constexpr int MOD_CONTROL = 0x0002;
    constexpr int MOD_ALT = 0x0004;
    constexpr int MOD_SUPER = 0x0008;      // Windows/Command key
    constexpr int MOD_CAPS_LOCK = 0x0010;
    constexpr int MOD_NUM_LOCK = 0x0020;
    constexpr int MOD_SCROLL_LOCK = 0x0040;

     constexpr int MOD_MASK = 0x000000FF;

    // Mouse buttons (bits 8-15)
    constexpr int MOUSE_BUTTON_1 = 0x0100;  // Left
    constexpr int MOUSE_BUTTON_2 = 0x0200;  // Right
    constexpr int MOUSE_BUTTON_3 = 0x0400;  // Middle
    constexpr int MOUSE_BUTTON_4 = 0x0800;
    constexpr int MOUSE_BUTTON_5 = 0x1000;
    constexpr int MOUSE_BUTTON_6 = 0x2000;
    constexpr int MOUSE_BUTTON_7 = 0x4000;
    constexpr int MOUSE_BUTTON_8 = 0x8000;

    constexpr int MOUSE_BUTTON_MASK = 0x0000FF00;

    
    // Event state flags (bits 16-23)
    constexpr int STATE_CONSUMED  = 0x010000;  // Event has been handled
    constexpr int STATE_BUBBLING  = 0x020000;  // Event is bubbling up
    constexpr int STATE_CAPTURING = 0x040000;  // Event is in capture phase
    constexpr int STATE_SYNTHETIC = 0x080000;  // Generated, not from OS
    constexpr int STATE_RECORDED  = 0x100000;  // Event was recorded
    constexpr int STATE_REPLAYING = 0x200000;  // Event is from playback

    constexpr int EVENT_STATE_MASK = 0x00FF0000;
    
    inline bool has_flag(int state, int flag) {
        return (state & flag) != 0;
    }
    
    inline int set_flag(int state, int flag) {
        return state | flag;
    }
    
    inline int clear_flag(int state, int flag) {
        return state & ~flag;
    }
}


} // namespace EventBytes

#endif // EVENT_BYTE