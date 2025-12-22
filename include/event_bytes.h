// include/event_bytes.h
// Event type constants matching Java EventBytes.java
// Organized by category for consistency across protocol

#ifndef EVENT_BYTES_H
#define EVENT_BYTES_H

#include <cstdint>
#include <string_view>

namespace EventBytes {

   
// ===== MOUSE EVENTS =====
    constexpr std::string_view EVENT_MOUSE_MOVE_RELATIVE  = "mouse_move_rel";
    constexpr std::string_view EVENT_MOUSE_BUTTON_DOWN    = "mouse_button_down";
    constexpr std::string_view EVENT_MOUSE_BUTTON_UP      = "mouse_button_up";
    constexpr std::string_view EVENT_MOUSE_CLICK          = "mouse_click";
    constexpr std::string_view EVENT_MOUSE_DOUBLE_CLICK   = "mouse_double_click";
    constexpr std::string_view EVENT_SCROLL               = "mouse_scroll";
    constexpr std::string_view EVENT_MOUSE_ENTER           = "mouse_enter";
    constexpr std::string_view EVENT_MOUSE_EXIT            = "mouse_exit";
    constexpr std::string_view EVENT_MOUSE_DRAG_START      = "mouse_drag_start";
    constexpr std::string_view EVENT_MOUSE_DRAG            = "mouse_drag";
    constexpr std::string_view EVENT_MOUSE_DRAG_END        = "mouse_drag_end";
    constexpr std::string_view EVENT_MOUSE_MOVE_ABSOLUTE   = "mouse_move_abs";

    // ===== KEYBOARD EVENTS =====
    constexpr std::string_view EVENT_KEY_DOWN       = "key_down";
    constexpr std::string_view EVENT_KEY_UP         = "key_up";
    constexpr std::string_view EVENT_KEY_REPEAT     = "key_repeat";
    constexpr std::string_view EVENT_KEY_CHAR       = "key_char";
    constexpr std::string_view EVENT_KEY_CHAR_MODS  = "key_char_mods";

    // ===== CONTAINER / WINDOW EVENTS =====
    constexpr std::string_view EVENT_FOCUS_GAINED        = "container_focus_gained";
    constexpr std::string_view EVENT_FOCUS_LOST          = "container_focus_lost";

    constexpr std::string_view EVENT_WINDOW_RESIZE       = "container_resize";
    constexpr std::string_view EVENT_WINDOW_MOVE         = "container_move";
    constexpr std::string_view EVENT_WINDOW_CLOSE        = "container_close";
    constexpr std::string_view EVENT_FRAMEBUFFER_RESIZE  = "container_resize";

    // ===== SPECIAL INPUT =====
    constexpr std::string_view EVENT_RAW_HID = "raw_hid";

    // ===== ENCRYPTION / PROTOCOL =====
    constexpr std::string_view TYPE_ENCRYPTION_OFFER   = "encryption_offer";
    constexpr std::string_view TYPE_ENCRYPTION_ACCEPT  = "encryption_accept";
    constexpr std::string_view TYPE_ENCRYPTION_READY   = "encryption_ready";
    constexpr std::string_view TYPE_ENCRYPTED          = "encrypted";
    constexpr std::string_view TYPE_ENCRYPTION_DECLINE = "encryption_decline";

    // ===== STATE CHANGE EVENTS =====
    constexpr std::string_view EVENT_RELEASE = "release";
    constexpr std::string_view EVENT_REMOVED = "removed";
    constexpr std::string_view EVENT_CHANGED = "changed";
    constexpr std::string_view EVENT_CHECKED = "checked";
    constexpr std::string_view EVENT_UPDATED = "updated";
    constexpr std::string_view EVENT_ADDED   = "added";

    // ===== PROTOCOL CONTROL =====
    constexpr std::string_view TYPE_ERROR        = "error";
    constexpr std::string_view TYPE_DISCONNECTED = "disconnected";
    constexpr std::string_view TYPE_PONG         = "pong";
    constexpr std::string_view TYPE_PING         = "ping";
    constexpr std::string_view TYPE_ACCEPT       = "accept";
    constexpr std::string_view TYPE_HELLO        = "hello";
    constexpr std::string_view TYPE_CMD          = "cmd";
    constexpr std::string_view TYPE_SHUTDOWN     = "shutdown";

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