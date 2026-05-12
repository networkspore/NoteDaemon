// include/event_bytes.h
// Event type constants as pre-serialized NoteBytes::Value objects
// Organized by category for consistency across protocol

#ifndef EVENT_BYTES_H
#define EVENT_BYTES_H

#include "notebytes.h"

namespace EventBytes {

// ===== MOUSE EVENTS =====
inline const NoteBytes::Value EVENT_MOUSE_MOVE_RELATIVE("mouse_move_rel");
inline const NoteBytes::Value EVENT_MOUSE_BUTTON_DOWN("mouse_button_down");
inline const NoteBytes::Value EVENT_MOUSE_BUTTON_UP("mouse_button_up");
inline const NoteBytes::Value EVENT_MOUSE_CLICK("mouse_click");
inline const NoteBytes::Value EVENT_MOUSE_DOUBLE_CLICK("mouse_double_click");
inline const NoteBytes::Value EVENT_SCROLL("mouse_scroll");
inline const NoteBytes::Value EVENT_MOUSE_ENTER("mouse_enter");
inline const NoteBytes::Value EVENT_MOUSE_EXIT("mouse_exit");
inline const NoteBytes::Value EVENT_MOUSE_DRAG_START("mouse_drag_start");
inline const NoteBytes::Value EVENT_MOUSE_DRAG("mouse_drag");
inline const NoteBytes::Value EVENT_MOUSE_DRAG_END("mouse_drag_end");
inline const NoteBytes::Value EVENT_MOUSE_MOVE_ABSOLUTE("mouse_move_abs");

// ===== KEYBOARD EVENTS =====
inline const NoteBytes::Value EVENT_KEY_DOWN("key_down");
inline const NoteBytes::Value EVENT_KEY_UP("key_up");
inline const NoteBytes::Value EVENT_KEY_REPEAT("key_repeat");
inline const NoteBytes::Value EVENT_KEY_CHAR("key_char");
//inline const NoteBytes::Value EVENT_KEY_CHAR_MODS("key_char_mods");

// ===== CONTAINER / WINDOW EVENTS =====
inline const NoteBytes::Value EVENT_FOCUS_GAINED("container_focus_gained");
inline const NoteBytes::Value EVENT_FOCUS_LOST("container_focus_lost");
inline const NoteBytes::Value EVENT_WINDOW_RESIZE("container_resize");
inline const NoteBytes::Value EVENT_WINDOW_MOVE("container_move");
inline const NoteBytes::Value EVENT_WINDOW_CLOSE("container_close");
inline const NoteBytes::Value EVENT_FRAMEBUFFER_RESIZE("container_resize");

// ===== SPECIAL INPUT =====
inline const NoteBytes::Value EVENT_RAW_HID("raw_hid");




/**
 * State flags for input events
 * Matches Java EventBytes.StateFlags
 */
namespace StateFlags {
    // Modifier keys (bits 0-7)
    constexpr int MOD_SHIFT = 0x0001;
    constexpr int MOD_CONTROL = 0x0002;
    constexpr int MOD_ALT = 0x0004;
    constexpr int MOD_SUPER = 0x0008;
    constexpr int MOD_CAPS_LOCK = 0x0010;
    constexpr int MOD_NUM_LOCK = 0x0020;
    constexpr int MOD_SCROLL_LOCK = 0x0040;

    constexpr int MOD_MASK = 0x000000FF;

    // Mouse buttons (bits 8-15)
    constexpr int MOUSE_BUTTON_1 = 0x0100;
    constexpr int MOUSE_BUTTON_2 = 0x0200;
    constexpr int MOUSE_BUTTON_3 = 0x0400;
    constexpr int MOUSE_BUTTON_4 = 0x0800;
    constexpr int MOUSE_BUTTON_5 = 0x1000;
    constexpr int MOUSE_BUTTON_6 = 0x2000;
    constexpr int MOUSE_BUTTON_7 = 0x4000;
    constexpr int MOUSE_BUTTON_8 = 0x8000;

    constexpr int MOUSE_BUTTON_MASK = 0x0000FF00;

    // Event state flags (bits 16-23)
    constexpr int STATE_CONSUMED  = 0x010000;
    constexpr int STATE_BUBBLING  = 0x020000;
    constexpr int STATE_CAPTURING = 0x040000;
    constexpr int STATE_SYNTHETIC = 0x080000;
    constexpr int STATE_RECORDED  = 0x100000;
    constexpr int STATE_REPLAYING = 0x200000;

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

#endif // EVENT_BYTES_H