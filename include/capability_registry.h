// include/capability_registry.h
// C++ Capability Registry matching Java CapabilityRegistry

#ifndef CAPABILITY_REGISTRY_H
#define CAPABILITY_REGISTRY_H

#include <boost/multiprecision/cpp_int.hpp>


#include <cstdint>
#include <string>
#include <map>
#include <set>
#include <vector>
#include "bitflag_state_bigint.h"
#include "note_messaging.h"

using boost::multiprecision::cpp_int;

namespace Capabilities {

/**
 * Capability bit positions (matching Java CapabilityRegistry)
 * Uses uint64_t for 64-bit capability masks
 */
namespace Bits {
    // Input device types (bits 0-7)
    constexpr int KEYBOARD             = 0;
    constexpr int MOUSE                = 1;
    constexpr int TOUCH                = 2;
    constexpr int GAMEPAD              = 3;
    constexpr int PEN                  = 4;
    constexpr int TOUCHPAD             = 5;
    constexpr int SCROLL               = 6;


    constexpr int RAW_MODE             = 8;
    constexpr int PARSED_MODE          = 9;
    constexpr int PASSTHROUGH_MODE     = 10;
    constexpr int FILTERED_MODE        = 11;

    constexpr int ABSOLUTE_COORDINATES = 16;
    constexpr int RELATIVE_COORDINATES = 17;
    constexpr int SCREEN_COORDINATES   = 18;
    constexpr int NORMALIZED_COORDINATES = 19;

    constexpr int HIGH_PRECISION       = 24;
    constexpr int MULTIPLE_DEVICES     = 25;
    constexpr int GLOBAL_CAPTURE       = 26;
    constexpr int PROVIDES_SCANCODES   = 27;
    constexpr int NANOSECOND_TIMESTAMPS = 28;
     
     // Device type detection (bits 32-39)

    constexpr int DEVICE_TYPE_KNOWN    = 32;
    constexpr int HID_DEVICE           = 33;
    constexpr int USB_DEVICE           = 34;
    constexpr int BLUETOOTH_DEVICE     = 35;
     
     // State capabilities (bits 40-47)

    constexpr int ENCRYPTION_SUPPORTED = 40;
    constexpr int ENCRYPTION_ENABLED   = 41;
    constexpr int BUFFERING_SUPPORTED  = 42;
    constexpr int BUFFERING_ENABLED    = 43;
     
     // Lifecycle (bits 48-55)
    constexpr int SCENE_LOCATION       = 48;
    constexpr int SCENE_SIZE           = 49;
    constexpr int WINDOW_LIFECYCLE     = 50;
    constexpr int STAGE_POSITION       = 51;
    constexpr int STAGE_SIZE           = 52;
    constexpr int STAGE_FOCUS          = 53;
     
     // Composite capabilities (bits 56-63)

    
    // Mode mask (all mutually exclusive modes)
    constexpr int COMPOSITE_SOURCE     = 56;
    constexpr int MULTIPLE_CHILDREN    = 57;
    
    const std::vector<int> MODE_BITS = {RAW_MODE, PARSED_MODE, PASSTHROUGH_MODE, FILTERED_MODE};
    
}

namespace Masks {
    inline cpp_int mode_mask() {
        return State::create_mask(Bits::MODE_BITS);
    }
    
    inline cpp_int device_type_mask() {
        return State::create_range_mask(Bits::KEYBOARD, Bits::SCROLL);
    }
    
    inline cpp_int coordinate_mask() {
        return State::create_range_mask(Bits::ABSOLUTE_COORDINATES, Bits::NORMALIZED_COORDINATES);
    }
    
    inline cpp_int advanced_features_mask() {
        return State::create_range_mask(Bits::HIGH_PRECISION, Bits::NANOSECOND_TIMESTAMPS);
    }
    
    inline cpp_int device_detection_mask() {
        return State::create_range_mask(Bits::DEVICE_TYPE_KNOWN, Bits::BLUETOOTH_DEVICE);
    }
    
    inline cpp_int encryption_mask() {
        cpp_int mask = 0;
        State::bit_set(mask, Bits::ENCRYPTION_SUPPORTED);
        State::bit_set(mask, Bits::ENCRYPTION_ENABLED);
        return mask;
    }
}

/**
 * Capability names for string conversion
 */
namespace Names {
    inline const char* get_capability_name(int bit_position) {
        switch (bit_position) {
            case Bits::KEYBOARD: return NoteMessaging::ItemTypes::KEYBOARD;
            case Bits::MOUSE: return NoteMessaging::ItemTypes::MOUSE;
            case Bits::TOUCH: return NoteMessaging::ItemTypes::TOUCHPAD;
            case Bits::GAMEPAD: return NoteMessaging::ItemTypes::GAMEPAD;
            case Bits::PEN: return NoteMessaging::ItemTypes::PEN;
            case Bits::TOUCHPAD: return NoteMessaging::ItemTypes::TOUCHPAD;
            case Bits::SCROLL: return NoteMessaging::ItemTypes::SCROLL;
            
            case Bits::RAW_MODE: return "raw_mode";
            case Bits::PARSED_MODE: return "parsed_mode";
            case Bits::PASSTHROUGH_MODE: return "passthrough_mode";
            case Bits::FILTERED_MODE: return "filtered_mode";
            
            case Bits::ABSOLUTE_COORDINATES: return "absolute_coordinates";
            case Bits::RELATIVE_COORDINATES: return "relative_coordinates";
            case Bits::SCREEN_COORDINATES: return "screen_coordinates";
            case Bits::NORMALIZED_COORDINATES: return "normalized_coordinates";
            
            case Bits::HIGH_PRECISION: return "high_precision";
            case Bits::MULTIPLE_DEVICES: return "multiple_devices";
            case Bits::GLOBAL_CAPTURE: return "global_capture";
            case Bits::PROVIDES_SCANCODES: return "provides_scancodes";
            case Bits::NANOSECOND_TIMESTAMPS: return "nanosecond_timestamps";
            
            case Bits::DEVICE_TYPE_KNOWN: return "device_type_known";
            case Bits::HID_DEVICE: return "hid_device";
            case Bits::USB_DEVICE: return "usb_device";
            case Bits::BLUETOOTH_DEVICE: return "bluetooth_device";
            
            case Bits::ENCRYPTION_SUPPORTED: return "encryption_supported";
            case Bits::ENCRYPTION_ENABLED: return "encryption_enabled";
            case Bits::BUFFERING_SUPPORTED: return "buffering_supported";
            case Bits::BUFFERING_ENABLED: return "buffering_enabled";
            
            default: return "unknown";
        }
    }
    
    inline int get_capability_bit(const std::string& name) {
        static std::map<std::string, int> name_to_bit = {
            {"keyboard", Bits::KEYBOARD},
            {"mouse", Bits::MOUSE},
            {"touch", Bits::TOUCH},
            {"gamepad", Bits::GAMEPAD},
            {"pen", Bits::PEN},
            {"touchpad", Bits::TOUCHPAD},
            {"scroll", Bits::SCROLL},
            
            {"raw_mode", Bits::RAW_MODE},
            {"parsed_mode", Bits::PARSED_MODE},
            {"passthrough_mode", Bits::PASSTHROUGH_MODE},
            {"filtered_mode", Bits::FILTERED_MODE},
            
            {"absolute_coordinates", Bits::ABSOLUTE_COORDINATES},
            {"relative_coordinates", Bits::RELATIVE_COORDINATES},
            {"screen_coordinates", Bits::SCREEN_COORDINATES},
            {"normalized_coordinates", Bits::NORMALIZED_COORDINATES},
            
            {"high_precision", Bits::HIGH_PRECISION},
            {"multiple_devices", Bits::MULTIPLE_DEVICES},
            {"global_capture", Bits::GLOBAL_CAPTURE},
            {"provides_scancodes", Bits::PROVIDES_SCANCODES},
            {"nanosecond_timestamps", Bits::NANOSECOND_TIMESTAMPS},
            
            {"device_type_known", Bits::DEVICE_TYPE_KNOWN},
            {"hid_device", Bits::HID_DEVICE},
            {"usb_device", Bits::USB_DEVICE},
            {"bluetooth_device", Bits::BLUETOOTH_DEVICE},
            
            {"encryption_supported", Bits::ENCRYPTION_SUPPORTED},
            {"encryption_enabled", Bits::ENCRYPTION_ENABLED},
            {"buffering_supported", Bits::BUFFERING_SUPPORTED},
            {"buffering_enabled", Bits::BUFFERING_ENABLED},
        };
        
        auto it = name_to_bit.find(name);
        return (it != name_to_bit.end()) ? it->second : 0;
    }

    inline std::string format_capabilities(const cpp_int& caps) {
        std::string out = "";
        bool first = true;

        for (int bit = 0; bit < 64; bit++) {
            if (State::bit_test(caps, bit)) {
                if (!first) out += ", ";
                out += Capabilities::Names::get_capability_name(bit);
                first = false;
            }
        }

        if (out.empty()) out = "none";
        return out;
    }
}

/**
 * Capability validation helpers
 */
namespace Validation {
    inline bool is_mode(int bit_position) {
        for (int mode_bit : Bits::MODE_BITS) {
            if (bit_position == mode_bit) return true;
        }
        return false;
    }
    
    inline bool has_mode_conflict(const cpp_int& state) {
        cpp_int mode_mask = Masks::mode_mask();
        return State::count_bits_in_mask(state, mode_mask) > 1;
    }
    
    inline int get_enabled_mode(const cpp_int& state) {
        cpp_int mode_mask = Masks::mode_mask();
        cpp_int masked_state = state & mode_mask;  // explicitly name it
        for (int mode_bit : Bits::MODE_BITS) {
            if (State::bit_test(masked_state, mode_bit)) return mode_bit;
        }
        return -1;
    }

    inline const char* get_mode_name(const cpp_int& state) {
        int mode = get_enabled_mode(state);
        if (mode < 0) return "none";
        return Names::get_capability_name(mode);
    }
    
    inline bool has_any_device_type(const cpp_int& capabilities) {
        cpp_int device_mask = Masks::device_type_mask();
        return State::has_any_bits(capabilities, device_mask);
    }
    
    inline bool supports_encryption(const cpp_int& capabilities) {
        return State::bit_test(capabilities, Bits::ENCRYPTION_SUPPORTED);
    }
    
    inline bool is_encrypted(const cpp_int& capabilities) {
        return State::bit_test(capabilities, Bits::ENCRYPTION_ENABLED);
    }
    
    inline cpp_int get_device_types(const cpp_int& capabilities) {
        cpp_int device_mask = Masks::device_type_mask();
        return State::apply_mask(capabilities, device_mask);
    }

    inline bool validate_mode_compatibility(const std::string& device_type, const std::string& requested_mode) {
        // Raw mode works with everything
        if (requested_mode == "raw_mode") {
            return true;
        }
        
        // Parsed mode requires known device type
        if (requested_mode == "parsed_mode") {
            return device_type != "unknown";
        }
        
        return true;
    }
        
}

/**
 * Device type detection helpers
 */
namespace Detection {
    inline cpp_int detect_keyboard_capabilities() {
        cpp_int caps = 0;
        State::bit_set(caps, Bits::KEYBOARD);
        State::bit_set(caps, Bits::PROVIDES_SCANCODES);
        State::bit_set(caps, Bits::DEVICE_TYPE_KNOWN);
        State::bit_set(caps, Bits::HID_DEVICE);
        State::bit_set(caps, Bits::USB_DEVICE);
        State::bit_set(caps, Bits::RAW_MODE);
        State::bit_set(caps, Bits::PARSED_MODE);
        State::bit_set(caps, Bits::FILTERED_MODE);
        State::bit_set(caps, Bits::ENCRYPTION_SUPPORTED);
        State::bit_set(caps, Bits::BUFFERING_SUPPORTED);
        return caps;
    }
    
    inline cpp_int detect_mouse_capabilities() {
        cpp_int caps = 0;
        State::bit_set(caps, Bits::MOUSE);
        State::bit_set(caps, Bits::SCROLL);
        State::bit_set(caps, Bits::RELATIVE_COORDINATES);
        State::bit_set(caps, Bits::DEVICE_TYPE_KNOWN);
        State::bit_set(caps, Bits::HID_DEVICE);
        State::bit_set(caps, Bits::USB_DEVICE);
        State::bit_set(caps, Bits::RAW_MODE);
        State::bit_set(caps, Bits::PARSED_MODE);
        State::bit_set(caps, Bits::FILTERED_MODE);
        State::bit_set(caps, Bits::ENCRYPTION_SUPPORTED);
        State::bit_set(caps, Bits::BUFFERING_SUPPORTED);
        return caps;
    }
    
    
    inline cpp_int detect_unknown_capabilities() {
        cpp_int caps = 0;
        State::bit_set(caps, Bits::HID_DEVICE);
        State::bit_set(caps, Bits::USB_DEVICE);
        State::bit_set(caps, Bits::RAW_MODE);
        State::bit_set(caps, Bits::PASSTHROUGH_MODE);
        State::bit_set(caps, Bits::ENCRYPTION_SUPPORTED);
        State::bit_set(caps, Bits::BUFFERING_SUPPORTED);
        return caps;
    }
    
    inline int get_default_mode(const std::string& device_type) {
        if (device_type == "unknown") {
            return Bits::RAW_MODE;
        } else {
            return Bits::PARSED_MODE;
        }
    }
}

} // namespace Capabilities

#endif // CAPABILITY_REGISTRY_H