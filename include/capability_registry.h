// include/capability_registry.h
// C++ Capability Registry matching Java CapabilityRegistry

#ifndef CAPABILITY_REGISTRY_H
#define CAPABILITY_REGISTRY_H


#include "note_messaging.h"
#include <cstdint>
#include <string>
#include <map>
#include <set>

namespace Capabilities {

/**
 * Capability bit positions (matching Java CapabilityRegistry)
 * Uses uint64_t for 64-bit capability masks
 */
namespace Bits {
    // Input device types (bits 0-7)
    constexpr uint64_t KEYBOARD             = 1ULL << 0;
    constexpr uint64_t MOUSE                = 1ULL << 1;
    constexpr uint64_t TOUCH                = 1ULL << 2;
    constexpr uint64_t GAMEPAD              = 1ULL << 3;
    constexpr uint64_t PEN                  = 1ULL << 4;
    constexpr uint64_t TOUCHPAD             = 1ULL << 5;
    constexpr uint64_t SCROLL               = 1ULL << 6;
    
    // Device modes (bits 8-15) - mutually exclusive
    constexpr uint64_t RAW_MODE             = 1ULL << 8;
    constexpr uint64_t PARSED_MODE          = 1ULL << 9;
    constexpr uint64_t PASSTHROUGH_MODE     = 1ULL << 10;
    constexpr uint64_t FILTERED_MODE        = 1ULL << 11;
    
    // Coordinate systems (bits 16-23)
    constexpr uint64_t ABSOLUTE_COORDINATES = 1ULL << 16;
    constexpr uint64_t RELATIVE_COORDINATES = 1ULL << 17;
    constexpr uint64_t SCREEN_COORDINATES   = 1ULL << 18;
    constexpr uint64_t NORMALIZED_COORDINATES = 1ULL << 19;
    
    // Advanced features (bits 24-31)
    constexpr uint64_t HIGH_PRECISION       = 1ULL << 24;
    constexpr uint64_t MULTIPLE_DEVICES     = 1ULL << 25;
    constexpr uint64_t GLOBAL_CAPTURE       = 1ULL << 26;
    constexpr uint64_t PROVIDES_SCANCODES   = 1ULL << 27;
    constexpr uint64_t NANOSECOND_TIMESTAMPS = 1ULL << 28;
    
    // Device type detection (bits 32-39)
    constexpr uint64_t DEVICE_TYPE_KNOWN    = 1ULL << 32;
    constexpr uint64_t HID_DEVICE           = 1ULL << 33;
    constexpr uint64_t USB_DEVICE           = 1ULL << 34;
    constexpr uint64_t BLUETOOTH_DEVICE     = 1ULL << 35;
    
    // State capabilities (bits 40-47)
    constexpr uint64_t ENCRYPTION_SUPPORTED = 1ULL << 40;
    constexpr uint64_t ENCRYPTION_ENABLED   = 1ULL << 41;
    constexpr uint64_t BUFFERING_SUPPORTED  = 1ULL << 42;
    constexpr uint64_t BUFFERING_ENABLED    = 1ULL << 43;
    
    // Lifecycle (bits 48-55)
    constexpr uint64_t SCENE_LOCATION       = 1ULL << 48;
    constexpr uint64_t SCENE_SIZE           = 1ULL << 49;
    constexpr uint64_t WINDOW_LIFECYCLE     = 1ULL << 50;
    constexpr uint64_t STAGE_POSITION       = 1ULL << 51;
    constexpr uint64_t STAGE_SIZE           = 1ULL << 52;
    constexpr uint64_t STAGE_FOCUS          = 1ULL << 53;
    
    // Composite capabilities (bits 56-63)
    constexpr uint64_t COMPOSITE_SOURCE     = 1ULL << 56;
    constexpr uint64_t MULTIPLE_CHILDREN    = 1ULL << 57;
    
    // Mode mask (all mutually exclusive modes)
    constexpr uint64_t MODE_MASK = RAW_MODE | PARSED_MODE | PASSTHROUGH_MODE | FILTERED_MODE;
}

/**
 * Capability names for string conversion
 */
namespace Names {
    inline const char* get_capability_name(uint64_t bit) {
        switch (bit) {
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
    
    inline uint64_t get_capability_bit(const std::string& name) {
        static std::map<std::string, uint64_t> name_to_bit = {
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
}

/**
 * Capability validation helpers
 */
namespace Validation {
    inline bool is_mode(uint64_t bit) {
        return (bit & Bits::MODE_MASK) != 0;
    }
    
    inline bool has_mode_conflict(uint64_t capabilities) {
        uint64_t modes = capabilities & Bits::MODE_MASK;
        // Check if more than one bit is set in mode mask
        return modes != 0 && (modes & (modes - 1)) != 0;
    }
    
    inline uint64_t get_enabled_mode(uint64_t capabilities) {
        return capabilities & Bits::MODE_MASK;
    }
    
    inline const char* get_mode_name(uint64_t capabilities) {
        uint64_t mode = get_enabled_mode(capabilities);
        if (mode == 0) return "none";
        return Names::get_capability_name(mode);
    }
    
    inline bool validate_mode_compatibility(const std::string& device_type, const std::string& mode) {
        // Raw mode works with everything
        if (mode == "raw_mode") {
            return true;
        }
        
        // Parsed mode requires known device type
        if (mode == "parsed_mode") {
            return device_type != "unknown";
        }
        
        return true;
    }
}

/**
 * Device type detection helpers
 */
namespace Detection {
    inline uint64_t detect_keyboard_capabilities() {
        return Bits::KEYBOARD |
               Bits::PROVIDES_SCANCODES |
               Bits::DEVICE_TYPE_KNOWN |
               Bits::HID_DEVICE |
               Bits::USB_DEVICE |
               Bits::RAW_MODE |
               Bits::PARSED_MODE |
               Bits::FILTERED_MODE |
               Bits::ENCRYPTION_SUPPORTED |
               Bits::BUFFERING_SUPPORTED;
    }
    
    inline uint64_t detect_mouse_capabilities() {
        return Bits::MOUSE |
               Bits::SCROLL |
               Bits::RELATIVE_COORDINATES |
               Bits::DEVICE_TYPE_KNOWN |
               Bits::HID_DEVICE |
               Bits::USB_DEVICE |
               Bits::RAW_MODE |
               Bits::PARSED_MODE |
               Bits::FILTERED_MODE |
               Bits::ENCRYPTION_SUPPORTED |
               Bits::BUFFERING_SUPPORTED;
    }
    
    inline uint64_t detect_unknown_capabilities() {
        return Bits::HID_DEVICE |
               Bits::USB_DEVICE |
               Bits::RAW_MODE |
               Bits::PASSTHROUGH_MODE |
               Bits::ENCRYPTION_SUPPORTED |
               Bits::BUFFERING_SUPPORTED;
    }
    
    inline uint64_t get_default_mode(const std::string& device_type) {
        if (device_type == "unknown") {
            return Bits::RAW_MODE;
        } else {
            return Bits::PARSED_MODE;
        }
    }
}

} // namespace Capabilities

#endif // CAPABILITY_REGISTRY_H