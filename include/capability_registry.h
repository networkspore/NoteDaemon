// include/capability_registry.h
// C++ Capability Registry matching Java CapabilityRegistry
// Updated to work with pre-serialized NoteBytes::Value constants

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
     
    constexpr int DEVICE_TYPE_KNOWN    = 32;
    constexpr int HID_DEVICE           = 33;
    constexpr int USB_DEVICE           = 34;
    constexpr int BLUETOOTH_DEVICE     = 35;
    constexpr int VIDEO_DEVICE         = 36;
    constexpr int VIDEO_STREAMING      = 37;
    constexpr int FRAME_CAPTURE        = 38;
     
    constexpr int ENCRYPTION_SUPPORTED = 40;
    constexpr int ENCRYPTION_ENABLED   = 41;
    constexpr int BUFFERING_SUPPORTED  = 42;
    constexpr int BUFFERING_ENABLED    = 43;
     
    constexpr int SCENE_LOCATION       = 48;
    constexpr int SCENE_SIZE           = 49;
    constexpr int WINDOW_LIFECYCLE     = 50;
    constexpr int STAGE_POSITION       = 51;
    constexpr int STAGE_SIZE           = 52;
    constexpr int STAGE_FOCUS          = 53;
    
    constexpr int COMPOSITE_SOURCE     = 56;
    constexpr int MULTIPLE_CHILDREN    = 57;

    // Hardware Wallet Capabilities (bits 58-59)
    constexpr int HARDWARE_WALLET      = 58;  // Ledger, Trezor, etc.
    constexpr int APDU_PROTOCOL        = 59;  // APDU-based communication
    constexpr int LEDGER_MODE          = 12;  // Ledger APDU mode (in mode range 8-15)

    // Camera Algorithm Capabilities (CPU-friendly, bits 60-67)
    constexpr int MOTION_DETECTION     = 60;
    constexpr int SCENE_CHANGE         = 61;
    constexpr int ROI_CAPTURE          = 62;
    constexpr int PRIVACY_MASKING      = 63;
    constexpr int TIMESTAMP_OVERLAY    = 64;
    constexpr int FRAME_AVERAGING      = 65;
    constexpr int BACKGROUND_SUBTRACT  = 66;
    constexpr int MOTION_VECTORS       = 67;

    const std::vector<int> MODE_BITS = {RAW_MODE, PARSED_MODE, PASSTHROUGH_MODE, FILTERED_MODE, LEDGER_MODE};
    const std::vector<int> CAMERA_ALGO_BITS = {MOTION_DETECTION, SCENE_CHANGE, ROI_CAPTURE,
        PRIVACY_MASKING, TIMESTAMP_OVERLAY, FRAME_AVERAGING, BACKGROUND_SUBTRACT, MOTION_VECTORS};
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
    /**
     * Get capability name as C string (for logging)
     */
    inline const char* get_capability_name(int bit_position) {
        switch (bit_position) {
            case Bits::KEYBOARD: return "keyboard";
            case Bits::MOUSE: return "mouse";
            case Bits::TOUCH: return "touchpad";
            case Bits::GAMEPAD: return "gamepad";
            case Bits::PEN: return "pen";
            case Bits::TOUCHPAD: return "touchpad";
            case Bits::SCROLL: return "scroll";
            
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
            case Bits::VIDEO_DEVICE: return "video_device";
            case Bits::VIDEO_STREAMING: return "video_streaming";
            case Bits::FRAME_CAPTURE: return "frame_capture";

            // Camera algorithm capabilities
            case Bits::MOTION_DETECTION: return "motion_detection";
            case Bits::SCENE_CHANGE: return "scene_change";
            case Bits::ROI_CAPTURE: return "roi_capture";
            
            // Hardware wallet capabilities
            case Bits::HARDWARE_WALLET: return "hardware_wallet";
            case Bits::APDU_PROTOCOL: return "apdu_protocol";
            case Bits::LEDGER_MODE: return "ledger_mode";
            case Bits::PRIVACY_MASKING: return "privacy_masking";
            case Bits::TIMESTAMP_OVERLAY: return "timestamp_overlay";
            case Bits::FRAME_AVERAGING: return "frame_averaging";
            case Bits::BACKGROUND_SUBTRACT: return "background_subtract";
            case Bits::MOTION_VECTORS: return "motion_vectors";

            case Bits::ENCRYPTION_SUPPORTED: return "encryption_supported";
            case Bits::ENCRYPTION_ENABLED: return "encryption_enabled";
            case Bits::BUFFERING_SUPPORTED: return "buffering_supported";
            case Bits::BUFFERING_ENABLED: return "buffering_enabled";
            
            default: return "unknown";
        }
    }
    
    /**
     * Get capability bit position from string name
     */
    inline int get_capability_bit(const std::string& name) {
        static std::map<std::string, int> name_to_bit = {
            {"keyboard", Bits::KEYBOARD},
            {"mouse", Bits::MOUSE},
            {"touchpad", Bits::TOUCH},
            {"gamepad", Bits::GAMEPAD},
            {"pen", Bits::PEN},
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
            {"video_device", Bits::VIDEO_DEVICE},
            {"video_streaming", Bits::VIDEO_STREAMING},
            {"frame_capture", Bits::FRAME_CAPTURE},

            // Camera algorithm capabilities
            {"motion_detection", Bits::MOTION_DETECTION},
            {"scene_change", Bits::SCENE_CHANGE},
            {"roi_capture", Bits::ROI_CAPTURE},
            
            // Hardware wallet capabilities
            {"hardware_wallet", Bits::HARDWARE_WALLET},
            {"apdu_protocol", Bits::APDU_PROTOCOL},
            {"ledger_mode", Bits::LEDGER_MODE},
            {"privacy_masking", Bits::PRIVACY_MASKING},
            {"timestamp_overlay", Bits::TIMESTAMP_OVERLAY},
            {"frame_averaging", Bits::FRAME_AVERAGING},
            {"background_subtract", Bits::BACKGROUND_SUBTRACT},
            {"motion_vectors", Bits::MOTION_VECTORS},

            {"encryption_supported", Bits::ENCRYPTION_SUPPORTED},
            {"encryption_enabled", Bits::ENCRYPTION_ENABLED},
            {"buffering_supported", Bits::BUFFERING_SUPPORTED},
            {"buffering_enabled", Bits::BUFFERING_ENABLED},
        };
        
        auto it = name_to_bit.find(name);
        return (it != name_to_bit.end()) ? it->second : -1;
    }
    
    /**
     * Get pre-serialized NoteBytes::Value for a capability
     * Useful for protocol messages
     */
    inline const NoteBytes::Value& get_capability_value(int bit_position) {
        switch (bit_position) {
            case Bits::KEYBOARD: return NoteMessaging::ItemTypes::KEYBOARD;
            case Bits::MOUSE: return NoteMessaging::ItemTypes::MOUSE;
            case Bits::TOUCH: return NoteMessaging::ItemTypes::TOUCHPAD;
            case Bits::GAMEPAD: return NoteMessaging::ItemTypes::GAMEPAD;
            case Bits::PEN: return NoteMessaging::ItemTypes::PEN;
            case Bits::TOUCHPAD: return NoteMessaging::ItemTypes::TOUCHPAD;
            case Bits::SCROLL: return NoteMessaging::ItemTypes::SCROLL;
            
            case Bits::RAW_MODE: return NoteMessaging::Modes::RAW;
            case Bits::PARSED_MODE: return NoteMessaging::Modes::PARSED;
            case Bits::PASSTHROUGH_MODE: return NoteMessaging::Modes::PASSTHROUGH;
            case Bits::FILTERED_MODE: return NoteMessaging::Modes::FILTERED;
            
            default: return NoteMessaging::ItemTypes::UNKNOWN;
        }
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
        cpp_int masked_state = state & mode_mask;
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

    inline bool validate_mode_compatibility(const std::string& device_type, 
                                           const std::string& requested_mode) {
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

    inline cpp_int detect_camera_capabilities() {
        cpp_int caps = 0;
        State::bit_set(caps, Bits::USB_DEVICE);
        State::bit_set(caps, Bits::VIDEO_DEVICE);
        State::bit_set(caps, Bits::VIDEO_STREAMING);
        State::bit_set(caps, Bits::FRAME_CAPTURE);
        State::bit_set(caps, Bits::DEVICE_TYPE_KNOWN);
        State::bit_set(caps, Bits::RAW_MODE);
        State::bit_set(caps, Bits::PASSTHROUGH_MODE);
        State::bit_set(caps, Bits::ENCRYPTION_SUPPORTED);
        State::bit_set(caps, Bits::BUFFERING_SUPPORTED);
        // CPU-friendly algorithm capabilities
        State::bit_set(caps, Bits::MOTION_DETECTION);
        State::bit_set(caps, Bits::SCENE_CHANGE);
        State::bit_set(caps, Bits::ROI_CAPTURE);
        State::bit_set(caps, Bits::PRIVACY_MASKING);
        State::bit_set(caps, Bits::TIMESTAMP_OVERLAY);
        return caps;
    }
    
    /**
     * Detect capabilities for Ledger hardware wallet devices
     */
    inline cpp_int detect_ledger_capabilities() {
        cpp_int caps = 0;
        State::bit_set(caps, Bits::HARDWARE_WALLET);
        State::bit_set(caps, Bits::APDU_PROTOCOL);
        State::bit_set(caps, Bits::LEDGER_MODE);
        State::bit_set(caps, Bits::DEVICE_TYPE_KNOWN);
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
