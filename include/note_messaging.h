// include/note_messaging.h
// Messaging constants as pre-serialized NoteBytes::Value objects
// Matching Java NoteMessaging.java

#ifndef MESSAGING_H
#define MESSAGING_H

#include <map>
#include "notebytes.h"

namespace NoteMessaging {

    // =============================================================================
    // PROTOCOL MESSAGES - Pre-serialized command strings
    // =============================================================================
    namespace ProtocolMessages {
        // Connection Lifecycle
        inline const NoteBytes::Value HELLO("hello");
        inline const NoteBytes::Value READY("ready");
        inline const NoteBytes::Value ACCEPT("accept");
        inline const NoteBytes::Value PING("ping");
        inline const NoteBytes::Value PONG("pong");
        inline const NoteBytes::Value SHUTDOWN("shutdown");
        inline const NoteBytes::Value DISCONNECTED("disconnected");
        
        // Discovery Phase
        inline const NoteBytes::Value REQUEST_DISCOVERY("request_discovery");
        inline const NoteBytes::Value ITEM_LIST("item_list");
        inline const NoteBytes::Value GET_ITEM_INFO("get_item_info");
        inline const NoteBytes::Value ITEM_INFO("item_info");
        inline const NoteBytes::Value GET_CAPABILITIES("get_capabilities");
        
        // Claim Phase
        inline const NoteBytes::Value CLAIM_ITEM("claim_item");
        inline const NoteBytes::Value ITEM_CLAIMED("item_claimed");
        inline const NoteBytes::Value RELEASE_ITEM("release_item");
        inline const NoteBytes::Value ITEM_RELEASED("item_released");
        
        // Configuration Phase
        inline const NoteBytes::Value SET_MODE("set_mode");
        inline const NoteBytes::Value SET_FILTER("set_filter");
        inline const NoteBytes::Value ENABLE_FEATURE("enable_feature");
        inline const NoteBytes::Value DISABLE_FEATURE("disable_feature");
        
        // Streaming Control
        inline const NoteBytes::Value START_STREAM("start_stream");
        inline const NoteBytes::Value STOP_STREAM("stop_stream");
        inline const NoteBytes::Value PAUSE_ITEM("pause_item");
        inline const NoteBytes::Value RESUME_ITEM("resume_item");
        
        inline const NoteBytes::Value DEVICE_DISCONNECTED("device_disconnected");
        inline const NoteBytes::Value RESUME("resume");
        inline const NoteBytes::Value DEVICE_ATTACHED("device_attached");
        inline const NoteBytes::Value DEVICE_DETACHED("device_detached");

        // Encryption Lifecycle
        inline const NoteBytes::Value ENABLE_ENCRYPTION("enable_encryption");
        inline const NoteBytes::Value DISABLE_ENCRYPTION("disable_encryption");
        inline const NoteBytes::Value ENCRYPTION_READY("encryption_ready");
        
        // Status Messages
        inline const NoteBytes::Value ERROR("error");
        inline const NoteBytes::Value SUCCESS("success");
        inline const NoteBytes::Value FAILED("failed");
        inline const NoteBytes::Value PROGRESS("progress");
        inline const NoteBytes::Value INFO("info");

        
        // State Changes
        inline const NoteBytes::Value STARTED("started");
        inline const NoteBytes::Value STOPPED("stopped");
        inline const NoteBytes::Value UPDATED("updated");
        inline const NoteBytes::Value AVAILABLE_MSG("available");
        inline const NoteBytes::Value UNAVAILABLE("unavailable");
        inline const NoteBytes::Value TIMED_OUT("timed_out");
    }

    // =============================================================================
    // MESSAGE KEYS - Pre-serialized field names
    // =============================================================================
    namespace Keys {
        // Identity & Routing
        inline const NoteBytes::Value EMPTY("");
        inline const NoteBytes::Value UUID_128("uuid_128");
        inline const NoteBytes::Value DEVICE_ID("device_id");
        inline const NoteBytes::Value ID("id");
        inline const NoteBytes::Value EVENT("event");
        inline const NoteBytes::Value CONTROL("control");
        inline const NoteBytes::Value SEQUENCE("seq_id");
        inline const NoteBytes::Value SESSION_ID("session_id");
        inline const NoteBytes::Value PID("pid");
        inline const NoteBytes::Value RECEIVER_ID("receiver_id");
        inline const NoteBytes::Value SENDER_ID("sender_id");
        inline const NoteBytes::Value CODE_KEY("code");
        inline const NoteBytes::Value CURRENT_MODE("current_mode");
        inline const NoteBytes::Value STATE_TYPE("state_type");
        inline const NoteBytes::Value IV("iv");
        inline const NoteBytes::Value CORRELATION_ID("correlationId");
        
        // Metadata
        inline const NoteBytes::Value NAME("name");
        inline const NoteBytes::Value TIMESTAMP("time_stamp");
        inline const NoteBytes::Value VERSION("version");
        
        // Payload
        inline const NoteBytes::Value PAYLOAD("payload");
        inline const NoteBytes::Value STATE_FLAGS("state_flags");
        inline const NoteBytes::Value CMD("cmd");
        
        // Status & Results
        inline const NoteBytes::Value STATUS("status");
        inline const NoteBytes::Value ERROR_CODE("error");
        inline const NoteBytes::Value MSG("msg");
        inline const NoteBytes::Value RESULT("result");
        inline const NoteBytes::Value WARNING("warning");
        inline const NoteBytes::Value EXCEPTION("exception");
        inline const NoteBytes::Value AVAILABLE("available");
        
        // Items (Generic resource term)
        inline const NoteBytes::Value ITEM("item");
        inline const NoteBytes::Value ITEMS("items");
        inline const NoteBytes::Value ITEM_TYPE("item_type");
        inline const NoteBytes::Value ITEM_COUNT("item_count");
        inline const NoteBytes::Value ITEM_PATH("item_path");
        inline const NoteBytes::Value ITEM_CLASS("item_class");
        inline const NoteBytes::Value ITEM_SUBCLASS("item_subclass");
        inline const NoteBytes::Value ITEM_PROTOCOL("item_protocol");
        inline const NoteBytes::Value ITEM_ADDRESS("item_address");
        
        inline const NoteBytes::Value VENDOR_ID("vendor_id");
        inline const NoteBytes::Value PRODUCT_ID("product_id");
        inline const NoteBytes::Value BUS_NUMBER("bus_number");
        inline const NoteBytes::Value MANUFACTURER("manufacturer");
        inline const NoteBytes::Value PRODUCT("product");
        inline const NoteBytes::Value SERIAL_NUMBER("serial_number");
        inline const NoteBytes::Value KERNEL_DRIVER_ATTACHED("kernel_driver_attached");
        inline const NoteBytes::Value INTERFACE_NUMBER( "interface_number");
        
        // Capabilities
        inline const NoteBytes::Value MODE("mode");
        inline const NoteBytes::Value AVAILABLE_CAPABILITIES("available_capabilities");
        inline const NoteBytes::Value CLAIMED_ITEMS("claimedItems");
        inline const NoteBytes::Value ENABLED_CAPABILITIES("enabled_capabilities");
        inline const NoteBytes::Value CAPABILITY_NAMES("capability_names");
        inline const NoteBytes::Value AVAILABLE_MODES("available_modes");
        inline const NoteBytes::Value DEFAULT_MODE("default_mode");
        inline const NoteBytes::Value CONSTRAINTS("constraints");
        inline const NoteBytes::Value CHILDREN("children");
        
        // Encryption
        inline const NoteBytes::Value ENCRYPTION("encryption");
        inline const NoteBytes::Value CIPHER("cipher");
        inline const NoteBytes::Value PHASE("phase");
        inline const NoteBytes::Value PUBLIC_KEY("pub_key");
        inline const NoteBytes::Value AES_IV("aes_iv");
        
        // Flow Control
        inline const NoteBytes::Value PROCESSED_COUNT("processed_count");
        inline const NoteBytes::Value TOTAL("total");
        inline const NoteBytes::Value COMPLETED("completed");
        
        inline const NoteBytes::Value SCOPE("scope");
        inline const NoteBytes::Value STATE("state");

          
        inline const NoteBytes::Value MESSAGES_SENT("messages_sent");
        inline const NoteBytes::Value MESSAGES_ACKED("messages_acked");
        inline const NoteBytes::Value MISSED_PONGS("missed_pongs");
        inline const NoteBytes::Value LAST_PING_SENT("last_ping_sent");
        inline const NoteBytes::Value LAST_PONG_RECEIVED("last_pong_received");
        inline const NoteBytes::Value PENDING_EVENTS("pending_events");
        inline const NoteBytes::Value EVENTS_SENT("events_sent");
        inline const NoteBytes::Value EVENTS_DROPPED("events_dropped");
        
    }

    // =============================================================================
    // ITEM TYPES - Pre-serialized resource types
    // =============================================================================
    namespace ItemTypes {
        // USB Device Types
        inline const NoteBytes::Value KEYBOARD("keyboard");
        inline const NoteBytes::Value MOUSE("mouse");
        inline const NoteBytes::Value GAMEPAD("gamepad");
        inline const NoteBytes::Value TOUCHPAD("touchpad");
        inline const NoteBytes::Value UNKNOWN("unknown");
        inline const NoteBytes::Value PEN("pen");
        inline const NoteBytes::Value SCROLL("scroll");
        
        // Window Types (for future use)
        inline const NoteBytes::Value WINDOW("window");
        inline const NoteBytes::Value SCENE("scene");
        inline const NoteBytes::Value STAGE("stage");
        
        // Network Types (for future use)
        inline const NoteBytes::Value PEER("peer");
        inline const NoteBytes::Value ENDPOINT("endpoint");
    }

    // =============================================================================
    // MODES - Pre-serialized operating modes
    // =============================================================================
    namespace Modes {
        inline const NoteBytes::Value RAW("raw");
        inline const NoteBytes::Value PARSED("parsed");
        inline const NoteBytes::Value PASSTHROUGH("passthrough");
        inline const NoteBytes::Value FILTERED("filtered");
        inline const NoteBytes::Value UNKNOWN("unknown");
        inline const NoteBytes::Value NONE("none");
    }

    // =============================================================================
    // ERROR CODES - Standardized error codes (keep as integers)
    // =============================================================================
    namespace ErrorCodes {
        // General errors (0-9)
        constexpr int UNKNOWN               = 0;
        constexpr int PARSE_ERROR           = 1;
        constexpr int INVALID_MESSAGE       = 2;
        constexpr int TIMEOUT               = 3;
        constexpr int INTERRUPTED           = 4;
        
        // Resource errors (10-19)
        constexpr int ITEM_NOT_FOUND        = 10;
        constexpr int ITEM_NOT_AVAILABLE    = 11;
        constexpr int MODE_INCOMPATIBLE     = 12;
        constexpr int MODE_NOT_SUPPORTED    = 13;
        constexpr int FEATURE_NOT_SUPPORTED = 14;
        constexpr int CLAIM_FAILED          = 15;
        
        // Permission errors (20-29)
        constexpr int PERMISSION_DENIED     = 20;
        constexpr int UNAUTHORIZED          = 21;
        constexpr int PID_MISMATCH          = 22;
        constexpr int ALREADY_CLAIMED       = 23;
        
        // State errors (30-39)
        constexpr int INVALID_STATE         = 30;
        constexpr int NOT_CLAIMED           = 31;
        constexpr int NOT_STREAMING         = 32;
        constexpr int ALREADY_STREAMING     = 33;
        
        // Protocol errors (40-49)
        constexpr int PROTOCOL_ERROR        = 40;
        constexpr int VERSION_MISMATCH      = 41;
        constexpr int HANDSHAKE_FAILED      = 42;
        
        // Encryption errors (50-59)
        constexpr int ENCRYPTION_FAILED     = 50;
        constexpr int DECRYPTION_FAILED     = 51;
        constexpr int KEY_EXCHANGE_FAILED   = 52;
    }

    // =============================================================================
    // STATUS VALUES - Pre-serialized status strings
    // =============================================================================
    namespace Status {
        inline const NoteBytes::Value OK("ok");
        inline const NoteBytes::Value READY("ready");
        inline const NoteBytes::Value PENDING("pending");
        inline const NoteBytes::Value PROCESSING("processing");
        inline const NoteBytes::Value COMPLETE("complete");
        inline const NoteBytes::Value FAILED("failed");
        inline const NoteBytes::Value CANCELLED("cancelled");
        inline const NoteBytes::Value ACTIVE("active");
    }

    // =============================================================================
    // HELPER FUNCTIONS
    // =============================================================================

    /**
     * Check if a NoteBytes::Value matches a protocol constant
     * Uses optimized equality (hash-based)
     */
    inline bool is_message(const NoteBytes::Value& value, const NoteBytes::Value& constant) {
        return value == constant;
    }

    /**
     * Get error message for error code
     */
    inline const char* get_error_message(int error_code) {
        static const std::map<int, const char*> error_messages = {
            {ErrorCodes::UNKNOWN, "Unknown error"},
            {ErrorCodes::PARSE_ERROR, "Parse error"},
            {ErrorCodes::INVALID_MESSAGE, "Invalid message"},
            {ErrorCodes::ITEM_NOT_FOUND, "Item not found"},
            {ErrorCodes::ITEM_NOT_AVAILABLE, "Item not available"},
            {ErrorCodes::MODE_INCOMPATIBLE, "Mode not compatible"},
            {ErrorCodes::MODE_NOT_SUPPORTED, "Mode not supported"},
            {ErrorCodes::PERMISSION_DENIED, "Permission denied"},
            {ErrorCodes::UNAUTHORIZED, "Unauthorized"},
            {ErrorCodes::PID_MISMATCH, "PID mismatch"},
            {ErrorCodes::CLAIM_FAILED, "Failed to claim item"},
            {ErrorCodes::ENCRYPTION_FAILED, "Encryption failed"},
            {ErrorCodes::DECRYPTION_FAILED, "Decryption failed"},
            {ErrorCodes::KEY_EXCHANGE_FAILED, "Key exchange failed"},
        };
        
        auto it = error_messages.find(error_code);
        return (it != error_messages.end()) ? it->second : "Unknown error";
    }
}

#endif // MESSAGING_H