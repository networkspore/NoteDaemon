// include/Messaging.h
// Messaging constants matching Java NoteMessaging.java

#ifndef MESSAGING_H
#define MESSAGING_H

#include <cstdint>
#include <map>
#include <string>

namespace NoteMessaging{


    // =============================================================================
    // PROTOCOL MESSAGES - Standardized command strings
    // =============================================================================
    namespace ProtocolMessages {
        // Connection Lifecycle
        constexpr const char* HELLO         = "hello";        // Initial handshake
        constexpr const char* READY         = "ready";        // Server ready
        constexpr const char* ACCEPT        = "accept";       // Operation accepted
        constexpr const char* PING          = "ping";         // Heartbeat ping
        constexpr const char* PONG          = "pong";         // Heartbeat pong
        constexpr const char* SHUTDOWN      = "shutdown";     // Graceful shutdown
        constexpr const char* DISCONNECTED  = "disconnected"; // Disconnect event
        
        // Discovery Phase
        constexpr const char* REQUEST_DISCOVERY = "request_discovery"; // Request list
        constexpr const char* ITEM_LIST         = "item_list";         // Item list response
        constexpr const char* GET_ITEM_INFO     = "get_item_info";     // Request details
        constexpr const char* ITEM_INFO         = "item_info";         // Item details response
        constexpr const char* GET_CAPABILITIES  = "get_capabilities";  // Request caps
        
        // Claim Phase
        constexpr const char* CLAIM_ITEM    = "claim_item";    // Claim resource
        constexpr const char* ITEM_CLAIMED  = "item_claimed";  // Claim confirmed
        constexpr const char* RELEASE_ITEM  = "release_item";  // Release resource
        constexpr const char* ITEM_RELEASED = "item_released"; // Release confirmed
        
        // Configuration Phase
        constexpr const char* SET_MODE      = "set_mode";      // Change mode
        constexpr const char* SET_FILTER    = "set_filter";    // Apply filter
        constexpr const char* ENABLE_FEATURE  = "enable_feature";  // Enable feature
        constexpr const char* DISABLE_FEATURE = "disable_feature"; // Disable feature
        
        // Streaming Control
        constexpr const char* START_STREAM  = "start_stream";  // Begin streaming
        constexpr const char* STOP_STREAM   = "stop_stream";   // Stop streaming
        constexpr const char* PAUSE_ITEM    = "pause_item";    // Pause streaming
        constexpr const char* RESUME_ITEM   = "resume_item";   // Resume streaming
        constexpr const char* RESUME        = "resume";        // Client ready (ack)
        
        // Encryption Lifecycle
        constexpr const char* ENABLE_ENCRYPTION  = "enable_encryption";  // Start encryption
        constexpr const char* DISABLE_ENCRYPTION = "disable_encryption"; // Stop encryption
        constexpr const char* ENCRYPTION_READY   = "encryption_ready";   // Encryption active
        
        // Status Messages
        constexpr const char* ERROR         = "error";         // Error occurred
        constexpr const char* SUCCESS       = "success";       // Operation succeeded
        constexpr const char* FAILED        = "failed";        // Operation failed
        constexpr const char* PROGRESS      = "progress";      // Progress update
        constexpr const char* INFO          = "info";          // Information
        
        // State Changes
        constexpr const char* STARTED       = "started";       // Started
        constexpr const char* STOPPED       = "stopped";       // Stopped
        constexpr const char* UPDATED       = "updated";       // Updated
        constexpr const char* AVAILABLE_MSG = "available";     // Now available
        constexpr const char* UNAVAILABLE   = "unavailable";   // Now unavailable
        constexpr const char* TIMED_OUT     = "timed_out";     // Timeout occurred
    }

    
    // =============================================================================
    // MESSAGE KEYS - Standardized field names
    // =============================================================================

    namespace Keys {
        // Identity & Routing
        constexpr const char* UUID_128      = "uuid_128";
        // Identity & Routing
        constexpr const char* DEVICE_ID     = "device_id";
        constexpr const char* ID            = "id";
        constexpr const char* EVENT          = "event";
        constexpr const char* SEQUENCE      = "seq_id";
        constexpr const char* SESSION_ID    = "session_id";
        constexpr const char* PID           = "pid";
        constexpr const char* RECEIVER_ID   = "receiver_id";
        constexpr const char* SENDER_ID     = "sender_id";
        constexpr const char* CODE_KEY      = "code";
        constexpr const char* CURRENT_MODE  = "current_mode";
        constexpr const char* STATE_TYPE    = "state_type";
        constexpr const char* IV            = "iv";
        // Metadata
        constexpr const char* NAME          = "name";
        constexpr const char* TIMESTAMP     = "time_stamp";
        constexpr const char* VERSION       = "version";
        
        // Payload
        constexpr const char* PAYLOAD       = "payload";
        constexpr const char* STATE_FLAGS   = "state_flags";
        constexpr const char* CMD           = "cmd";
        
        // Status & Results
        constexpr const char* STATUS        = "status";
        constexpr const char* ERROR_CODE    = "error";
        constexpr const char* MSG           = "msg";
        constexpr const char* RESULT        = "result";
        constexpr const char* WARNING       = "warning";
        constexpr const char* EXCEPTION     = "exception";
        constexpr const char* AVAILABLE     = "available";

        // Items (Generic resource term)
        constexpr const char* ITEM          = "item";
        constexpr const char* ITEMS         = "items";
        constexpr const char* ITEM_TYPE     = "item_type";
        constexpr const char* ITEM_COUNT    = "item_count";
        constexpr const char* ITEM_PATH     = "item_path";
        constexpr const char* ITEM_CLASS        = "item_class";
        constexpr const char* ITEM_SUBCLASS     = "item_subclass";
        constexpr const char* ITEM_PROTOCOL     = "item_protocol";
        constexpr const char* ITEM_ADDRESS      = "item_address";
       
        constexpr const char* VENDOR_ID         = "vendor_id";
        constexpr const char* PRODUCT_ID        = "product_id";
        constexpr const char* BUS_NUMBER        = "bus_number";
        constexpr const char* MANUFACTURER      = "manufacturer";
        constexpr const char* PRODUCT           = "product";
        constexpr const char* SERIAL_NUMBER     = "serial_number";
        constexpr const char* KERNEL_DRIVER_ATTACHED    = "kernel_driver_attached";
        // Capabilities
        constexpr const char* MODE                      = "mode";
        constexpr const char* AVAILABLE_CAPABILITIES    = "available_capabilities";        
        constexpr const char* CLAIMED_ITEMS             = "claimedItems";
        constexpr const char* ENABLED_CAPABILITIES      = "enabled_capabilities";
        constexpr const char* CAPABILITY_NAMES          = "capability_names";
        constexpr const char* AVAILABLE_MODES           = "available_modes";

        
        constexpr const char* DEFAULT_MODE      = "default_mode";
        constexpr const char* CONSTRAINTS       = "constraints";
        constexpr const char* CHILDREN          = "children";
        
        // Encryption
        constexpr const char* ENCRYPTION    = "encryption";
        constexpr const char* CIPHER        = "cipher";
        constexpr const char* PHASE         = "phase";
        constexpr const char* PUBLIC_KEY    = "pub_key";
        constexpr const char* AES_IV        = "aes_iv";
        
        // Flow Control
        constexpr const char* PROCESSED_COUNT = "processed_count";
        constexpr const char* TOTAL           = "total";
        constexpr const char* COMPLETED       = "completed";

        constexpr const char* SCOPE         = "scope";
        constexpr const char* STATE         = "state";
    }

    // =============================================================================
    // ITEM TYPES - Generic resource types (context-specific)
    // =============================================================================
    namespace ItemTypes {
        // USB Device Types
        constexpr const char* KEYBOARD  = "keyboard";
        constexpr const char* MOUSE     = "mouse";
        constexpr const char* GAMEPAD   = "gamepad";
        constexpr const char* TOUCHPAD  = "touchpad";
        constexpr const char* UNKNOWN   = "unknown";
        constexpr const char* PEN       = "pen";
        constexpr const char* SCROLL    = "scroll";
        
        // Window Types (for future use)
        constexpr const char* WINDOW    = "window";
        constexpr const char* SCENE     = "scene";
        constexpr const char* STAGE     = "stage";
        
        // Network Types (for future use)
        constexpr const char* PEER      = "peer";
        constexpr const char* ENDPOINT  = "endpoint";
    }

    // =============================================================================
    // MODES - Operating modes for items
    // =============================================================================
    namespace Modes {
        constexpr const char* RAW           = "raw";           // Raw data
        constexpr const char* PARSED        = "parsed";        // Parsed events
        constexpr const char* PASSTHROUGH   = "passthrough";   // OS passthrough
        constexpr const char* FILTERED      = "filtered";      // With filters
        constexpr const char* UNKNOWN       = ItemTypes::UNKNOWN;
        constexpr const char* NONE          = "none";
    }

    // =============================================================================
    // ERROR CODES - Standardized error codes
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
    // STATUS VALUES - Common status strings
    // =============================================================================
    namespace Status {
        constexpr const char* OK            = "ok";
        constexpr const char* READY         = "ready";
        constexpr const char* PENDING       = "pending";
        constexpr const char* PROCESSING    = "processing";
        constexpr const char* COMPLETE      = "complete";
        constexpr const char* FAILED        = "failed";
        constexpr const char* CANCELLED     = "cancelled";
        constexpr const char* ACTIVE        = "active";
    }

    // =============================================================================
    // MESSAGE PATTERNS - Common message construction helpers
    // =============================================================================

    /**
    * Standard message structure:
    * {
    *   "type": <byte>,           // Message type
    *   "seqId": <6-byte array>,  // Sequence number
    *   "cmd": <string>,          // Command (for TYPE_CMD)
    *   ... additional fields
    * }
    */

    /**
    * Standard error structure:
    * {
    *   "type": TYPE_ERROR,
    *   "seqId": <sequence>,
    *   "error": <error_code>,
    *   "msg": <error_message>
    * }
    */

    /**
    * Standard response structure:
    * {
    *   "type": TYPE_ACCEPT,
    *   "seqId": <sequence>,
    *   "status": <status_string>
    * }
    */

    /**
    * Standard item structure:
    * {
    *   "itemId": <identifier>,
    *   "itemType": <type_string>,
    *   "name": <human_name>,
    *   "available": <bool>,
    *   "availableCaps": <capability_set>,
    *   "defaultMode": <mode_string>
    * }
    */

    /**
    * Standard claim request:
    * {
    *   "type": TYPE_CMD,
    *   "seqId": <sequence>,
    *   "cmd": "claim_item",
    *   "itemId": <identifier>,
    *   "srcId": <source_id>,
    *   "pid": <process_id>,
    *   "mode": <requested_mode>
    * }
    */

    /**
    * Standard routed event packet:
    * [INTEGER:srcId][OBJECT or ENCRYPTED:event_packet]
    * 
    * Event packet structure:
    * {
    *   "type": <event_type>,
    *   "seqId": <sequence>,
    *   "stFlags": <state_flags>,    // optional
    *   "payload": [<values>]         // optional
    * }
    */


    // =============================================================================
    // HELPER FUNCTIONS
    // =============================================================================

    /**
    * Check if a string matches a protocol message constant
    */
    inline bool is_message(const std::string& str, const char* msg) {
        return str == msg;
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
        };
        
        auto it = error_messages.find(error_code);
        return (it != error_messages.end()) ? it->second : "Unknown error";
    }
}
#endif // MESSAGING