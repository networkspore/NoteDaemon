
#ifndef FLAGS_H
#define FLAGS_H

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/fwd.hpp>
#include "bitflag_state_bigint.h"
#include "note_messaging.h"
#include "notebytes.h"
#include "capability_registry.h"

using boost::multiprecision::cpp_int;


namespace State {

    /**
    * Client state flags (matches Java ClientStateFlags)
    * Uses bit POSITIONS (0, 1, 2...) instead of shifted values
    */
    namespace ClientFlags {
        // Connection state (bits 0-7)
        constexpr int CONNECTED            = 0;
        constexpr int AUTHENTICATED        = 1;
        constexpr int DISCOVERING          = 2;
        constexpr int HAS_CLAIMED_DEVICES  = 3;
        constexpr int STREAMING            = 4;
        constexpr int PAUSED               = 5;
        constexpr int DISCONNECTING        = 6;
        constexpr int ERROR_STATE          = 7;
        
        // Capabilities (bits 8-15)
        constexpr int SUPPORTS_ENCRYPTION  = 8;
        constexpr int SUPPORTS_RAW_MODE    = 9;
        constexpr int SUPPORTS_FILTERING   = 10;
        constexpr int SUPPORTS_BATCH       = 11;
        
        // Heartbeat state (bits 16-23)
        constexpr int HEARTBEAT_ENABLED    = 16;
        constexpr int HEARTBEAT_WAITING    = 17;
        constexpr int HEARTBEAT_TIMEOUT    = 18;
        
        // Backpressure state (bits 24-31)
        constexpr int BACKPRESSURE_ACTIVE  = 24;
        constexpr int FLOW_CONTROL_PAUSED  = 25;
        constexpr int QUEUE_FULL           = 26;
        
        inline bool can_discover(const cpp_int& state) {
            return bit_test(state, AUTHENTICATED) && !bit_test(state, DISCONNECTING);
        }
        
        inline bool can_claim(const cpp_int& state) {
            return bit_test(state, AUTHENTICATED) && !bit_test(state, DISCONNECTING);
        }
        
        inline bool can_stream(const cpp_int& state) {
            return bit_test(state, HAS_CLAIMED_DEVICES) &&
                !bit_test(state, PAUSED) &&
                !bit_test(state, BACKPRESSURE_ACTIVE) &&
                !bit_test(state, DISCONNECTING);
        }
        
        inline bool is_heartbeat_healthy(const cpp_int& state) {
            return bit_test(state, HEARTBEAT_ENABLED) && !bit_test(state, HEARTBEAT_TIMEOUT);
        }
    }


    
    /**
    * Device state flags (matches Java DeviceStateFlags)
    * Uses bit POSITIONS
    */
    namespace DeviceFlags {
        // Claim state (bits 0-7)
        constexpr int CLAIMED              = 0;
        constexpr int KERNEL_DETACHED      = 1;
        constexpr int INTERFACE_CLAIMED    = 2;
        constexpr int EXCLUSIVE_ACCESS     = 3;
        
        // Configuration state (bits 8-15)
        constexpr int ENCRYPTION_ENABLED   = 8;
        constexpr int FILTER_ENABLED       = 9;
        constexpr int RAW_MODE             = 10;
        constexpr int PARSED_MODE          = 11;
        constexpr int PASSTHROUGH_MODE     = 12;
        
        // Streaming state (bits 16-23)
        constexpr int STREAMING            = 16;
        constexpr int PAUSED               = 17;
        constexpr int BACKPRESSURE_ACTIVE  = 18;
        constexpr int EVENT_BUFFERING      = 19;
        
        // Error state (bits 24-31)
        constexpr int DEVICE_ERROR         = 24;
        constexpr int TRANSFER_ERROR       = 25;
        constexpr int DISCONNECTED         = 26;
        constexpr int STALE                = 27;

        // Mode mask (all mutually exclusive modes)
        const std::vector<int> MODE_BITS = {RAW_MODE, PARSED_MODE, PASSTHROUGH_MODE};

        namespace DeviceMasks {
            inline cpp_int mode_mask() {
                return create_mask(DeviceFlags::MODE_BITS);
            }
            
            inline cpp_int error_mask() {
                return create_range_mask(DeviceFlags::DEVICE_ERROR, DeviceFlags::STALE);
            }
            
            inline cpp_int streaming_mask() {
                return create_range_mask(DeviceFlags::STREAMING, DeviceFlags::EVENT_BUFFERING);
            }
        }
        inline std::string get_mode_name(const cpp_int& state) {
            if (bit_test(state, RAW_MODE)) return "raw";
            if (bit_test(state, PARSED_MODE)) return "parsed";
            if (bit_test(state, PASSTHROUGH_MODE)) return "passthrough";
            return "unknown";
        }

       
        inline bool has_any_errors(const cpp_int& state) {
           cpp_int error_mask = DeviceMasks::error_mask();
            return has_any_bits(state, error_mask);
        }
        
        inline bool is_streaming_active(const cpp_int& state) {
            return bit_test(state, STREAMING) && 
                !bit_test(state, PAUSED) &&
                !bit_test(state, BACKPRESSURE_ACTIVE);
        }
    }

    


    /**
    * Client session state (C++ version)
    */
    struct ClientSession {
        std::string session_id;
        pid_t client_pid;
        BitFlagStateMachine state;
        
        // Heartbeat tracking
        uint64_t last_ping_sent = 0;
        uint64_t last_pong_received = 0;
        std::atomic<int> missed_pongs{0};
        
        // Backpressure tracking
        std::atomic<int> messages_sent{0};
        std::atomic<int> messages_acknowledged{0};
        
        // Configuration
        int max_unacknowledged_messages = 100;
        uint64_t heartbeat_interval_ms = 5000;
        uint64_t heartbeat_timeout_ms = 15000;
        
        ClientSession(const std::string& id, pid_t pid)
            : session_id(id), client_pid(pid), state("client-" + id) {
            setup_transitions();
        }
        
        void setup_transitions() {
            // When authenticated, enable heartbeat
            state.on_flag_added(ClientFlags::AUTHENTICATED, [this](cpp_int, cpp_int) {
                state.add_flag(ClientFlags::HEARTBEAT_ENABLED);
            });
            
            // When backpressure activates, pause streaming
            state.on_flag_added(ClientFlags::BACKPRESSURE_ACTIVE, [this](cpp_int, cpp_int) {
                state.add_flag(ClientFlags::FLOW_CONTROL_PAUSED);
                syslog(LOG_WARNING, "Backpressure activated for client %s", session_id.c_str());
            });
            
            // When heartbeat times out, mark error
            state.on_flag_added(ClientFlags::HEARTBEAT_TIMEOUT, [this](cpp_int, cpp_int) {
                state.add_flag(ClientFlags::ERROR_STATE);
                syslog(LOG_ERR, "Heartbeat timeout for client %s", session_id.c_str());
            });
        }
        
        bool should_apply_backpressure() {
            int sent = messages_sent.load();
            int acked = messages_acknowledged.load();
            int unacked = sent - acked;
            
            if (unacked >= max_unacknowledged_messages) {
                state.add_flag(ClientFlags::BACKPRESSURE_ACTIVE);
                return true;
            }
            
            return false;
        }
        
        void message_sent() {
            messages_sent.fetch_add(1);
            should_apply_backpressure();
        }
        
        void messages_acked(int count) {
            messages_acknowledged.fetch_add(count);
            
            int sent = messages_sent.load();
            int acked = messages_acknowledged.load();
            int unacked = sent - acked;
            
            if (unacked < max_unacknowledged_messages / 2) {
                state.remove_flag(ClientFlags::BACKPRESSURE_ACTIVE);
                state.remove_flag(ClientFlags::FLOW_CONTROL_PAUSED);
            }
        }
        
        bool check_heartbeat() {
            if (!state.has_flag(ClientFlags::HEARTBEAT_ENABLED)) {
                return true;
            }
            
            uint64_t now = get_time_ms();
            
            if (state.has_flag(ClientFlags::HEARTBEAT_WAITING)) {
                uint64_t time_since_ping = now - last_ping_sent;
                
                if (time_since_ping > heartbeat_timeout_ms) {
                    int missed = missed_pongs.fetch_add(1) + 1;
                    
                    if (missed >= 3) {
                        state.add_flag(ClientFlags::HEARTBEAT_TIMEOUT);
                        return false;
                    }
                }
            }
            
            return true;
        }
        
        void send_ping() {
            last_ping_sent = get_time_ms();
            state.add_flag(ClientFlags::HEARTBEAT_WAITING);
        }
        
        void received_pong() {
            last_pong_received = get_time_ms();
            state.remove_flag(ClientFlags::HEARTBEAT_WAITING);
            missed_pongs.store(0);
        }
        
    private:
        static uint64_t get_time_ms() {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }
    };

    /**
    * Device state (with capabilities)
    */
    struct DeviceState {
        std::string device_id;
        int32_t source_id;
        pid_t owner_pid;
        BitFlagStateMachine state;
        
        // Capability tracking
        cpp_int available_capabilities;
        cpp_int enabled_capabilities;
        std::string device_type;
        
        // Hardware metadata (stored as native types, not strings)
        struct HardwareInfo {
            int vendor_id = 0;
            int product_id = 0;
            std::string manufacturer;
            std::string product;
            std::string serial_number;
            int bus_number = 0;
            int device_address = 0;
            
            // Convert to NoteBytes::Object for protocol transmission
            NoteBytes::Object to_notebytes() const {
                NoteBytes::Object obj;
                obj.add(NoteMessaging::Keys::VENDOR_ID, vendor_id);
                obj.add(NoteMessaging::Keys::PRODUCT_ID, product_id);
                if (!manufacturer.empty()) obj.add(NoteMessaging::Keys::MANUFACTURER, manufacturer);
                if (!product.empty()) obj.add(NoteMessaging::Keys::PRODUCT, product);
                if (!serial_number.empty()) obj.add(NoteMessaging::Keys::SERIAL_NUMBER, serial_number);
                obj.add(NoteMessaging::Keys::BUS_NUMBER, bus_number);
                obj.add(NoteMessaging::Keys::ITEM_ADDRESS, device_address);
                return obj;
            }
        } hardware_info;
        
        // Backpressure tracking
        std::atomic<int> pending_events{0};
        std::atomic<uint64_t> events_sent{0};
        std::atomic<uint64_t> events_dropped{0};
        uint64_t last_event_time = 0;
        
        // Queueing primitives
        std::mutex queue_mutex;
        std::condition_variable queue_cv;
        
        DeviceState(const std::string& id, int32_t sid, pid_t pid,
                const std::string& dev_type, const cpp_int& avail_caps)
            : device_id(id), source_id(sid), owner_pid(pid), 
            state(id),
            available_capabilities(avail_caps),
            enabled_capabilities(0),
            device_type(dev_type) {
            setup_transitions();
        }
        
        void setup_transitions() {
            // When claimed, mark as streaming
            state.on_flag_added(DeviceFlags::CLAIMED, [this](cpp_int, cpp_int) {
                state.add_flag(DeviceFlags::STREAMING);
            });
            
            // When backpressure activates, enable buffering
            state.on_flag_added(DeviceFlags::BACKPRESSURE_ACTIVE, [this](cpp_int, cpp_int) {
                state.add_flag(DeviceFlags::EVENT_BUFFERING);
                syslog(LOG_WARNING, "Backpressure on device %s", device_id.c_str());
            });
            
            // When paused, stop streaming
            state.on_flag_added(DeviceFlags::PAUSED, [this](cpp_int, cpp_int) {
                state.remove_flag(DeviceFlags::STREAMING);
            });
            
            // When disconnected, disable all capabilities
            state.on_flag_added(DeviceFlags::DISCONNECTED, [this](cpp_int, cpp_int) {
                state.add_flag(DeviceFlags::DEVICE_ERROR);
                state.remove_flag(DeviceFlags::STREAMING);
                enabled_capabilities = 0;
            });
        }
        
        bool enable_mode(int mode_bit) {
            if (!bit_test(available_capabilities, mode_bit)) {
                return false;
            }
            
            // Disable all other modes using mask
            cpp_int mode_mask = Capabilities::Masks::mode_mask();
            clear_mask(enabled_capabilities, mode_mask);
            
            // Enable the requested mode
            bit_set(enabled_capabilities, mode_bit);
            return true;
        }
        
        bool enable_mode(const std::string& mode_name) {
            int mode = Capabilities::Names::get_capability_bit(mode_name);
            if (mode < 0) {
                return false;
            }
            return enable_mode(mode);
        }
        
        int get_current_mode_bit() const {
            return Capabilities::Validation::get_enabled_mode(enabled_capabilities);
        }

        bool has_capability(int bit_position) const {
            return bit_test(enabled_capabilities, bit_position);
        }
        
        bool has_any_capabilities(const cpp_int& mask) const {
            return has_any_bits(enabled_capabilities, mask);
        }
        
        bool has_all_capabilities(const cpp_int& mask) const {
            return has_all_bits(enabled_capabilities, mask);
        }
        
        cpp_int get_capabilities_in_range(int start_bit, int end_bit) const {
            cpp_int range_mask = create_range_mask(start_bit, end_bit);
            return apply_mask(enabled_capabilities, range_mask);
        }
        
        void event_queued() {
            pending_events.fetch_add(1);
            events_sent.fetch_add(1);
        }
        
        void event_delivered() {
            int pending = pending_events.fetch_sub(1) - 1;
            
            if (pending < 50) {
                state.remove_flag(DeviceFlags::BACKPRESSURE_ACTIVE);
                state.remove_flag(DeviceFlags::EVENT_BUFFERING);
            }
        }
        
        void release() {
            state.remove_flag(DeviceFlags::STREAMING);
            state.remove_flag(DeviceFlags::CLAIMED);
            pending_events.store(0);
            enabled_capabilities = 0;
        }
    };


    /**
    * Serialize BitFlagStateMachine to NoteBytes::Object
    */
    inline NoteBytes::Object serialize_state_machine(const BitFlagStateMachine& sm) {
        NoteBytes::Object obj;
        obj.add(NoteMessaging::Keys::ID, sm.get_id());
        obj.add(NoteMessaging::Keys::STATE, sm.get_state());
        
        return obj;
    }

    /**
    * Deserialize NoteBytes::Object to BitFlagStateMachine
    */
    inline BitFlagStateMachine deserialize_state_machine(const NoteBytes::Object& obj) {
        std::string id = obj.get_string(NoteMessaging::Keys::ID, NoteMessaging::ItemTypes::UNKNOWN);
        cpp_int state = obj.get_cpp_int(NoteMessaging::Keys::STATE);
        
        return BitFlagStateMachine(id, state);
    }

    /**
    * Serialize ClientSession state for protocol transmission
    */
    inline NoteBytes::Object serialize_client_session(const ClientSession& session) {
        NoteBytes::Object obj;
        obj.add(NoteMessaging::Keys::SESSION_ID, session.session_id);
        obj.add(NoteMessaging::Keys::PID, (int32_t)session.client_pid);
        obj.add(NoteMessaging::Keys::STATE, session.state.get_state());
        
        obj.add("messages_sent", (int32_t)session.messages_sent.load());
        obj.add("messages_acked", (int32_t)session.messages_acknowledged.load());
        obj.add("missed_pongs", (int32_t)session.missed_pongs.load());
        
        obj.add("last_ping_sent", (int64_t)session.last_ping_sent);
        obj.add("last_pong_received", (int64_t)session.last_pong_received);
        
        return obj;
    }

    /**
    * Serialize DeviceState for protocol transmission
    */
    inline NoteBytes::Object serialize_device_state(const DeviceState& device) {
        NoteBytes::Object obj;
        obj.add(NoteMessaging::Keys::ITEM_ID, device.device_id);
        obj.add(NoteMessaging::Keys::SOURCE_ID, device.source_id);
        obj.add(NoteMessaging::Keys::PID, (int32_t)device.owner_pid);
        obj.add(NoteMessaging::Keys::ITEM_TYPE, device.device_type);
        
        obj.add(NoteMessaging::Keys::STATE, device.state.get_state());
        
        obj.add(NoteMessaging::Keys::AVAILABLE_CAPABILITIES, device.available_capabilities);
        obj.add(NoteMessaging::Keys::ENABLED_CAPABILITIES, device.enabled_capabilities);
        obj.add(NoteMessaging::Keys::CURRENT_MODE, device.get_current_mode_bit());
        
        obj.add("pending_events", (int32_t)device.pending_events.load());
        obj.add("events_sent", (int64_t)device.events_sent.load());
        obj.add("events_dropped", (int64_t)device.events_dropped.load());
        
        return obj;
    }

    /**
    * Sync state from protocol message (update local state machine from Java)
    */
    inline void sync_state_from_protocol(BitFlagStateMachine& sm, const NoteBytes::Object& msg) {
        cpp_int new_state = msg.get_cpp_int(NoteMessaging::Keys::STATE);
        sm.set_state(new_state);
    }

    /**
    * Example: Send state update message
    */
    inline NoteBytes::Object create_state_update_message(
        const BitFlagStateMachine& sm,
        const std::string& state_type  // "client" or "device"
    ) {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, "state_update");
        msg.add(NoteMessaging::Keys::STATE_TYPE, state_type);
        msg.add(NoteMessaging::Keys::ID, sm.get_id());
        msg.add(NoteMessaging::Keys::STATE, sm.get_state());
        
        return msg;
    }


}

#endif 