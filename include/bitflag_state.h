// include/bitflag_state.h
// C++ BitFlag State Management matching Java BitFlagStateMachine

#ifndef BITFLAG_STATE_H
#define BITFLAG_STATE_H

#include <atomic>
#include <cstdint>
#include <string>
#include <map>
#include <sys/syslog.h>
#include <vector>
#include <functional>
#include <mutex>
#include "capability_registry.h"


namespace State {

    
/**
 * Client state flags (matches Java ClientStateFlags)
 */
namespace ClientFlags {
    // Connection state (bits 0-7)
    constexpr uint64_t CONNECTED            = 1ULL << 0;
    constexpr uint64_t AUTHENTICATED        = 1ULL << 1;
    constexpr uint64_t DISCOVERING          = 1ULL << 2;
    constexpr uint64_t HAS_CLAIMED_DEVICES  = 1ULL << 3;
    constexpr uint64_t STREAMING            = 1ULL << 4;
    constexpr uint64_t PAUSED               = 1ULL << 5;
    constexpr uint64_t DISCONNECTING        = 1ULL << 6;
    constexpr uint64_t ERROR_STATE          = 1ULL << 7;
    
    // Capabilities (bits 8-15)
    constexpr uint64_t SUPPORTS_ENCRYPTION  = 1ULL << 8;
    constexpr uint64_t SUPPORTS_RAW_MODE    = 1ULL << 9;
    constexpr uint64_t SUPPORTS_FILTERING   = 1ULL << 10;
    constexpr uint64_t SUPPORTS_BATCH       = 1ULL << 11;
    
    // Heartbeat state (bits 16-23)
    constexpr uint64_t HEARTBEAT_ENABLED    = 1ULL << 16;
    constexpr uint64_t HEARTBEAT_WAITING    = 1ULL << 17;
    constexpr uint64_t HEARTBEAT_TIMEOUT    = 1ULL << 18;
    
    // Backpressure state (bits 24-31)
    constexpr uint64_t BACKPRESSURE_ACTIVE  = 1ULL << 24;
    constexpr uint64_t FLOW_CONTROL_PAUSED  = 1ULL << 25;
    constexpr uint64_t QUEUE_FULL           = 1ULL << 26;
    
    inline bool can_discover(uint64_t state) {
        return (state & AUTHENTICATED) && !(state & DISCONNECTING);
    }
    
    inline bool can_claim(uint64_t state) {
        return (state & AUTHENTICATED) && !(state & DISCONNECTING);
    }
    
    inline bool can_stream(uint64_t state) {
        return (state & HAS_CLAIMED_DEVICES) &&
               !(state & PAUSED) &&
               !(state & BACKPRESSURE_ACTIVE) &&
               !(state & DISCONNECTING);
    }
    
    inline bool is_heartbeat_healthy(uint64_t state) {
        return (state & HEARTBEAT_ENABLED) && !(state & HEARTBEAT_TIMEOUT);
    }
}

/**
 * Device state flags (matches Java DeviceStateFlags)
 */
namespace DeviceFlags {
    // Claim state (bits 0-7)
    constexpr uint64_t CLAIMED              = 1ULL << 0;
    constexpr uint64_t KERNEL_DETACHED      = 1ULL << 1;
    constexpr uint64_t INTERFACE_CLAIMED    = 1ULL << 2;
    constexpr uint64_t EXCLUSIVE_ACCESS     = 1ULL << 3;
    
    // Configuration state (bits 8-15)
    constexpr uint64_t ENCRYPTION_ENABLED   = 1ULL << 8;
    constexpr uint64_t FILTER_ENABLED       = 1ULL << 9;
    constexpr uint64_t RAW_MODE             = 1ULL << 10;
    constexpr uint64_t PARSED_MODE          = 1ULL << 11;
    constexpr uint64_t PASSTHROUGH_MODE     = 1ULL << 12;
    
    // Streaming state (bits 16-23)
    constexpr uint64_t STREAMING            = 1ULL << 16;
    constexpr uint64_t PAUSED               = 1ULL << 17;
    constexpr uint64_t BACKPRESSURE_ACTIVE  = 1ULL << 18;
    constexpr uint64_t EVENT_BUFFERING      = 1ULL << 19;
    
    // Error state (bits 24-31)
    constexpr uint64_t DEVICE_ERROR         = 1ULL << 24;
    constexpr uint64_t TRANSFER_ERROR       = 1ULL << 25;
    constexpr uint64_t DISCONNECTED         = 1ULL << 26;
    constexpr uint64_t STALE                = 1ULL << 27;

    constexpr uint64_t MODE_MASK = RAW_MODE | PARSED_MODE;

    inline std::string get_mode_name(uint64_t state) {
        if (state & RAW_MODE) return "raw";
        if (state & PARSED_MODE) return "parsed";
        return "unknown";
    }
}

/**
 * BitFlag State Machine (C++ implementation matching Java)
 */
class BitFlagStateMachine {
private:
    std::string id_;
    uint64_t state_;
    std::mutex mutex_;
    
    // State change listeners
    std::map<uint64_t, std::vector<std::function<void(uint64_t, uint64_t)>>> listeners_;
    std::vector<std::function<void(uint64_t, uint64_t)>> global_listeners_;
    
    // Transitions
    struct Transition {
        uint64_t trigger_bit;
        bool on_add;  // true = on add, false = on remove
        std::function<bool(uint64_t, uint64_t)> guard;
        std::function<void(uint64_t, uint64_t)> action;
    };
    std::map<uint64_t, std::vector<Transition>> transitions_;
    
public:
    BitFlagStateMachine(const std::string& id, uint64_t initial_state = 0)
        : id_(id), state_(initial_state) {}
    
    // ===== STATE QUERIES =====
    
    bool has_flag(uint64_t flag) const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        return (state_ & flag) == flag;
    }
    
    bool has_any_flags(uint64_t flags) const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        return (state_ & flags) != 0;
    }
    
    bool has_all_flags(uint64_t flags) const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        return (state_ & flags) == flags;
    }
    
    uint64_t get_state() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        return state_;
    }
    
    std::string get_id() const {
        return id_;
    }
    
    // ===== STATE MUTATIONS =====
    
    bool add_flag(uint64_t flag) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if ((state_ & flag) == flag) {
            return false;  // Already has flag
        }
        
        uint64_t old_state = state_;
        state_ |= flag;
        
        notify_state_change(old_state, state_, flag, true);
        check_transitions(flag, true, old_state);
        
        return true;
    }
    
    bool remove_flag(uint64_t flag) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if ((state_ & flag) == 0) {
            return false;  // Doesn't have flag
        }
        
        uint64_t old_state = state_;
        state_ &= ~flag;
        
        notify_state_change(old_state, state_, flag, false);
        check_transitions(flag, false, old_state);
        
        return true;
    }

    
    bool toggle_flag(uint64_t flag) {
        if (has_flag(flag)) {
            return remove_flag(flag);
        } else {
            return add_flag(flag);
        }
    }
    
    void set_state(uint64_t new_state) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (state_ == new_state) return;
        
        uint64_t old_state = state_;
        state_ = new_state;
        
        notify_state_change(old_state, new_state, 0, false);
        
        // Check transitions for all changed bits
        uint64_t changed = old_state ^ new_state;
        for (int i = 0; i < 64; i++) {
            uint64_t bit = 1ULL << i;
            if (changed & bit) {
                bool added = (new_state & bit) != 0;
                check_transitions(bit, added, old_state);
            }
        }
    }
    
    void clear_all() {
        set_state(0);
    }
    
    // ===== LISTENERS =====
    
    void add_listener(uint64_t flag, std::function<void(uint64_t, uint64_t)> listener) {
        std::lock_guard<std::mutex> lock(mutex_);
        listeners_[flag].push_back(listener);
    }
    
    void add_global_listener(std::function<void(uint64_t, uint64_t)> listener) {
        std::lock_guard<std::mutex> lock(mutex_);
        global_listeners_.push_back(listener);
    }
    
    // ===== TRANSITIONS =====
    
    void add_transition(uint64_t trigger_bit, bool on_add,
                       std::function<bool(uint64_t, uint64_t)> guard,
                       std::function<void(uint64_t, uint64_t)> action) {
        std::lock_guard<std::mutex> lock(mutex_);
        Transition t{trigger_bit, on_add, guard, action};
        transitions_[trigger_bit].push_back(t);
    }
    
    void on_flag_added(uint64_t flag, std::function<void(uint64_t, uint64_t)> action) {
        add_transition(flag, true, 
                      [](uint64_t, uint64_t) { return true; },
                      action);
    }
    
    void on_flag_removed(uint64_t flag, std::function<void(uint64_t, uint64_t)> action) {
        add_transition(flag, false,
                      [](uint64_t, uint64_t) { return true; },
                      action);
    }
    
    // ===== UTILITIES =====
    
    

    std::string describe_flags(const std::map<uint64_t, std::string>& flag_names) const {
        std::string result = "[";
        bool first = true;
        
        for (const auto& pair : flag_names) {
            if (has_flag(pair.first)) {
                if (!first) result += ", ";
                result += pair.second;
                first = false;
            }
        }
        
        result += "]";
        return result;
    }
    
    int count_active_flags() const {
        int count = 0;
        uint64_t state = get_state();
        while (state) {
            count += (state & 1);
            state >>= 1;
        }
        return count;
    }
    
private:
    void notify_state_change(uint64_t old_state, uint64_t new_state, 
                            uint64_t changed_bit, bool targeted) {
        // Note: Assumes mutex is already locked
        
        // Global listeners
        for (auto& listener : global_listeners_) {
            listener(old_state, new_state);
        }
        
        // Targeted listeners
        if (targeted && changed_bit != 0) {
            auto it = listeners_.find(changed_bit);
            if (it != listeners_.end()) {
                for (auto& listener : it->second) {
                    listener(old_state, new_state);
                }
            }
        } else {
            // Notify all affected listeners
            uint64_t changed = old_state ^ new_state;
            for (int i = 0; i < 64; i++) {
                uint64_t bit = 1ULL << i;
                if (changed & bit) {
                    auto it = listeners_.find(bit);
                    if (it != listeners_.end()) {
                        for (auto& listener : it->second) {
                            listener(old_state, new_state);
                        }
                    }
                }
            }
        }
    }
    
    void check_transitions(uint64_t trigger_bit, bool is_add, uint64_t old_state) {
        // Note: Assumes mutex is already locked
        
        auto it = transitions_.find(trigger_bit);
        if (it == transitions_.end()) return;
        
        uint64_t new_state = state_;
        for (const auto& transition : it->second) {
            if (transition.on_add == is_add) {
                if (!transition.guard || transition.guard(old_state, new_state)) {
                    if (transition.action) {
                        transition.action(old_state, new_state);
                    }
                }
            }
        }
    }
};

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
        state.on_flag_added(ClientFlags::AUTHENTICATED, [this](uint64_t, uint64_t) {
            state.add_flag(ClientFlags::HEARTBEAT_ENABLED);
        });
        
        // When backpressure activates, pause streaming
        state.on_flag_added(ClientFlags::BACKPRESSURE_ACTIVE, [this](uint64_t, uint64_t) {
            state.add_flag(ClientFlags::FLOW_CONTROL_PAUSED);
            syslog(LOG_WARNING, "Backpressure activated for client %s", session_id.c_str());
        });
        
        // When heartbeat times out, mark error
        state.on_flag_added(ClientFlags::HEARTBEAT_TIMEOUT, [this](uint64_t, uint64_t) {
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
 * Device state (C++ version with capabilities)
 */
struct DeviceState {
    std::string device_id;
    int32_t source_id;
    pid_t owner_pid;
    BitFlagStateMachine state;
    
    // Capability tracking (what device can do + user preferences)
    uint64_t available_capabilities;  // What device HAS
    uint64_t enabled_capabilities;    // What user ENABLED
    std::string device_type;          // "keyboard", "mouse", etc.
    
    // Hardware metadata
    std::map<std::string, std::string> hardware_info;
    
    // Backpressure tracking
    std::atomic<int> pending_events{0};
    std::atomic<uint64_t> events_sent{0};
    std::atomic<uint64_t> events_dropped{0};
    uint64_t last_event_time = 0;
    
    DeviceState(const std::string& id, int32_t sid, pid_t pid,
               const std::string& dev_type, uint64_t avail_caps)
        : device_id(id), source_id(sid), owner_pid(pid), 
          state("device-" + std::to_string(sid)),
          available_capabilities(avail_caps),
          enabled_capabilities(0),
          device_type(dev_type) {
        setup_transitions();
    }
    
    void setup_transitions() {
        // When claimed, mark as streaming
        state.on_flag_added(DeviceFlags::CLAIMED, [this](uint64_t, uint64_t) {
            state.add_flag(DeviceFlags::STREAMING);
        });
        
        // When backpressure activates, enable buffering
        state.on_flag_added(DeviceFlags::BACKPRESSURE_ACTIVE, [this](uint64_t, uint64_t) {
            state.add_flag(DeviceFlags::EVENT_BUFFERING);
            syslog(LOG_WARNING, "Backpressure on device %s", device_id.c_str());
        });
        
        // When paused, stop streaming
        state.on_flag_added(DeviceFlags::PAUSED, [this](uint64_t, uint64_t) {
            state.remove_flag(DeviceFlags::STREAMING);
        });
        
        // When disconnected, disable all capabilities
        state.on_flag_added(DeviceFlags::DISCONNECTED, [this](uint64_t, uint64_t) {
            state.add_flag(DeviceFlags::DEVICE_ERROR);
            state.remove_flag(DeviceFlags::STREAMING);
            enabled_capabilities = 0;  // Disable all
        });
        
        // When encryption enabled, check capability
        state.on_flag_added(DeviceFlags::ENCRYPTION_ENABLED, [this](uint64_t, uint64_t) {
            if (!(available_capabilities & Capabilities::Bits::ENCRYPTION_SUPPORTED)) {
                syslog(LOG_ERR, "Device does not support encryption");
                state.remove_flag(DeviceFlags::ENCRYPTION_ENABLED);
            } else {
                enabled_capabilities |= Capabilities::Bits::ENCRYPTION_ENABLED;
            }
        });
        
        // When filter enabled, check capability
        state.on_flag_added(DeviceFlags::FILTER_ENABLED, [this](uint64_t, uint64_t) {
            if (!(available_capabilities & Capabilities::Bits::FILTERED_MODE)) {
                syslog(LOG_ERR, "Device does not support filtering");
                state.remove_flag(DeviceFlags::FILTER_ENABLED);
            } else {
                enabled_capabilities |= Capabilities::Bits::FILTERED_MODE;
            }
        });
    }
    
    // ===== CAPABILITY MANAGEMENT =====
    
    bool has_capability(uint64_t cap) const {
        return (available_capabilities & cap) != 0;
    }
    
    bool is_capability_enabled(uint64_t cap) const {
        return (enabled_capabilities & cap) != 0;
    }
    
    bool enable_mode(uint64_t mode) {
        // Check if mode is available
        if (!has_capability(mode)) {
            syslog(LOG_ERR, "Mode not available: %s", 
                   Capabilities::Names::get_capability_name(mode));
            return false;
        }
        
        // Check if it's actually a mode
        if (!Capabilities::Validation::is_mode(mode)) {
            syslog(LOG_ERR, "Not a mode capability: %s",
                   Capabilities::Names::get_capability_name(mode));
            return false;
        }
        
        // Disable all other modes (mutually exclusive)
        enabled_capabilities &= ~Capabilities::Bits::MODE_MASK;
        
        // Enable requested mode
        enabled_capabilities |= mode;
        
        syslog(LOG_INFO, "Enabled mode '%s' for device %s",
               Capabilities::Names::get_capability_name(mode),
               device_id.c_str());
        
        return true;
    }
    
    bool enable_mode(const std::string& mode_name) {
        uint64_t mode = Capabilities::Names::get_capability_bit(mode_name);
        if (mode == 0) {
            syslog(LOG_ERR, "Unknown mode: %s", mode_name.c_str());
            return false;
        }
        return enable_mode(mode);
    }
    
    std::string get_current_mode() const {
        return Capabilities::Validation::get_mode_name(enabled_capabilities);
    }
    
    uint64_t get_current_mode_bit() const {
        return Capabilities::Validation::get_enabled_mode(enabled_capabilities);
    }
    
    void set_hardware_info(const std::string& key, const std::string& value) {
        hardware_info[key] = value;
    }
    
    std::string get_hardware_info(const std::string& key) const {
        auto it = hardware_info.find(key);
        return (it != hardware_info.end()) ? it->second : "";
    }
    
    bool can_queue_event() {
        if (!state.has_flag(DeviceFlags::STREAMING)) {
            return false;
        }
        
        if (pending_events.load() > 100) {
            state.add_flag(DeviceFlags::BACKPRESSURE_ACTIVE);
        }
        
        return true;
    }
    
    void event_queued() {
        pending_events.fetch_add(1);
        events_sent.fetch_add(1);
        last_event_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
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


} // namespace State

#endif // BITFLAG_STATE_H