// include/bitflag_state_bigint.h
// C++ BitFlag State Management using Boost multiprecision for Java BigInteger compatibility

#ifndef BITFLAG_STATE_BIGINT_H
#define BITFLAG_STATE_BIGINT_H

#include <boost/multiprecision/cpp_int.hpp>
#include <condition_variable>
#include <string>
#include <map>
#include <vector>
#include <functional>
#include <mutex>
#include <atomic>
#include <sys/syslog.h>


using boost::multiprecision::cpp_int;

namespace State {
    inline void bit_set(cpp_int& value, int bit_position) {
        value |= (cpp_int(1) << bit_position);
    }

    inline void bit_clear(cpp_int& value, int bit_position) {
        value &= ~(cpp_int(1) << bit_position);
    }

    inline void bit_unset(cpp_int& value, int bit_position) {
        bit_clear(value, bit_position);
    }

    inline bool bit_test(const cpp_int& value, int bit_position) {
        return (value & (cpp_int(1) << bit_position)) != 0;
    }

    // Mask operations - DECLARE THESE BEFORE capability_registry.h includes this file
    inline cpp_int create_mask(const std::vector<int>& bit_positions) {
        cpp_int mask = 0;
        for (int pos : bit_positions) {
            bit_set(mask, pos);
        }
        return mask;
    }

    inline cpp_int create_range_mask(int start_bit, int end_bit) {
        cpp_int mask = 0;
        for (int i = start_bit; i <= end_bit; i++) {
            bit_set(mask, i);
        }
        return mask;
    }

    inline bool has_any_bits(const cpp_int& state, const cpp_int& mask) {
        return (state & mask) != 0;
    }

    inline bool has_all_bits(const cpp_int& state, const cpp_int& mask) {
        return (state & mask) == mask;
    }

    inline cpp_int apply_mask(const cpp_int& state, const cpp_int& mask) {
        return state & mask;
    }

    inline void clear_mask(cpp_int& state, const cpp_int& mask) {
        state &= ~mask;
    }

    inline void set_mask(cpp_int& state, const cpp_int& mask) {
        state |= mask;
    }

    inline int count_bits_in_mask(const cpp_int& state, const cpp_int& mask) {
        cpp_int masked = state & mask;
        int count = 0;
        while (masked > 0) {
            if ((masked & 1) != 0) count++;
            masked >>= 1;
        }
        return count;
    }

    inline int msb(const cpp_int& value) {
        if (value == 0) return -1;
        int pos = 0;
        cpp_int temp = value;
        while (temp > 1) {
            temp >>= 1;
            pos++;
        }
        return pos;
    }
    
/**
 * BitFlag State Machine using cpp_int (unlimited precision like Java BigInteger)
 */
class BitFlagStateMachine {
private:
    std::string id_;
    cpp_int state_;
    std::mutex mutex_;
    
    // State change listeners
    std::map<int, std::vector<std::function<void(cpp_int, cpp_int)>>> listeners_;
    std::vector<std::function<void(cpp_int, cpp_int)>> global_listeners_;
    
    // Transitions
    struct Transition {
        int trigger_bit;
        bool on_add;
        std::function<bool(cpp_int, cpp_int)> guard;
        std::function<void(cpp_int, cpp_int)> action;
    };
    std::map<int, std::vector<Transition>> transitions_;
    
public:
    BitFlagStateMachine(const std::string& id, cpp_int initial_state = 0)
        : id_(id), state_(initial_state) {}
    
    // ===== STATE QUERIES =====
    
    /**
     * Check if bit position is set
     * @param bit_position The bit position (0, 1, 2, ...)
     */
    bool has_flag(int bit_position) const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        return bit_test(state_, bit_position);
    }
    
    bool has_any_flags(const std::vector<int>& bit_positions) const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        for (int pos : bit_positions) {
            if (bit_test(state_, pos)) return true;
        }
        return false;
    }
    
    bool has_all_flags(const std::vector<int>& bit_positions) const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        for (int pos : bit_positions) {
            if (!bit_test(state_, pos)) return false;
        }
        return true;
    }
    
    cpp_int get_state() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        return state_;
    }
    
    std::string get_id() const {
        return id_;
    }
    
    // ===== STATE MUTATIONS =====
    
    /**
     * Add flag at bit position
     * @param bit_position The bit position (0, 1, 2, ...)
     */
    bool add_flag(int bit_position) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (bit_test(state_, bit_position)) {
            return false;  // Already has flag
        }
        
        cpp_int old_state = state_;
        bit_set(state_, bit_position);
        
        notify_state_change(old_state, state_, bit_position, true);
        check_transitions(bit_position, true, old_state);
        
        return true;
    }
    
    /**
     * Remove flag at bit position
     */
    bool remove_flag(int bit_position) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (!bit_test(state_, bit_position)) {
            return false;  // Doesn't have flag
        }
        
        cpp_int old_state = state_;
        bit_unset(state_, bit_position);
        
        notify_state_change(old_state, state_, bit_position, false);
        check_transitions(bit_position, false, old_state);
        
        return true;
    }
    
    bool toggle_flag(int bit_position) {
        if (has_flag(bit_position)) {
            return remove_flag(bit_position);
        } else {
            return add_flag(bit_position);
        }
    }
    
    void set_state(cpp_int new_state) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (state_ == new_state) return;
        
        cpp_int old_state = state_;
        state_ = new_state;
        
        notify_state_change(old_state, new_state, -1, false);
        
        // Check transitions for all changed bits
        cpp_int changed = old_state ^ new_state;
        for (int i = 0; i < msb(changed) + 1; i++) {
            if (bit_test(changed, i)) {
                bool added = bit_test(new_state, i);
                check_transitions(i, added, old_state);
            }
        }
    }
    
    void clear_all() {
        set_state(0);
    }
    
    // ===== LISTENERS =====
    
    void add_listener(int bit_position, std::function<void(cpp_int, cpp_int)> listener) {
        std::lock_guard<std::mutex> lock(mutex_);
        listeners_[bit_position].push_back(listener);
    }
    
    void add_global_listener(std::function<void(cpp_int, cpp_int)> listener) {
        std::lock_guard<std::mutex> lock(mutex_);
        global_listeners_.push_back(listener);
    }
    
    // ===== TRANSITIONS =====
    
    void add_transition(int trigger_bit, bool on_add,
                       std::function<bool(cpp_int, cpp_int)> guard,
                       std::function<void(cpp_int, cpp_int)> action) {
        std::lock_guard<std::mutex> lock(mutex_);
        Transition t{trigger_bit, on_add, guard, action};
        transitions_[trigger_bit].push_back(t);
    }
    
    void on_flag_added(int bit_position, std::function<void(cpp_int, cpp_int)> action) {
        add_transition(bit_position, true, 
                      [](cpp_int, cpp_int) { return true; },
                      action);
    }
    
    void on_flag_removed(int bit_position, std::function<void(cpp_int, cpp_int)> action) {
        add_transition(bit_position, false,
                      [](cpp_int, cpp_int) { return true; },
                      action);
    }
    
    // ===== SERIALIZATION =====
    
    /**
     * Serialize state to bytes (compatible with Java BigInteger.toByteArray())
     */
    std::vector<uint8_t> to_bytes() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        
        if (state_ == 0) {
            return std::vector<uint8_t>{0};
        }
        
        // Export as bytes (big-endian, compatible with Java)
        std::vector<uint8_t> bytes;
        cpp_int temp = state_;
        
        while (temp > 0) {
            bytes.insert(bytes.begin(), static_cast<uint8_t>(temp & 0xFF));
            temp >>= 8;
        }
        
        return bytes;
    }
    
    /**
     * Deserialize state from bytes (compatible with Java BigInteger constructor)
     */
    static cpp_int from_bytes(const uint8_t* data, size_t len) {
        cpp_int result = 0;
        for (size_t i = 0; i < len; i++) {
            result <<= 8;
            result |= data[i];
        }
        return result;
    }
    
    /**
     * Get state as hex string (for debugging)
     */
    std::string to_hex_string() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        std::stringstream ss;
        ss << std::hex << state_;
        return ss.str();
    }
    
    // ===== UTILITIES =====
    
    std::string describe_flags(const std::map<int, std::string>& flag_names) const {
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
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
        int count = 0;
        cpp_int temp = state_;
        while (temp > 0) {
            if ((temp & 1) == 1) count++;
            temp >>= 1;
        }
        return count;
    }

        
private:
    void notify_state_change(cpp_int old_state, cpp_int new_state, 
                            int changed_bit, bool targeted) {
        // Global listeners
        for (auto& listener : global_listeners_) {
            listener(old_state, new_state);
        }
        
        // Targeted listeners
        if (targeted && changed_bit >= 0) {
            auto it = listeners_.find(changed_bit);
            if (it != listeners_.end()) {
                for (auto& listener : it->second) {
                    listener(old_state, new_state);
                }
            }
        } else {
            // Notify all affected listeners
            cpp_int changed = old_state ^ new_state;
            int max_bit = msb(changed);
            
            for (int i = 0; i <= max_bit; i++) {
                if (bit_test(changed, i)) {
                    auto it = listeners_.find(i);
                    if (it != listeners_.end()) {
                        for (auto& listener : it->second) {
                            listener(old_state, new_state);
                        }
                    }
                }
            }
        }
    }
    
    void check_transitions(int trigger_bit, bool is_add, cpp_int old_state) {
        auto it = transitions_.find(trigger_bit);
        if (it == transitions_.end()) return;
        
        cpp_int new_state = state_;
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

} // namespace State

#endif // BITFLAG_STATE_BIGINT_H