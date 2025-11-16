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
#include <condition_variable>

namespace State {

    
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



} // namespace State

#endif // BITFLAG_STATE_H