// include/bitflag_state_long.h
// C++ BitFlag State Management - lock-free state via std::atomic<uint64_t>

#ifndef BITFLAG_STATE_H
#define BITFLAG_STATE_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace State {

/**
 * BitFlag State Machine backed by std::atomic<uint64_t>.
 *
 * State reads and writes are fully lock-free.
 * A mutex is used only when registering or snapshotting listeners/transitions,
 * which are expected to be infrequent (typically at startup).
 * Callbacks are always invoked outside any lock.
 *
 * Maximum 64 independent flags (bits 0-63).
 */
class BitFlagStateMachine {
public:
    using StateCallback = std::function<void(uint64_t /*old*/, uint64_t /*new*/)>;
    using GuardFn       = std::function<bool(uint64_t /*old*/, uint64_t /*new*/)>;

    explicit BitFlagStateMachine(const std::string& id, uint64_t initial_state = 0)
        : id_(id), state_(initial_state) {}

    // Non-copyable, non-movable (owns an atomic and a mutex)
    BitFlagStateMachine(const BitFlagStateMachine&)            = delete;
    BitFlagStateMachine& operator=(const BitFlagStateMachine&) = delete;
    BitFlagStateMachine(BitFlagStateMachine&&)                 = delete;
    BitFlagStateMachine& operator=(BitFlagStateMachine&&)      = delete;

    // ===== QUERIES — fully lock-free =====

    bool has_flag(uint64_t flag) const {
        return (state_.load(std::memory_order_acquire) & flag) == flag;
    }

    bool has_any_flags(uint64_t flags) const {
        return (state_.load(std::memory_order_acquire) & flags) != 0;
    }

    bool has_all_flags(uint64_t flags) const {
        return (state_.load(std::memory_order_acquire) & flags) == flags;
    }

    uint64_t get_state() const {
        return state_.load(std::memory_order_acquire);
    }

    const std::string& get_id() const {
        return id_;  // immutable after construction
    }

    int count_active_flags() const {
        uint64_t s = state_.load(std::memory_order_acquire);
        // __builtin_popcountll is available on GCC/Clang; fallback loop otherwise
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_popcountll(s);
#else
        int count = 0;
        while (s) { count += (s & 1); s >>= 1; }
        return count;
#endif
    }

    // ===== MUTATIONS — lock-free state update, callbacks fired outside lock =====

    /**
     * Set all bits in flag. Returns false if all bits were already set (no-op).
     */
    bool add_flag(uint64_t flag) {
        uint64_t old_state = state_.fetch_or(flag, std::memory_order_acq_rel);
        if ((old_state & flag) == flag) return false;  // already fully set

        uint64_t new_state = old_state | flag;
        fire_callbacks(flag, /*added=*/true, old_state, new_state);
        return true;
    }

    /**
     * Clear all bits in flag. Returns false if all bits were already clear (no-op).
     */
    bool remove_flag(uint64_t flag) {
        uint64_t old_state = state_.fetch_and(~flag, std::memory_order_acq_rel);
        if ((old_state & flag) == 0) return false;  // already fully clear

        uint64_t new_state = old_state & ~flag;
        fire_callbacks(flag, /*added=*/false, old_state, new_state);
        return true;
    }

    /**
     * Atomically toggle flag via compare_exchange loop — no TOCTOU race.
     * Returns true if the flag is set after the operation, false if cleared.
     */
    bool toggle_flag(uint64_t flag) {
        uint64_t old_state = state_.load(std::memory_order_acquire);
        uint64_t new_state;
        bool added;

        do {
            bool currently_set = (old_state & flag) == flag;
            new_state = currently_set ? (old_state & ~flag) : (old_state | flag);
            added     = !currently_set;
        } while (!state_.compare_exchange_weak(old_state, new_state,
                                               std::memory_order_acq_rel,
                                               std::memory_order_acquire));

        fire_callbacks(flag, added, old_state, new_state);
        return added;
    }

    /**
     * Replace the entire state atomically.
     * Fires listeners and transitions for every bit that changed.
     */
    void set_state(uint64_t desired) {
        uint64_t old_state = state_.exchange(desired, std::memory_order_acq_rel);
        if (old_state == desired) return;

        fire_all_changed_callbacks(old_state, desired);
    }

    void clear_all() {
        set_state(0);
    }

    // ===== LISTENER REGISTRATION — guarded by reg_mutex_ =====

    void add_listener(uint64_t flag, StateCallback listener) {
        std::lock_guard<std::mutex> lock(reg_mutex_);
        listeners_[flag].push_back(std::move(listener));
    }

    void add_global_listener(StateCallback listener) {
        std::lock_guard<std::mutex> lock(reg_mutex_);
        global_listeners_.push_back(std::move(listener));
    }

    // ===== TRANSITION REGISTRATION — guarded by reg_mutex_ =====

    void add_transition(uint64_t trigger_flag, bool on_add,
                        GuardFn       guard,
                        StateCallback action) {
        std::lock_guard<std::mutex> lock(reg_mutex_);
        transitions_[trigger_flag].push_back({trigger_flag, on_add,
                                               std::move(guard),
                                               std::move(action)});
    }

    void on_flag_added(uint64_t flag, StateCallback action) {
        add_transition(flag, /*on_add=*/true,
                       [](uint64_t, uint64_t) { return true; },
                       std::move(action));
    }

    void on_flag_removed(uint64_t flag, StateCallback action) {
        add_transition(flag, /*on_add=*/false,
                       [](uint64_t, uint64_t) { return true; },
                       std::move(action));
    }

    // ===== UTILITIES =====

    std::string describe_flags(const std::map<uint64_t, std::string>& flag_names) const {
        uint64_t snapshot = state_.load(std::memory_order_acquire);
        std::string result = "[";
        bool first = true;
        for (const auto& [flag, name] : flag_names) {
            if ((snapshot & flag) == flag) {
                if (!first) result += ", ";
                result += name;
                first = false;
            }
        }
        result += "]";
        return result;
    }

private:
    struct Transition {
        uint64_t      trigger_flag;
        bool          on_add;
        GuardFn       guard;
        StateCallback action;
    };

    /**
     * Snapshot listeners and transitions under reg_mutex_, then fire outside it.
     * Used by add_flag / remove_flag / toggle_flag (single flag change).
     */
    void fire_callbacks(uint64_t flag, bool added,
                        uint64_t old_state, uint64_t new_state) {
        std::vector<StateCallback> listeners_snap;
        std::vector<StateCallback> global_snap;
        std::vector<Transition>    transitions_snap;

        {
            std::lock_guard<std::mutex> lock(reg_mutex_);
            auto lit = listeners_.find(flag);
            if (lit != listeners_.end()) listeners_snap = lit->second;
            global_snap = global_listeners_;
            auto tit = transitions_.find(flag);
            if (tit != transitions_.end()) transitions_snap = tit->second;
        }

        for (auto& cb : listeners_snap)  cb(old_state, new_state);
        for (auto& cb : global_snap)     cb(old_state, new_state);
        for (auto& t  : transitions_snap) {
            if (t.on_add == added && t.guard(old_state, new_state)) {
                t.action(old_state, new_state);
            }
        }
    }

    /**
     * Snapshot and fire callbacks for every bit that changed between
     * old_state and new_state. Used by set_state.
     */
    void fire_all_changed_callbacks(uint64_t old_state, uint64_t new_state) {
        std::vector<StateCallback>                              global_snap;
        std::vector<std::pair<uint64_t, std::vector<StateCallback>>>   bit_listeners;
        std::vector<std::pair<uint64_t, std::vector<Transition>>>      bit_transitions;

        {
            std::lock_guard<std::mutex> lock(reg_mutex_);
            global_snap = global_listeners_;

            uint64_t changed = old_state ^ new_state;
            while (changed) {
                // isolate lowest set bit
                uint64_t bit = changed & (~changed + 1);
                changed &= ~bit;

                auto lit = listeners_.find(bit);
                if (lit != listeners_.end()) {
                    bit_listeners.emplace_back(bit, lit->second);
                }
                auto tit = transitions_.find(bit);
                if (tit != transitions_.end()) {
                    bit_transitions.emplace_back(bit, tit->second);
                }
            }
        }

        for (auto& cb : global_snap) cb(old_state, new_state);

        for (auto& [bit, cbs] : bit_listeners) {
            for (auto& cb : cbs) cb(old_state, new_state);
        }

        for (auto& [bit, transitions] : bit_transitions) {
            bool added = (new_state & bit) != 0;
            for (auto& t : transitions) {
                if (t.on_add == added && t.guard(old_state, new_state)) {
                    t.action(old_state, new_state);
                }
            }
        }
    }

    // ===== DATA =====

    const std::string      id_;
    std::atomic<uint64_t>  state_;       // lock-free state
    mutable std::mutex     reg_mutex_;   // guards listeners_ and transitions_ only

    std::map<uint64_t, std::vector<StateCallback>> listeners_;
    std::vector<StateCallback>                     global_listeners_;
    std::map<uint64_t, std::vector<Transition>>    transitions_;
};

} // namespace State

#endif // BITFLAG_STATE_H