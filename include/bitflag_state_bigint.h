// include/bitflag_state_bigint.h
// C++ BitFlag State Management using Boost multiprecision for Java BigInteger compatibility

#ifndef BITFLAG_STATE_BIGINT_H
#define BITFLAG_STATE_BIGINT_H

#include <boost/multiprecision/cpp_int.hpp>
#include <functional>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/syslog.h>
#include <vector>

using boost::multiprecision::cpp_int;

namespace State {

    // ===== FREE FUNCTIONS =====

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

    // ===== STATE MACHINE =====

    /**
     * BitFlag State Machine using cpp_int (unlimited precision like Java BigInteger).
     *
     * Thread safety: all public methods are safe to call concurrently.
     * Listeners and transition actions are always invoked outside the lock
     * to prevent deadlocks when callbacks re-enter the state machine.
     */
    class BitFlagStateMachine {
    public:
        using StateCallback = std::function<void(cpp_int /*old*/, cpp_int /*new*/)>;
        using GuardFn      = std::function<bool(cpp_int /*old*/, cpp_int /*new*/)>;

        explicit BitFlagStateMachine(const std::string& id, cpp_int initial_state = 0)
            : id_(id), state_(std::move(initial_state)) {}

        // Non-copyable, non-movable (owns a mutex)
        BitFlagStateMachine(const BitFlagStateMachine&)            = delete;
        BitFlagStateMachine& operator=(const BitFlagStateMachine&) = delete;
        BitFlagStateMachine(BitFlagStateMachine&&)                 = delete;
        BitFlagStateMachine& operator=(BitFlagStateMachine&&)      = delete;

        // ===== QUERIES =====

        bool has_flag(int bit_position) const {
            std::lock_guard<std::mutex> lock(mutex_);
            return bit_test(state_, bit_position);
        }

        bool has_any_flags(const std::vector<int>& bit_positions) const {
            std::lock_guard<std::mutex> lock(mutex_);
            for (int pos : bit_positions) {
                if (bit_test(state_, pos)) return true;
            }
            return false;
        }

        bool has_all_flags(const std::vector<int>& bit_positions) const {
            std::lock_guard<std::mutex> lock(mutex_);
            for (int pos : bit_positions) {
                if (!bit_test(state_, pos)) return false;
            }
            return true;
        }

        cpp_int get_state() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return state_;
        }

        const std::string& get_id() const {
            return id_;  // immutable after construction — no lock needed
        }

        int count_active_flags() const {
            std::lock_guard<std::mutex> lock(mutex_);
            int count = 0;
            cpp_int temp = state_;
            while (temp > 0) {
                if ((temp & 1) == 1) count++;
                temp >>= 1;
            }
            return count;
        }

        // ===== MUTATIONS =====

        /**
         * Set bit_position. Returns false if already set (no-op).
         * Listeners and transitions are fired after the lock is released.
         */
        bool add_flag(int bit_position) {
            cpp_int old_state, new_state;
            PendingNotifications pending;

            {
                std::lock_guard<std::mutex> lock(mutex_);

                if (bit_test(state_, bit_position)) return false;

                old_state = state_;
                bit_set(state_, bit_position);
                new_state = state_;

                collect_notifications(bit_position, pending);
            }

            fire_notifications(pending, old_state, new_state, /*added=*/true);
            return true;
        }

        /**
         * Clear bit_position. Returns false if already clear (no-op).
         * Listeners and transitions are fired after the lock is released.
         */
        bool remove_flag(int bit_position) {
            cpp_int old_state, new_state;
            PendingNotifications pending;

            {
                std::lock_guard<std::mutex> lock(mutex_);

                if (!bit_test(state_, bit_position)) return false;

                old_state = state_;
                bit_unset(state_, bit_position);
                new_state = state_;

                collect_notifications(bit_position, pending);
            }

            fire_notifications(pending, old_state, new_state, /*added=*/false);
            return true;
        }

        /**
         * Atomically toggle bit_position under a single lock acquisition.
         * Returns true if the bit is set after the operation, false if cleared.
         */
        bool toggle_flag(int bit_position) {
            cpp_int old_state, new_state;
            bool added;
            PendingNotifications pending;

            {
                std::lock_guard<std::mutex> lock(mutex_);

                old_state = state_;
                if (bit_test(state_, bit_position)) {
                    bit_unset(state_, bit_position);
                    added = false;
                } else {
                    bit_set(state_, bit_position);
                    added = true;
                }
                new_state = state_;

                collect_notifications(bit_position, pending);
            }

            fire_notifications(pending, old_state, new_state, added);
            return added;
        }

        /**
         * Replace the entire state.
         * Listeners and transitions fire for every bit that changed.
         */
        void set_state(cpp_int desired) {
            cpp_int old_state, new_state;
            std::vector<StateCallback>                           global_cbs;
            std::vector<std::pair<int, std::vector<StateCallback>>> bit_cbs_per_bit;
            std::vector<std::pair<int, std::vector<Transition>>> transitions_to_check;

            {
                std::lock_guard<std::mutex> lock(mutex_);

                if (state_ == desired) return;

                old_state = state_;
                state_    = desired;
                new_state = desired;

                // Snapshot everything needed before releasing the lock
                global_cbs = global_listeners_;

                cpp_int changed = old_state ^ new_state;
                int top = msb(changed);
                for (int i = 0; i <= top; i++) {
                    if (!bit_test(changed, i)) continue;

                    auto lit = listeners_.find(i);
                    if (lit != listeners_.end()) {
                        bit_cbs_per_bit.emplace_back(i, lit->second);
                    }

                    auto tit = transitions_.find(i);
                    if (tit != transitions_.end()) {
                        transitions_to_check.emplace_back(i, tit->second);
                    }
                }
            }
            // Lock is released — fire everything outside

            for (auto& cb : global_cbs) {
                cb(old_state, new_state);
            }

            for (auto& [bit, cbs] : bit_cbs_per_bit) {
                for (auto& cb : cbs) cb(old_state, new_state);
            }

            for (auto& [bit, transitions] : transitions_to_check) {
                bool added = bit_test(new_state, bit);
                for (auto& t : transitions) {
                    if (t.on_add == added && t.guard(old_state, new_state)) {
                        t.action(old_state, new_state);
                    }
                }
            }
        }

        void clear_all() {
            set_state(0);
        }

        // ===== LISTENERS =====

        void add_listener(int bit_position, StateCallback listener) {
            std::lock_guard<std::mutex> lock(mutex_);
            listeners_[bit_position].push_back(std::move(listener));
        }

        void add_global_listener(StateCallback listener) {
            std::lock_guard<std::mutex> lock(mutex_);
            global_listeners_.push_back(std::move(listener));
        }

        // ===== TRANSITIONS =====

        void add_transition(int trigger_bit, bool on_add,
                            GuardFn   guard,
                            StateCallback action) {
            std::lock_guard<std::mutex> lock(mutex_);
            transitions_[trigger_bit].push_back({trigger_bit, on_add,
                                                  std::move(guard),
                                                  std::move(action)});
        }

        void on_flag_added(int bit_position, StateCallback action) {
            add_transition(bit_position, /*on_add=*/true,
                           [](cpp_int, cpp_int) { return true; },
                           std::move(action));
        }

        void on_flag_removed(int bit_position, StateCallback action) {
            add_transition(bit_position, /*on_add=*/false,
                           [](cpp_int, cpp_int) { return true; },
                           std::move(action));
        }

        // ===== SERIALIZATION =====

        /**
         * Serialize state to bytes (big-endian, compatible with Java BigInteger.toByteArray()).
         */
        std::vector<uint8_t> to_bytes() const {
            std::lock_guard<std::mutex> lock(mutex_);

            if (state_ == 0) return {0};

            std::vector<uint8_t> bytes;
            cpp_int temp = state_;
            while (temp > 0) {
                bytes.insert(bytes.begin(), static_cast<uint8_t>(temp & 0xFF));
                temp >>= 8;
            }
            return bytes;
        }

        /**
         * Deserialize state from bytes (compatible with Java BigInteger(byte[]) constructor).
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
         * Hex string representation of current state (for debugging).
         */
        std::string to_hex_string() const {
            std::lock_guard<std::mutex> lock(mutex_);
            std::ostringstream ss;
            ss << std::hex << state_;
            return ss.str();
        }

        // ===== UTILITIES =====

        std::string describe_flags(const std::map<int, std::string>& flag_names) const {
            // take a snapshot so we don't hold the lock while building the string
            cpp_int snapshot;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                snapshot = state_;
            }

            std::string result = "[";
            bool first = true;
            for (const auto& [bit, name] : flag_names) {
                if (bit_test(snapshot, bit)) {
                    if (!first) result += ", ";
                    result += name;
                    first = false;
                }
            }
            result += "]";
            return result;
        }

    private:
        // ===== INTERNAL TYPES =====

        struct Transition {
            int           trigger_bit;
            bool          on_add;
            GuardFn       guard;
            StateCallback action;
        };

        struct PendingNotifications {
            std::vector<StateCallback>        listeners;
            std::vector<StateCallback>        global_listeners;
            std::vector<Transition>           transitions;
        };

        // ===== HELPERS (called with lock held) =====

        /**
         * Snapshot all callbacks that need to fire for a single-bit change.
         * Must be called while holding mutex_.
         */
        void collect_notifications(int bit_position, PendingNotifications& out) {
            auto lit = listeners_.find(bit_position);
            if (lit != listeners_.end()) {
                out.listeners = lit->second;
            }
            out.global_listeners = global_listeners_;

            auto tit = transitions_.find(bit_position);
            if (tit != transitions_.end()) {
                out.transitions = tit->second;
            }
        }

        /**
         * Fire all collected callbacks. Must be called with mutex_ NOT held.
         */
        void fire_notifications(const PendingNotifications& pending,
                                const cpp_int& old_state,
                                const cpp_int& new_state,
                                bool           added) {
            for (const auto& cb : pending.listeners) {
                cb(old_state, new_state);
            }
            for (const auto& cb : pending.global_listeners) {
                cb(old_state, new_state);
            }
            for (const auto& t : pending.transitions) {
                if (t.on_add == added && t.guard(old_state, new_state)) {
                    t.action(old_state, new_state);
                }
            }
        }

        // ===== DATA =====

        const std::string id_;
        cpp_int           state_;
        mutable std::mutex mutex_;  // mutable: allows locking in const methods

        std::map<int, std::vector<StateCallback>> listeners_;
        std::vector<StateCallback>                global_listeners_;
        std::map<int, std::vector<Transition>>    transitions_;
    };

} // namespace State

#endif // BITFLAG_STATE_BIGINT_H