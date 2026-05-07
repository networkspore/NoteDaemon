// device_session_test.cpp
// Unit tests for DeviceState and state machine (used by DeviceSession)

#include "state.h"
#include <gtest/gtest.h>
#include <cstring>
#include <unistd.h>

class DeviceSessionTest : public ::testing::Test {
protected:
    pid_t owner_pid_;

    void SetUp() override {
        owner_pid_ = getpid();
    }

    void TearDown() override {
    }
};

// Test 1: Verify DeviceState creation
TEST_F(DeviceSessionTest, DeviceStateCreation) {
    cpp_int caps = 0;
    auto state = std::make_shared<State::DeviceState>(
        "test-device-001", owner_pid_, "HID", caps
    );

    EXPECT_FALSE(state->state.has_flag(State::DeviceFlags::CLAIMED));
    EXPECT_EQ(state->owner_pid, owner_pid_);
}

// Test 2: Verify state flag transitions
TEST_F(DeviceSessionTest, StateFlagTransitions) {
    cpp_int caps = 0;
    auto state = std::make_shared<State::DeviceState>(
        "test-device-001", owner_pid_, "HID", caps
    );

    // Claim device
    state->state.add_flag(State::DeviceFlags::CLAIMED);
    EXPECT_TRUE(state->state.has_flag(State::DeviceFlags::CLAIMED));

    // Start streaming
    state->state.add_flag(State::DeviceFlags::STREAMING);
    EXPECT_TRUE(state->state.has_flag(State::DeviceFlags::STREAMING));

    // Stop streaming
    state->state.remove_flag(State::DeviceFlags::STREAMING);
    EXPECT_FALSE(state->state.has_flag(State::DeviceFlags::STREAMING));
}

// Test 3: Verify backpressure flag behavior (no deadlock)
TEST_F(DeviceSessionTest, BackpressureFlagNoDeadlock) {
    cpp_int caps = 0;
    auto state = std::make_shared<State::DeviceState>(
        "test-device-001", owner_pid_, "HID", caps
    );

    // Adding BACKPRESSURE_ACTIVE should also add EVENT_BUFFERING
    state->state.add_flag(State::DeviceFlags::BACKPRESSURE_ACTIVE);

    // Give time for listener to fire
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    EXPECT_TRUE(state->state.has_flag(State::DeviceFlags::BACKPRESSURE_ACTIVE));
    EXPECT_TRUE(state->state.has_flag(State::DeviceFlags::EVENT_BUFFERING));
}

// Test 4: Verify event tracking
TEST_F(DeviceSessionTest, EventTracking) {
    cpp_int caps = 0;
    auto state = std::make_shared<State::DeviceState>(
        "test-device-001", owner_pid_, "HID", caps
    );

    state->event_queued();
    EXPECT_EQ(state->pending_events.load(), 1);

    state->event_delivered();
    EXPECT_EQ(state->pending_events.load(), 0);
    EXPECT_EQ(state->events_sent.load(), 1);
}

// Test 5: Verify events_dropped tracking
TEST_F(DeviceSessionTest, EventsDroppedTracking) {
    cpp_int caps = 0;
    auto state = std::make_shared<State::DeviceState>(
        "test-device-001", owner_pid_, "HID", caps
    );

    uint64_t initial = state->events_dropped.load();
    state->events_dropped.fetch_add(5);
    EXPECT_EQ(state->events_dropped.load(), initial + 5);
}

// Test 6: Verify error flag handling
TEST_F(DeviceSessionTest, ErrorFlag) {
    cpp_int caps = 0;
    auto state = std::make_shared<State::DeviceState>(
        "test-device-001", owner_pid_, "HID", caps
    );

    // Simulate device error
    state->state.add_flag(State::DeviceFlags::DEVICE_ERROR);
    EXPECT_TRUE(state->state.has_flag(State::DeviceFlags::DEVICE_ERROR));

    // Clear error
    state->state.remove_flag(State::DeviceFlags::DEVICE_ERROR);
    EXPECT_FALSE(state->state.has_flag(State::DeviceFlags::DEVICE_ERROR));
}
