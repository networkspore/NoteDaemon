// error_handling_test.cpp
// Unit tests for error handling (USB errors, malformed reports)

#include "state.h"
#include <gtest/gtest.h>
#include <cstring>
#include <unistd.h>

class ErrorHandlingTest : public ::testing::Test {
protected:
    std::shared_ptr<State::DeviceState> device_state_;
    pid_t owner_pid_;

    void SetUp() override {
        owner_pid_ = getpid();
        cpp_int caps = 0;
        device_state_ = std::make_shared<State::DeviceState>(
            "test-device-001", owner_pid_, "HID", caps
        );
    }

    void TearDown() override {
        device_state_.reset();
    }
};

// Test 1: Verify DEVICE_ERROR flag can be set
TEST_F(ErrorHandlingTest, DeviceErrorFlag) {
    EXPECT_FALSE(device_state_->state.has_flag(State::DeviceFlags::DEVICE_ERROR));

    device_state_->state.add_flag(State::DeviceFlags::DEVICE_ERROR);
    EXPECT_TRUE(device_state_->state.has_flag(State::DeviceFlags::DEVICE_ERROR));

    device_state_->state.remove_flag(State::DeviceFlags::DEVICE_ERROR);
    EXPECT_FALSE(device_state_->state.has_flag(State::DeviceFlags::DEVICE_ERROR));
}

// Test 2: Verify state handles rapid flag changes (no deadlock)
TEST_F(ErrorHandlingTest, RapidFlagChanges) {
    // Rapidly add/remove flags - should not deadlock
    for (int i = 0; i < 100; i++) {
        device_state_->state.add_flag(State::DeviceFlags::DEVICE_ERROR);
        device_state_->state.remove_flag(State::DeviceFlags::DEVICE_ERROR);
    }
    SUCCEED();
}

// Test 3: Verify multiple error flags can coexist
TEST_F(ErrorHandlingTest, MultipleErrorFlags) {
    device_state_->state.add_flag(State::DeviceFlags::DEVICE_ERROR);
    device_state_->state.add_flag(State::DeviceFlags::BACKPRESSURE_ACTIVE);

    EXPECT_TRUE(device_state_->state.has_flag(State::DeviceFlags::DEVICE_ERROR));
    EXPECT_TRUE(device_state_->state.has_flag(State::DeviceFlags::BACKPRESSURE_ACTIVE));
}

// Test 4: Verify BACKPRESSURE_ACTIVE with EVENT_BUFFERING
TEST_F(ErrorHandlingTest, BackpressureWithBuffering) {
    // Add BACKPRESSURE_ACTIVE
    device_state_->state.add_flag(State::DeviceFlags::BACKPRESSURE_ACTIVE);

    // Give time for listener
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    EXPECT_TRUE(device_state_->state.has_flag(State::DeviceFlags::BACKPRESSURE_ACTIVE));
    EXPECT_TRUE(device_state_->state.has_flag(State::DeviceFlags::EVENT_BUFFERING));
}

// Test 5: Verify event tracking under errors
TEST_F(ErrorHandlingTest, EventTrackingUnderErrors) {
    device_state_->event_queued();
    EXPECT_EQ(device_state_->pending_events.load(), 1);

    device_state_->event_delivered();
    EXPECT_EQ(device_state_->pending_events.load(), 0);
    EXPECT_EQ(device_state_->events_sent.load(), 1);
}

// Test 6: Verify events_dropped tracking
TEST_F(ErrorHandlingTest, EventsDroppedTracking) {
    uint64_t initial = device_state_->events_dropped.load();
    device_state_->events_dropped.fetch_add(5);
    EXPECT_EQ(device_state_->events_dropped.load(), initial + 5);
}
