#include "../include/state.h"
#include "../include/event_bytes.h"
#include <gtest/gtest.h>
#include <vector>
#include <cstring>

class DeviceSessionTest : public ::testing::Test {
protected:
    cpp_int state;
    cpp_int registry;

    void SetUp() override {
        state = 0;
        registry = 0;
    }
};

// Test state initialization
TEST_F(DeviceSessionTest, StateInit) {
    EXPECT_EQ(state, 0);
}

// Test capability registry add
TEST_F(DeviceSessionTest, CapabilityRegistryAdd) {
    // Add a capability
    State::bit_set(registry, Capabilities::Bits::ENCRYPTION_SUPPORTED);

    EXPECT_TRUE(State::bit_test(registry, Capabilities::Bits::ENCRYPTION_SUPPORTED));
}

// Test capability registry check
TEST_F(DeviceSessionTest, CapabilityRegistryCheck) {
    uint32_t caps = Capabilities::Bits::ENCRYPTION_SUPPORTED;
    State::bit_set(registry, caps);

    EXPECT_TRUE(State::bit_test(registry, caps));
    EXPECT_FALSE(State::bit_test(registry, Capabilities::Bits::BUFFERING_SUPPORTED));
}

// Test capability registry union
TEST_F(DeviceSessionTest, CapabilityRegistryUnion) {
    uint32_t caps1 = Capabilities::Bits::ENCRYPTION_SUPPORTED;
    uint32_t caps2 = Capabilities::Bits::BUFFERING_SUPPORTED;
    uint32_t combined = caps1 | caps2;

    State::bit_set(registry, caps1);
    State::bit_set(registry, caps2);

    EXPECT_TRUE(State::bit_test(registry, combined));
}

// Test capability registry intersection
TEST_F(DeviceSessionTest, CapabilityRegistryIntersection) {
    uint32_t caps1 = Capabilities::Bits::ENCRYPTION_SUPPORTED | Capabilities::Bits::BUFFERING_SUPPORTED;
    uint32_t caps2 = Capabilities::Bits::BUFFERING_SUPPORTED;

    State::bit_set(registry, caps1);
    State::bit_set(registry, caps2);

    EXPECT_TRUE(State::bit_test(registry, Capabilities::Bits::BUFFERING_SUPPORTED));
    EXPECT_FALSE(State::bit_test(registry, Capabilities::Bits::ENCRYPTION_SUPPORTED));
}

// Test capability registry clear
TEST_F(DeviceSessionTest, CapabilityRegistryClear) {
    uint32_t caps = Capabilities::Bits::ENCRYPTION_SUPPORTED;
    State::bit_set(registry, caps);

    EXPECT_EQ(State::bit_test(registry, caps), true);

    // Clear by resetting capability count
    registry = 0;

    EXPECT_EQ(State::bit_test(registry, caps), false);
}

// Test multiple state flags
TEST_F(DeviceSessionTest, MultipleStateFlags) {
    // Set all common state flags
    int state_flags = EventBytes::StateFlags::MOD_SHIFT;
    state_flags |= EventBytes::StateFlags::MOD_CONTROL;
    state_flags |= EventBytes::StateFlags::MOD_ALT;
    state_flags |= EventBytes::StateFlags::MOD_SUPER;
    state_flags |= EventBytes::StateFlags::MOD_CAPS_LOCK;
    state_flags |= EventBytes::StateFlags::MOD_NUM_LOCK;
    state_flags |= EventBytes::StateFlags::MOD_SCROLL_LOCK;

    EXPECT_EQ(state_flags, (EventBytes::StateFlags::MOD_SHIFT |
                            EventBytes::StateFlags::MOD_CONTROL |
                            EventBytes::StateFlags::MOD_ALT |
                            EventBytes::StateFlags::MOD_SUPER |
                            EventBytes::StateFlags::MOD_CAPS_LOCK |
                            EventBytes::StateFlags::MOD_NUM_LOCK |
                            EventBytes::StateFlags::MOD_SCROLL_LOCK));
}
