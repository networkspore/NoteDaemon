#include "../include/key_code.h"
#include <gtest/gtest.h>
#include <vector>
#include <cstring>

class KeyCodeTest : public ::testing::Test {
protected:
    void TearDown() override {}
};

// Test KeyCode::hid_modifiers_to_state_flags
TEST_F(KeyCodeTest, ModifierToStateFlags) {
    // MOD_LEFT_CTRL (0x01) should map to MOD_CONTROL
    EXPECT_EQ(KeyCode::hid_modifiers_to_state_flags(0x01), EventBytes::StateFlags::MOD_CONTROL);
    // MOD_LEFT_SHIFT (0x02) should map to MOD_SHIFT
    EXPECT_EQ(KeyCode::hid_modifiers_to_state_flags(0x02), EventBytes::StateFlags::MOD_SHIFT);
    // MOD_LEFT_ALT (0x04) should map to MOD_ALT
    EXPECT_EQ(KeyCode::hid_modifiers_to_state_flags(0x04), EventBytes::StateFlags::MOD_ALT);
    // MOD_LEFT_GUI (0x08) should map to MOD_SUPER
    EXPECT_EQ(KeyCode::hid_modifiers_to_state_flags(0x08), EventBytes::StateFlags::MOD_SUPER);
}

// Test KeyCode::is_printable_key
TEST_F(KeyCodeTest, IsPrintableKey) {
    EXPECT_TRUE(KeyCode::is_printable_key(0x04)); // 'a'
    EXPECT_TRUE(KeyCode::is_printable_key(0x05)); // 'b'
    EXPECT_TRUE(KeyCode::is_printable_key(0x20)); // ' '
    EXPECT_FALSE(KeyCode::is_printable_key(0x01)); // Error rollover
    EXPECT_FALSE(KeyCode::is_printable_key(0x00)); // No key
}

// Test KeyCode::hid_usage_to_virtual_key
TEST_F(KeyCodeTest, HIDUsageToVirtualKey) {
    // For now, use HID usage ID directly as virtual key
    EXPECT_EQ(KeyCode::hid_usage_to_virtual_key(0x04), 0x04); // 'a' usage
    EXPECT_EQ(KeyCode::hid_usage_to_virtual_key(0x05), 0x05); // 'b' usage
}

// Test KeyCode::hid_usage_to_scancode
TEST_F(KeyCodeTest, HIDUsageToScancode) {
    // For now, use HID usage ID as scancode
    EXPECT_EQ(KeyCode::hid_usage_to_scancode(0x04), 0x04); // 'a' scancode
    EXPECT_EQ(KeyCode::hid_usage_to_scancode(0x05), 0x05); // 'b' scancode
}

// Test KeyCode::hid_usage_to_codepoint
TEST_F(KeyCodeTest, HIDUsageToCodepoint) {
    EXPECT_EQ(KeyCode::hid_usage_to_codepoint(0x04, false), 0x61); // 'a' lowercase
    EXPECT_EQ(KeyCode::hid_usage_to_codepoint(0x04, true), 0x41); // 'a' uppercase
}

// Test KeyCode::MOD constants
TEST_F(KeyCodeTest, MODConstants) {
    EXPECT_EQ(KeyCode::MOD_LEFT_CTRL, 0x01);
    EXPECT_EQ(KeyCode::MOD_LEFT_SHIFT, 0x02);
    EXPECT_EQ(KeyCode::MOD_LEFT_ALT, 0x04);
    EXPECT_EQ(KeyCode::MOD_LEFT_GUI, 0x08);
    EXPECT_EQ(KeyCode::MOD_RIGHT_CTRL, 0x10);
    EXPECT_EQ(KeyCode::MOD_RIGHT_SHIFT, 0x20);
    EXPECT_EQ(KeyCode::MOD_RIGHT_ALT, 0x40);
    EXPECT_EQ(KeyCode::MOD_RIGHT_GUI, 0x80);
}

// Test KeyCode::STATE_FLAGS
TEST_F(KeyCodeTest, StateFlagsConstants) {
    EXPECT_EQ(EventBytes::StateFlags::MOD_SHIFT, 0x0001);
    EXPECT_EQ(EventBytes::StateFlags::MOD_CONTROL, 0x0002);
    EXPECT_EQ(EventBytes::StateFlags::MOD_ALT, 0x0004);
    EXPECT_EQ(EventBytes::StateFlags::MOD_SUPER, 0x0008);
    EXPECT_EQ(EventBytes::StateFlags::MOD_CAPS_LOCK, 0x0010);
    EXPECT_EQ(EventBytes::StateFlags::MOD_NUM_LOCK, 0x0020);
    EXPECT_EQ(EventBytes::StateFlags::MOD_SCROLL_LOCK, 0x0040);
}

// Test KeyCode::KEY constants
TEST_F(KeyCodeTest, KeyConstants) {
    EXPECT_EQ(KeyCode::KEY_A, 0x04);
    EXPECT_EQ(KeyCode::KEY_B, 0x05);
    EXPECT_EQ(KeyCode::KEY_C, 0x06);
    EXPECT_EQ(KeyCode::KEY_Z, 0x1D);
    EXPECT_EQ(KeyCode::KEY_0, 0x27);
    EXPECT_EQ(KeyCode::KEY_1, 0x1E);
}
