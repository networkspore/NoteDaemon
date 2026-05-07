// keyboard_capture_lowlatency_test.cpp
// Unit tests for the low-latency keyboard capture module

#include "keyboard_capture_lowlatency.h"
#include "dro/spsc-queue.hpp"
#include "hid_device_streaming_thread.h"
#include <gtest/gtest.h>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>

// Test KeyboardEvent struct initialization
TEST(KeyboardEventTest, DefaultInitialization) {
    KeyboardEvent event;
    EXPECT_EQ(event.length, 0u);
    EXPECT_EQ(event.timestamp_ns, 0u);
    for (int i = 0; i < 8; i++) {
        EXPECT_EQ(event.data[i], 0);
    }
}

TEST(KeyboardEventTest, CopySemantics) {
    KeyboardEvent event;
    event.data[0] = 0x01;
    event.data[1] = 0x02;
    event.length = 2;
    event.timestamp_ns = 12345;

    KeyboardEvent copy = event;
    EXPECT_EQ(copy.data[0], 0x01);
    EXPECT_EQ(copy.data[1], 0x02);
    EXPECT_EQ(copy.length, 2);
    EXPECT_EQ(copy.timestamp_ns, 12345);
}

// Test SPSCQueue operations
TEST(SPSCQueueTest, BasicPushPop) {
    dro::SPSCQueue<KeyboardEvent> queue(64);

    KeyboardEvent in;
    in.data[0] = 0x01;
    in.length = 1;
    in.timestamp_ns = 100;

    EXPECT_TRUE(queue.try_push(in));

    KeyboardEvent out;
    EXPECT_TRUE(queue.try_pop(out));
    EXPECT_EQ(out.data[0], 0x01);
    EXPECT_EQ(out.length, 1);
    EXPECT_EQ(out.timestamp_ns, 100u);
}

TEST(SPSCQueueTest, EmptyQueuePop) {
    dro::SPSCQueue<KeyboardEvent> queue(64);
    KeyboardEvent out;
    EXPECT_FALSE(queue.try_pop(out));
}

TEST(SPSCQueueTest, FullQueuePush) {
    dro::SPSCQueue<KeyboardEvent> queue(4);

    KeyboardEvent event;
    for (int i = 0; i < 4; i++) {
        event.data[0] = static_cast<uint8_t>(i);
        EXPECT_TRUE(queue.try_push(event));
    }

    EXPECT_FALSE(queue.try_push(event));
}

// Test KeyboardCaptureLowLatency configuration
TEST(KeyboardCaptureLowLatencyConfigTest, ValidConfig) {
    KeyboardCaptureLowLatency::Config cfg;
    cfg.vendor_id = 0x1234;
    cfg.product_id = 0x5678;
    cfg.endpoint_in = 0x81;

    EXPECT_EQ(cfg.vendor_id, 0x1234);
    EXPECT_EQ(cfg.product_id, 0x5678);
    EXPECT_EQ(cfg.endpoint_in, 0x81);
    EXPECT_EQ(cfg.interface_num, -1);
    EXPECT_FALSE(static_cast<bool>(cfg.on_event));
    EXPECT_FALSE(static_cast<bool>(cfg.on_device_lost));
    EXPECT_FALSE(static_cast<bool>(cfg.on_device_found));
}

TEST(KeyboardCaptureLowLatencyConfigTest, CallbackAssignment) {
    KeyboardCaptureLowLatency::Config cfg;

    bool event_called = false;
    cfg.on_event = [&event_called](const KeyboardEvent& ev) {
        event_called = true;
    };

    bool lost_called = false;
    cfg.on_device_lost = [&lost_called]() {
        lost_called = true;
    };

    bool found_called = false;
    cfg.on_device_found = [&found_called]() {
        found_called = true;
    };

    KeyboardEvent ev;
    cfg.on_event(ev);
    EXPECT_TRUE(event_called);

    cfg.on_device_lost();
    EXPECT_TRUE(lost_called);

    cfg.on_device_found();
    EXPECT_TRUE(found_called);
}

TEST(KeyboardCaptureLowLatencyTest, IsRunningDefaultsToFalse) {
    KeyboardCaptureLowLatency::Config cfg;
    cfg.vendor_id = 0x1234;
    cfg.product_id = 0x5678;

    KeyboardCaptureLowLatency capture(cfg);
    EXPECT_FALSE(capture.is_running());
}

TEST(KeyboardCaptureLowLatencyTest, StartStopNoDevice) {
    KeyboardCaptureLowLatency::Config cfg;
    cfg.vendor_id = 0x1234;
    cfg.product_id = 0x5678;

    KeyboardCaptureLowLatency capture(cfg);
    capture.stop();
    EXPECT_FALSE(capture.is_running());
}

// Test HIDReportEvent (used in HIDDeviceStreamingThread)
TEST(HIDReportEventTest, DefaultInitialization) {
    HIDReportEvent event;
    EXPECT_TRUE(event.data.empty());
    EXPECT_EQ(event.timestamp_ns, 0u);
    EXPECT_FALSE(event.is_sentinel);
}

TEST(HIDReportEventTest, DataInitialization) {
    uint8_t data[] = {0x01, 0x02, 0x03};
    HIDReportEvent event(data, 3);
    EXPECT_EQ(event.data.size(), 3u);
    EXPECT_EQ(event.data[0], 0x01);
    EXPECT_EQ(event.data[1], 0x02);
    EXPECT_EQ(event.data[2], 0x03);
    EXPECT_FALSE(event.is_sentinel);
}

TEST(HIDReportEventTest, SentinelCreation) {
    HIDReportEvent event = HIDReportEvent::sentinel();
    EXPECT_TRUE(event.is_sentinel);
}

// Test HIDReportEvent SPSC queue operations
TEST(HIDReportEventQueueTest, PushPop) {
    dro::SPSCQueue<HIDReportEvent> queue(64);

    uint8_t data[] = {0x01, 0x02};
    HIDReportEvent in(data, 2);
    in.timestamp_ns = 999;

    EXPECT_TRUE(queue.try_push(in));

    HIDReportEvent out;
    EXPECT_TRUE(queue.try_pop(out));
    EXPECT_EQ(out.data.size(), 2u);
    EXPECT_EQ(out.data[0], 0x01);
    EXPECT_EQ(out.timestamp_ns, 999u);
}

TEST(HIDReportEventQueueTest, SentinelStopsLoop) {
    dro::SPSCQueue<HIDReportEvent> queue(64);

    EXPECT_TRUE(queue.try_push(HIDReportEvent::sentinel()));

    HIDReportEvent out;
    EXPECT_TRUE(queue.try_pop(out));
    EXPECT_TRUE(out.is_sentinel);
}
