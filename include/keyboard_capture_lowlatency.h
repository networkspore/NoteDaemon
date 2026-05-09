// keyboard_capture_lowlatency.h
// Low-latency keyboard capture module (lock-free by thread layout)

#ifndef KEYBOARD_CAPTURE_LOWLATENCY_H
#define KEYBOARD_CAPTURE_LOWLATENCY_H

#include <libusb-1.0/libusb.h>
#include <functional>
#include <vector>
#include <atomic>
#include <thread>
#include <cstring>

// HID constants — shared header replaces magic numbers throughout the codebase
#include "hid_constants.h"

// High-performance SPSC queue (lock-free)
#include "dro/spsc-queue.hpp"

// Fixed-size keyboard event - NO HEAP ALLOCATION
struct KeyboardEvent {
    uint8_t data[8];
    uint8_t length;
    uint64_t timestamp_ns;

    KeyboardEvent() : length(0), timestamp_ns(0) {
        memset(data, 0, sizeof(data));
    }
};

class KeyboardCaptureLowLatency {
public:
    using EventCallback      = std::function<void(const KeyboardEvent& event)>;
    using DeviceLostCallback = std::function<void()>;
    using DeviceFoundCallback = std::function<void()>;

    struct Config {
        libusb_context* libusb_ctx = nullptr;
        libusb_device_handle* handle = nullptr;
        int interface_num = -1;
        uint8_t endpoint_in = HidConstants::kDefaultEndpointIn;
        std::string device_id;
        uint16_t vendor_id = 0;
        uint16_t product_id = 0;
        EventCallback on_event;
        DeviceLostCallback on_device_lost;
        DeviceFoundCallback on_device_found;
    };

    explicit KeyboardCaptureLowLatency(const Config& cfg);
    ~KeyboardCaptureLowLatency();

    void start();
    void stop();
    bool is_running() const;

private:
    static void LIBUSB_CALL transfer_callback(libusb_transfer* xfer);

    void capture_loop();
    void process_loop();
    void monitor_loop();
    bool is_device_connected();
    bool find_and_open_device(libusb_device_handle*& handle,
                              int& interface_num,
                              uint8_t& endpoint_in);
    bool reconnect();  // Runs ONLY in capture thread

    Config cfg_;
    libusb_transfer* xfer_ = nullptr;
    std::vector<uint8_t> buffer_;

    std::thread capture_thread_;
    std::thread process_thread_;
    std::thread monitor_thread_;

    std::atomic<bool> running_{false};
    std::atomic<bool> device_lost_{false};
    std::atomic<bool> stop_requested_{false};

    dro::SPSCQueue<KeyboardEvent> event_queue_{HidConstants::kSpscQueueCapacity};
};

#endif // KEYBOARD_CAPTURE_LOWLATENCY_H
