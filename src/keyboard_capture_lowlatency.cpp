// keyboard_capture_lowlatency.cpp
// Low-latency keyboard capture (lock-free by thread layout)

#include "keyboard_capture_lowlatency.h"
#include <iostream>
#include <chrono>
#include <cstring>

KeyboardCaptureLowLatency::KeyboardCaptureLowLatency(const Config& cfg)
    : cfg_(cfg)
{
    buffer_.resize(HidConstants::kHidReportSize, 0); // 8-byte boot protocol
}

KeyboardCaptureLowLatency::~KeyboardCaptureLowLatency() {
    stop();
}

bool KeyboardCaptureLowLatency::find_and_open_device(libusb_device_handle*& handle,
                                                     int& interface_num,
                                                     uint8_t& endpoint_in) {
    if (!cfg_.libusb_ctx || cfg_.vendor_id == 0 || cfg_.product_id == 0) {
        return false;
    }

    libusb_device** dev_list = nullptr;
    ssize_t count = libusb_get_device_list(cfg_.libusb_ctx, &dev_list);
    if (count < 0) return false;

    libusb_device* keyboard = nullptr;
    interface_num = -1;
    endpoint_in = HidConstants::kDefaultEndpointIn;

    for (ssize_t i = 0; i < count; i++) {
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(dev_list[i], &desc) == 0) {
            if (desc.idVendor == cfg_.vendor_id &&
                desc.idProduct == cfg_.product_id) {
                libusb_config_descriptor* config = nullptr;
                if (libusb_get_active_config_descriptor(dev_list[i], &config) == 0) {
                    for (int j = 0; j < config->bNumInterfaces; j++) {
                        const libusb_interface& iface = config->interface[j];
                        for (int k = 0; k < iface.num_altsetting; k++) {
                            const libusb_interface_descriptor& alt = iface.altsetting[k];
                            if (alt.bInterfaceClass == LIBUSB_CLASS_HID) {
                                for (int l = 0; l < alt.bNumEndpoints; l++) {
                                    const libusb_endpoint_descriptor& ep = alt.endpoint[l];
                                    if ((ep.bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) ==
                                        LIBUSB_ENDPOINT_IN) {
                                        interface_num = alt.bInterfaceNumber;
                                        endpoint_in = ep.bEndpointAddress;
                                        keyboard = dev_list[i];
                                        break;
                                    }
                                }
                            }
                            if (keyboard) break;
                        }
                        if (keyboard) break;
                    }
                    libusb_free_config_descriptor(config);
                }
                if (keyboard) break;
            }
        }
    }

    if (!keyboard || interface_num < 0) {
        libusb_free_device_list(dev_list, 1);
        return false;
    }

    int rc = libusb_open(keyboard, &handle);
    libusb_free_device_list(dev_list, 1);

    if (rc != 0) {
        std::cerr << "Failed to open device: " << libusb_error_name(rc) << "\n";
        return false;
    }

    if (libusb_kernel_driver_active(handle, interface_num) == 1) {
        rc = libusb_detach_kernel_driver(handle, interface_num);
        if (rc != 0) {
            std::cerr << "Failed to detach kernel driver: "
                      << libusb_error_name(rc) << "\n";
        }
    }

    rc = libusb_claim_interface(handle, interface_num);
    if (rc != 0) {
        std::cerr << "Failed to claim interface: " << libusb_error_name(rc) << "\n";
        libusb_close(handle);
        handle = nullptr;
        return false;
    }

    std::cout << "Device opened: interface " << interface_num
              << ", endpoint 0x" << std::hex << (int)endpoint_in << std::dec << "\n";
    return true;
}

void KeyboardCaptureLowLatency::start() {
    if (running_.load(std::memory_order_relaxed)) return;

    if (!cfg_.handle && cfg_.vendor_id != 0 && cfg_.product_id != 0) {
        int iface_num;
        uint8_t ep_in;
        if (!find_and_open_device(cfg_.handle, iface_num, ep_in)) {
            std::cerr << "Failed to find/open device\n";
            return;
        }
        cfg_.interface_num = iface_num;
        cfg_.endpoint_in = ep_in;
    }

    if (!cfg_.handle || cfg_.interface_num < 0) {
        std::cerr << "Invalid device configuration\n";
        return;
    }

    running_.store(true, std::memory_order_release);
    stop_requested_.store(false, std::memory_order_release);
    device_lost_.store(false, std::memory_order_release);

    xfer_ = libusb_alloc_transfer(0);
    if (!xfer_) {
        running_.store(false, std::memory_order_release);
        return;
    }

    libusb_fill_interrupt_transfer(
        xfer_,
        cfg_.handle,
        cfg_.endpoint_in,
        buffer_.data(),
        (int)buffer_.size(),
        transfer_callback,
        this,
        0
    );

    int rc = libusb_submit_transfer(xfer_);
    if (rc != 0) {
        std::cerr << "Failed to submit transfer: " << libusb_error_name(rc) << "\n";
        libusb_free_transfer(xfer_);
        xfer_ = nullptr;
        running_.store(false, std::memory_order_release);
        return;
    }

    capture_thread_ = std::thread(&KeyboardCaptureLowLatency::capture_loop, this);
    process_thread_ = std::thread(&KeyboardCaptureLowLatency::process_loop, this);
    monitor_thread_ = std::thread(&KeyboardCaptureLowLatency::monitor_loop, this);

    std::cout << "Low-latency keyboard capture started\n";
}

void KeyboardCaptureLowLatency::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) return;
    stop_requested_.store(true, std::memory_order_release);

    std::cout << "Stopping low-latency capture...\n";

    // Interrupt capture thread's event loop
    if (cfg_.libusb_ctx) {
        libusb_interrupt_event_handler(cfg_.libusb_ctx);
    }

    // Join threads (capture thread cleans up resources)
    if (capture_thread_.joinable()) capture_thread_.join();
    if (monitor_thread_.joinable()) monitor_thread_.join();

    // Signal process thread to exit
    KeyboardEvent sentinel;
    sentinel.length = 0;
    event_queue_.push(sentinel);
    if (process_thread_.joinable()) process_thread_.join();

    std::cout << "Low-latency capture stopped\n";
}

bool KeyboardCaptureLowLatency::is_running() const {
    return running_.load(std::memory_order_relaxed);
}

bool KeyboardCaptureLowLatency::is_device_connected() {
    if (!cfg_.libusb_ctx || cfg_.vendor_id == 0 || cfg_.product_id == 0) {
        return true;
    }

    libusb_device** dev_list = nullptr;
    ssize_t count = libusb_get_device_list(cfg_.libusb_ctx, &dev_list);
    if (count < 0) return true;

    bool found = false;
    for (ssize_t i = 0; i < count; i++) {
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(dev_list[i], &desc) == 0) {
            if (desc.idVendor == cfg_.vendor_id &&
                desc.idProduct == cfg_.product_id) {
                found = true;
                break;
            }
        }
    }

    libusb_free_device_list(dev_list, 1);
    return found;
}

void LIBUSB_CALL KeyboardCaptureLowLatency::transfer_callback(libusb_transfer* xfer) {
    auto* self = static_cast<KeyboardCaptureLowLatency*>(xfer->user_data);

    if (xfer->status == LIBUSB_TRANSFER_COMPLETED && xfer->actual_length > 0) {
        KeyboardEvent event;
        size_t copy_len = (xfer->actual_length < 8) ? static_cast<size_t>(xfer->actual_length) : 8;
        memcpy(event.data, xfer->buffer, copy_len);
        event.length = static_cast<uint8_t>(copy_len);
        event.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

        // Intentionally drop event if queue full (maintains low latency)
        (void)self->event_queue_.try_push(event);
    } else if (xfer->status == LIBUSB_TRANSFER_NO_DEVICE) {
        self->device_lost_.store(true, std::memory_order_release);
        return; // Don't resubmit - capture loop will reconnect
    }

    // Resubmit if still running (and no device loss)
    if (self->running_.load(std::memory_order_relaxed)) {
        int rc = libusb_submit_transfer(xfer);
        if (rc != 0) {
            self->running_.store(false, std::memory_order_release);
        }
    }
}

void KeyboardCaptureLowLatency::capture_loop() {
    while (running_.load(std::memory_order_relaxed)) {
        struct timeval tv = {0, HidConstants::kLibusbPollTimeoutUs}; // 1ms timeout to avoid busy-wait
        libusb_handle_events_timeout_completed(cfg_.libusb_ctx, &tv, nullptr);

        // Handle reconnection if device was lost
        if (device_lost_.load(std::memory_order_acquire)) {
            std::cout << "Device lost, attempting reconnect...\n";
            if (reconnect()) {
                device_lost_.store(false, std::memory_order_release);
                if (cfg_.on_device_found) cfg_.on_device_found();
            }
        }
    }

    // Cleanup before thread exit (capture thread owns these resources)
    if (xfer_) {
        libusb_cancel_transfer(xfer_);
        struct timeval tv = {0, 100000}; // 100ms to process cancel
        libusb_handle_events_timeout(cfg_.libusb_ctx, &tv);
        libusb_free_transfer(xfer_);
        xfer_ = nullptr;
    }
    if (cfg_.handle) {
        if (cfg_.interface_num >= 0) {
            libusb_release_interface(cfg_.handle, cfg_.interface_num);
        }
        libusb_close(cfg_.handle);
        cfg_.handle = nullptr;
    }
}

void KeyboardCaptureLowLatency::process_loop() {
    KeyboardEvent event;
    while (true) {
        if (event_queue_.try_pop(event)) {
            if (event.length == 0) break; // Sentinel
            if (cfg_.on_event) cfg_.on_event(event);
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }
    // Drain remaining events
    while (event_queue_.try_pop(event)) {
        if (event.length > 0 && cfg_.on_event) cfg_.on_event(event);
    }
}

void KeyboardCaptureLowLatency::monitor_loop() {
    while (!stop_requested_.load(std::memory_order_relaxed)) {
        if (device_lost_.load(std::memory_order_relaxed)) {
            if (cfg_.on_device_lost) cfg_.on_device_lost();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

bool KeyboardCaptureLowLatency::reconnect() {
    // Must only run in capture thread (owns xfer_, handle, etc.)

    // Cleanup current state
    if (xfer_) {
        libusb_cancel_transfer(xfer_);
        struct timeval tv = {0, 100000};
        libusb_handle_events_timeout(cfg_.libusb_ctx, &tv);
        libusb_free_transfer(xfer_);
        xfer_ = nullptr;
    }
    if (cfg_.handle) {
        if (cfg_.interface_num >= 0) {
            libusb_release_interface(cfg_.handle, cfg_.interface_num);
        }
        libusb_close(cfg_.handle);
        cfg_.handle = nullptr;
    }
    cfg_.interface_num = -1;
    cfg_.endpoint_in = HidConstants::kDefaultEndpointIn;

    // Find and open new device
    libusb_device_handle* new_handle = nullptr;
    int iface_num;
    uint8_t ep_in;
    if (!find_and_open_device(new_handle, iface_num, ep_in)) {
        std::cerr << "Reconnect failed: could not find/open device\n";
        return false;
    }

    // Update state
    cfg_.handle = new_handle;
    cfg_.interface_num = iface_num;
    cfg_.endpoint_in = ep_in;

    // Allocate and submit new transfer
    xfer_ = libusb_alloc_transfer(0);
    if (!xfer_) {
        libusb_close(cfg_.handle);
        cfg_.handle = nullptr;
        return false;
    }

    libusb_fill_interrupt_transfer(xfer_, cfg_.handle, cfg_.endpoint_in,
        buffer_.data(), (int)buffer_.size(), transfer_callback, this, 0);

    int rc = libusb_submit_transfer(xfer_);
    if (rc != 0) {
        std::cerr << "Reconnect failed: " << libusb_error_name(rc) << "\n";
        libusb_free_transfer(xfer_);
        xfer_ = nullptr;
        libusb_close(cfg_.handle);
        cfg_.handle = nullptr;
        return false;
    }

    return true;
}
