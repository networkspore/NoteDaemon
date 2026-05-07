#ifndef HID_DEVICE_STREAMING_THREAD_H
#define HID_DEVICE_STREAMING_THREAD_H

#include "device_streaming_thread.h"
#include "usb_device_descriptor.h"
#include "state.h"
#include "input_packet.h"
#include "hid_parser.h"
#include "keyboard_capture_lowlatency.h"  // for dro::SPSCQueue
#include <libusb-1.0/libusb.h>
#include <thread>
#include <atomic>
#include <memory>
#include <vector>
#include <cstring>
#include <syslog.h>
#include <deque>

// Lock-free event type for passing HID reports between capture and process threads
struct HIDReportEvent {
    std::vector<uint8_t> data;
    uint64_t timestamp_ns;
    bool is_sentinel;  // true for stop signal

    HIDReportEvent() : timestamp_ns(0), is_sentinel(false) {}
    explicit HIDReportEvent(const uint8_t* d, int length)
        : data(d, d + length), timestamp_ns(0), is_sentinel(false) {}
    static HIDReportEvent sentinel() {
        HIDReportEvent e;
        e.is_sentinel = true;
        return e;
    }
};

class HIDDeviceStreamingThread : public DeviceStreamingThread {
private:
    std::shared_ptr<USBDeviceDescriptor> device_;
    std::shared_ptr<State::DeviceState> device_state_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> paused_{false};
    int client_fd_;
    std::unique_ptr<InputPacket::Factory> packet_factory_;
    std::unique_ptr<HIDParser::KeyboardParser> keyboard_parser_;

    // Async USB transfer
    libusb_transfer* xfer_ = nullptr;

    // Threads: capture (libusb event loop) and process (send to client)
    std::thread capture_thread_;
    std::thread process_thread_;

    // Lock-free queue for passing events (SPSC: capture -> process)
    dro::SPSCQueue<HIDReportEvent> spsc_queue_{1024};

    // Event queue for sending to client (backpressure handling, single-threaded)
    std::deque<std::vector<uint8_t>> client_queue_;
    static constexpr size_t MAX_QUEUE_SIZE = 1000;

public:
    HIDDeviceStreamingThread(std::shared_ptr<USBDeviceDescriptor> device,
                           std::shared_ptr<State::DeviceState> device_state,
                           int client_fd)
        : device_(device), device_state_(device_state), client_fd_(client_fd) {
        packet_factory_ = std::make_unique<InputPacket::Factory>(device_->device_id);
        keyboard_parser_ = std::make_unique<HIDParser::KeyboardParser>(packet_factory_.get());
    }

    ~HIDDeviceStreamingThread() override {
        stop();
    }

    void start() override {
        if (running_.load(std::memory_order_relaxed)) return;

        running_.store(true, std::memory_order_release);
        stop_requested_.store(false, std::memory_order_release);
        paused_.store(false, std::memory_order_release);

        // Allocate transfer
        xfer_ = libusb_alloc_transfer(0);
        if (!xfer_) {
            syslog(LOG_ERR, "Failed to allocate libusb transfer for %s",
                   device_->device_id.c_str());
            running_.store(false, std::memory_order_release);
            return;
        }

        // Allocate buffer for transfer
        uint8_t* buffer = new (std::nothrow) uint8_t[64];
        if (!buffer) {
            libusb_free_transfer(xfer_);
            xfer_ = nullptr;
            running_.store(false, std::memory_order_release);
            return;
        }

        // Get endpoint from device - use a default if not stored in device
        uint8_t endpoint_in = 0x81; // Default interrupt IN endpoint

        // Fill interrupt transfer
        libusb_fill_interrupt_transfer(
            xfer_,
            device_->handle,
            endpoint_in,
            buffer,
            64,
            &HIDDeviceStreamingThread::transfer_callback,
            this,
            0  // no timeout - handled by event loop
        );

        int rc = libusb_submit_transfer(xfer_);
        if (rc != LIBUSB_SUCCESS) {
            syslog(LOG_ERR, "Failed to submit transfer for %s: %s",
                   device_->device_id.c_str(), libusb_error_name(rc));
            delete[] buffer;
            libusb_free_transfer(xfer_);
            xfer_ = nullptr;
            running_.store(false, std::memory_order_release);
            return;
        }

        // Start threads
        capture_thread_ = std::thread(&HIDDeviceStreamingThread::capture_loop, this);
        process_thread_ = std::thread(&HIDDeviceStreamingThread::process_loop, this);

        syslog(LOG_INFO, "Started async streaming thread for device %s", device_->device_id.c_str());
    }

    void stop() override {
        if (!running_.exchange(false, std::memory_order_acq_rel)) return;
        stop_requested_.store(true, std::memory_order_release);

        // Signal process thread to exit
        (void)spsc_queue_.try_push(HIDReportEvent::sentinel());

        // Cancel transfer (will make capture loop exit)
        if (xfer_) {
            libusb_cancel_transfer(xfer_);
        }

        // Join threads
        if (capture_thread_.joinable()) capture_thread_.join();
        if (process_thread_.joinable()) process_thread_.join();

        // Cleanup transfer
        if (xfer_) {
            // Buffer is freed by libusb after transfer completes or is cancelled
            libusb_free_transfer(xfer_);
            xfer_ = nullptr;
        }

        syslog(LOG_INFO, "Stopped streaming thread for device %s", device_->device_id.c_str());
    }

    bool is_running() const override {
        return running_.load(std::memory_order_relaxed);
    }

private:
    static void LIBUSB_CALL transfer_callback(libusb_transfer* xfer) {
        auto* self = static_cast<HIDDeviceStreamingThread*>(xfer->user_data);

        if (xfer->status == LIBUSB_TRANSFER_COMPLETED && xfer->actual_length > 0) {
            // Push event to queue (lock-free, drop if full to maintain low latency)
            HIDReportEvent event(xfer->buffer, xfer->actual_length);
            event.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();

            if (!self->spsc_queue_.try_push(event)) {
                // Queue full, drop event (maintains low latency)
                self->device_state_->events_dropped.fetch_add(1, std::memory_order_relaxed);
            }
        } else if (xfer->status == LIBUSB_TRANSFER_NO_DEVICE) {
            // Device disconnected - notify via queue
            self->notify_device_lost();
        }

        // Resubmit if still running
        if (self->running_.load(std::memory_order_relaxed) &&
            xfer->status != LIBUSB_TRANSFER_NO_DEVICE) {
            int rc = libusb_submit_transfer(xfer);
            if (rc != LIBUSB_SUCCESS) {
                syslog(LOG_ERR, "Failed to resubmit transfer: %s", libusb_error_name(rc));
                self->running_.store(false, std::memory_order_release);
            }
        }
    }

    void capture_loop() {
        // This thread runs the libusb event loop
        // Use the device's libusb context if available, otherwise nullptr (default context)
        libusb_context* ctx = device_ ? nullptr : nullptr; // extend if ctx stored in device_

        struct timeval tv = {0, 1000}; // 1ms timeout to avoid busy-wait

        while (running_.load(std::memory_order_relaxed)) {
            libusb_handle_events_timeout_completed(ctx, &tv, nullptr);
        }

        // Cleanup: wait for cancelled transfer to complete
        struct timeval tv2 = {0, 100000}; // 100ms
        libusb_handle_events_timeout_completed(ctx, &tv2, nullptr);

        // Free buffer after transfer is done
        if (xfer_ && xfer_->buffer) {
            delete[] xfer_->buffer;
            xfer_->buffer = nullptr;
        }
    }

    void process_loop() {
        HIDReportEvent event;

        while (true) {
            if (spsc_queue_.try_pop(event)) {
                if (event.is_sentinel) break;  // Stop signal

                process_hid_report(event.data.data(), (int)event.data.size());
            } else {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }

        // Drain remaining events
        while (spsc_queue_.try_pop(event)) {
            if (!event.is_sentinel && !event.data.empty()) {
                process_hid_report(event.data.data(), (int)event.data.size());
            }
        }
    }

    void process_hid_report(const uint8_t* data, int length) {
        auto events = keyboard_parser_->parse_report(data, length);

        for (const auto& event_packet : events) {
            queue_event(event_packet);
        }
    }

    void queue_event(const std::vector<uint8_t>& event_packet) {
        if (client_queue_.size() >= MAX_QUEUE_SIZE) {
            device_state_->events_dropped.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        client_queue_.push_back(event_packet);
        device_state_->event_queued();

        // Try to send immediately if possible
        send_pending_events();
    }

    void send_pending_events() {
        while (!client_queue_.empty() && running_) {
            const auto& packet = client_queue_.front();

            ssize_t sent = write(client_fd_, packet.data(), packet.size());
            if (sent == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                } else {
                    syslog(LOG_ERR, "Failed to send event to client: %s", strerror(errno));
                    running_.store(false, std::memory_order_release);
                    break;
                }
            }

            client_queue_.pop_front();
            device_state_->event_delivered();
        }
    }

    void notify_device_lost() {
        // This is called from the callback context - just stop and let
        // the device session handle reconnection
        running_.store(false, std::memory_order_release);
        // Signal the process thread to exit
        (void)spsc_queue_.try_push(HIDReportEvent::sentinel());

        syslog(LOG_WARNING, "Device %s disconnected during async transfer",
               device_->device_id.c_str());
    }
};

#endif // HID_DEVICE_STREAMING_THREAD_H