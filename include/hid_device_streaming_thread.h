#ifndef HID_DEVICE_STREAMING_THREAD_H
#define HID_DEVICE_STREAMING_THREAD_H

#include "device_streaming_thread.h"
#include "usb_device_descriptor.h"
#include "state.h"
#include "input_packet.h"
#include "hid_parser.h"
#include <libusb-1.0/libusb.h>
#include <thread>
#include <atomic>
#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <syslog.h>

class HIDDeviceStreamingThread : public DeviceStreamingThread {
private:
    std::shared_ptr<USBDeviceDescriptor> device_;
    std::shared_ptr<State::DeviceState> device_state_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    int client_fd_;
    std::unique_ptr<InputPacket::Factory> packet_factory_;
    std::unique_ptr<HIDParser::KeyboardParser> keyboard_parser_;

    // Event queue for backpressure handling
    std::queue<std::vector<uint8_t>> event_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
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
        if (running_) return;

        running_ = true;
        paused_ = false;
        thread_ = std::thread(&HIDDeviceStreamingThread::stream_loop, this);
        syslog(LOG_INFO, "Started streaming thread for device %s", device_->device_id.c_str());
    }

    void stop() override {
        if (!running_) return;

        running_ = false;
        paused_ = false;

        // Wake up the thread if it's waiting
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            queue_cv_.notify_all();
        }

        if (thread_.joinable()) {
            thread_.join();
        }

        syslog(LOG_INFO, "Stopped streaming thread for device %s", device_->device_id.c_str());
    }

    bool is_running() const override {
        return running_;
    }

private:
    void stream_loop() {
        const int ENDPOINT_IN = 0x81;   // Interrupt IN endpoint
        const int TIMEOUT_MS = 1000;
        uint8_t buffer[64]; // HID report buffer

        while (running_) {
            if (paused_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            // Check backpressure
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                if (event_queue_.size() >= MAX_QUEUE_SIZE) {
                    device_state_->state.add_flag(State::DeviceFlags::BACKPRESSURE_ACTIVE);
                    queue_cv_.wait(lock, [this]() {
                        return !running_ || event_queue_.size() < MAX_QUEUE_SIZE / 2;
                    });
                    device_state_->state.remove_flag(State::DeviceFlags::BACKPRESSURE_ACTIVE);
                    continue;
                }
            }

            int transferred = 0;
            int result = libusb_interrupt_transfer(device_->handle, ENDPOINT_IN,
                                                 buffer, sizeof(buffer), &transferred, TIMEOUT_MS);

            if (result == LIBUSB_ERROR_TIMEOUT) {
                continue; // No data, try again
            }

            if (result != LIBUSB_SUCCESS) {
                syslog(LOG_ERR, "USB transfer error for device %s: %s",
                       device_->device_id.c_str(), libusb_error_name(result));
                device_state_->state.add_flag(State::DeviceFlags::TRANSFER_ERROR);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            if (transferred > 0) {
                process_hid_report(buffer, transferred);
            }
        }
    }

    void process_hid_report(const uint8_t* data, int length) {
        // For now, assume keyboard reports and use the keyboard parser
        // In a full implementation, you'd detect device type and use appropriate parser
        auto events = keyboard_parser_->parse_report(data, length);

        for (const auto& event_packet : events) {
            queue_event(event_packet);
        }
    }

    void queue_event(const std::vector<uint8_t>& event_packet) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (event_queue_.size() >= MAX_QUEUE_SIZE) {
                device_state_->events_dropped.fetch_add(1);
                return;
            }
            event_queue_.push(event_packet);
            device_state_->event_queued();
        }

        // Try to send immediately if possible
        send_pending_events();
    }

    void send_pending_events() {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        while (!event_queue_.empty() && running_) {
            const auto& packet = event_queue_.front();

            // Send to client socket
            ssize_t sent = write(client_fd_, packet.data(), packet.size());
            if (sent == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Client can't accept more data, wait
                    break;
                } else {
                    syslog(LOG_ERR, "Failed to send event to client: %s", strerror(errno));
                    running_ = false;
                    break;
                }
            }

            event_queue_.pop();
            device_state_->event_delivered();
        }

        queue_cv_.notify_all();
    }
};

#endif // HID_DEVICE_STREAMING_THREAD_H