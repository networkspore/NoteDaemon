// keyboard_capture_lowlatency.h
// Low-latency keyboard capture module.
// Based on diagnose_keyboard_clean.cpp pattern that captures ALL events.
// Uses lock-free queue to separate fast capture from slow processing.

#ifndef KEYBOARD_CAPTURE_LOWLATENCY_H
#define KEYBOARD_CAPTENCY_LOWLATENCY_H

#include <libusb-1.0/libusb.h>
#include <functional>
#include <memory>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <queue>

// Simple lock-free single-producer, single-consumer queue
// (In production, use a proper lock-free queue like moodycamel::ConcurrentQueue)
template<typename T>
class SPSCQueue {
private:
    static constexpr size_t QUEUE_SIZE = 1024;
    T buffer_[QUEUE_SIZE];
    std::atomic<size_t> write_pos_{0};
    std::atomic<size_t> read_pos_{0};
    
public:
    bool push(const T& item) {
        size_t wp = write_pos_.load(std::memory_order_relaxed);
        size_t rp = read_pos_.load(std::memory_order_acquire);
        size_t next_wp = (wp + 1) % QUEUE_SIZE;
        
        if (next_wp == rp) {
            return false; // Full
        }
        
        buffer_[wp] = item;
        write_pos_.store(next_wp, std::memory_order_release);
        return true;
    }
    
    bool pop(T& item) {
        size_t rp = read_pos_.load(std::memory_order_relaxed);
        size_t wp = write_pos_.load(std::memory_order_acquire);
        
        if (rp == wp) {
            return false; // Empty
        }
        
        item = buffer_[rp];
        read_pos_.store((rp + 1) % QUEUE_SIZE, std::memory_order_release);
        return true;
    }
    
    bool empty() const {
        return read_pos_.load(std::memory_order_acquire) == 
               write_pos_.load(std::memory_order_acquire);
    }
};

// Fixed-size keyboard event - NO HEAP ALLOCATION
struct KeyboardEvent {
    uint8_t data[8];  // Fixed 8-byte boot protocol report
    uint8_t length;    // Actual length (≤ 8)
    uint64_t timestamp_ns;
};



class KeyboardCaptureLowLatency {
public:
    using EventCallback = std::function<void(const KeyboardEvent& event)>;
    
    struct Config {
        libusb_context* libusb_ctx = nullptr;
        libusb_device_handle* handle = nullptr;
        int interface_num = -1;
        uint8_t endpoint_in = 0x81;
        std::string device_id;
        EventCallback on_event;
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
    
    Config cfg_;
    libusb_transfer* xfer_ = nullptr;
    std::vector<uint8_t> buffer_;
    
    std::thread capture_thread_;
    std::thread process_thread_;
    std::atomic<bool> running_{false};
    
    SPSCQueue<KeyboardEvent> event_queue_;
};

#endif // KEYBOARD_CAPTURE_LOWLATENCY_H
