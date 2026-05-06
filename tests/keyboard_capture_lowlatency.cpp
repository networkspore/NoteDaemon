// keyboard_capture_lowlatency.cpp
// Low-latency keyboard capture based on diagnose_keyboard_clean.cpp pattern.
// 
// Key design principles:
// 1. Capture thread uses callback with immediate transfer re-submission
// 2. MINIMAL work in callback - just memcpy to fixed buffer + push to queue
// 3. NO heap allocations in callback path
// 4. Separate processing thread for parsing (can be slower without affecting capture)

#include "keyboard_capture_lowlatency.h"
#include <iostream>
#include <chrono>
#include <cstring>

KeyboardCaptureLowLatency::KeyboardCaptureLowLatency(const Config& cfg)
    : cfg_(cfg)
{
    buffer_.resize(8, 0); // 8-byte boot protocol
}

KeyboardCaptureLowLatency::~KeyboardCaptureLowLatency() {
    stop();
}

void KeyboardCaptureLowLatency::start() {
    if (running_.load(std::memory_order_relaxed)) return;
    
    running_.store(true, std::memory_order_release);
    
    // Allocate transfer
    xfer_ = libusb_alloc_transfer(0);
    if (!xfer_) {
        running_.store(false, std::memory_order_release);
        return;
    }
    
    // Set up interrupt transfer (same as diagnose_keyboard_clean)
    libusb_fill_interrupt_transfer(
        xfer_,
        cfg_.handle,
        cfg_.endpoint_in,
        buffer_.data(),
        (int)buffer_.size(),
        transfer_callback,
        this,
        0  // No timeout - let the device dictate polling
    );
    
    // Submit the transfer
    int rc = libusb_submit_transfer(xfer_);
    if (rc != 0) {
        std::cerr << "Failed to submit transfer: " << libusb_error_name(rc) << "\n";
        libusb_free_transfer(xfer_);
        xfer_ = nullptr;
        running_.store(false, std::memory_order_release);
        return;
    }
    
    // Start capture thread (handles libusb events)
    capture_thread_ = std::thread(&KeyboardCaptureLowLatency::capture_loop, this);
    
    // Start processing thread (handles event callbacks)
    process_thread_ = std::thread(&KeyboardCaptureLowLatency::process_loop, this);
    
    std::cout << "Low-latency keyboard capture started\n";
}

void KeyboardCaptureLowLatency::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) return;
    
    std::cout << "Stopping low-latency capture...\n";
    
    // Cancel transfer
    if (xfer_) {
        libusb_cancel_transfer(xfer_);
    }
    
    // Signal event loop to exit
    if (cfg_.libusb_ctx) {
        libusb_interrupt_event_handler(cfg_.libusb_ctx);
    }
    
    // Wait for capture thread
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    
    // Push sentinel to wake up process thread (use length=0 as sentinel)
    KeyboardEvent sentinel;
    sentinel.length = 0; // Length 0 signals shutdown
    event_queue_.push(sentinel);
    
    if (process_thread_.joinable()) {
        process_thread_.join();
    }
    
    // Process any remaining events
    if (cfg_.libusb_ctx) {
        struct timeval tv = {0, 200000}; // 200ms
        libusb_handle_events_timeout(cfg_.libusb_ctx, &tv);
    }
    
    // Free transfer
    if (xfer_) {
        libusb_free_transfer(xfer_);
        xfer_ = nullptr;
    }
    
    // Reattach kernel driver
    if (cfg_.handle && cfg_.interface_num >= 0) {
        if (libusb_kernel_driver_active(cfg_.handle, cfg_.interface_num) == 0) {
            libusb_attach_kernel_driver(cfg_.handle, cfg_.interface_num);
        }
    }
    
    std::cout << "Low-latency capture stopped\n";
}

bool KeyboardCaptureLowLatency::is_running() const {
    return running_.load(std::memory_order_relaxed);
}

void LIBUSB_CALL KeyboardCaptureLowLatency::transfer_callback(libusb_transfer* xfer) {
    auto* self = static_cast<KeyboardCaptureLowLatency*>(xfer->user_data);
    
    if (xfer->status == LIBUSB_TRANSFER_COMPLETED && xfer->actual_length > 0) {
        // CRITICAL: Do MINIMAL work here - just memcpy + push
        
        KeyboardEvent event;
        
        // Copy data to fixed-size array (NO allocation!)
        size_t copy_len = (xfer->actual_length < 8) ? xfer->actual_length : 8;
        memcpy(event.data, xfer->buffer, copy_len);
        event.length = copy_len;
        
        // Timestamp (this is cheap - just reads clock)
        event.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count();
        
        // Push to lock-free queue (thread hop - the only real overhead)
        // If queue is full, we DROP the event to maintain low latency
        // This is critical - we can't wait in the callback!
        if (!self->event_queue_.push(event)) {
            // Queue full - drop event (better than blocking)
        }
    }
    
    // ALWAYS re-submit immediately while running
    // This is THE KEY to capturing all events
    if (self->running_.load(std::memory_order_relaxed)) {
        int rc = libusb_submit_transfer(xfer);
        if (rc != 0) {
            // Failed to re-submit - stop capture
            self->running_.store(false, std::memory_order_release);
        }
    }
}

void KeyboardCaptureLowLatency::capture_loop() {
    // Use the same pattern as diagnose_keyboard_clean
    // Non-blocking event loop
    while (running_.load(std::memory_order_relaxed)) {
        libusb_handle_events_completed(cfg_.libusb_ctx, nullptr);
    }
}

void KeyboardCaptureLowLatency::process_loop() {
    // This thread does the actual processing
    // It can take as long as needed - doesn't affect capture latency
    KeyboardEvent event;
    
    while (true) {
        if (event_queue_.pop(event)) {
            // Check for shutdown sentinel (length == 0)
            if (event.length == 0) {
                break;
            }
            
            // Process the event (parse, call user callback, etc.)
            // This can be slow - doesn't affect capture!
            if (cfg_.on_event) {
                cfg_.on_event(event);
            }
        } else {
            // Queue empty, short sleep to avoid busy-waiting
            // This sleep is fine - it doesn't affect capture latency
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }
    
    // Drain remaining events in queue
    while (event_queue_.pop(event)) {
        if (event.length > 0 && cfg_.on_event) {
            cfg_.on_event(event);
        }
    }
}
