// keyboard_capture_lowlatency_demo.cpp
// Demo for low-latency keyboard capture with hot-plug support.
// Shows how to use the module while maintaining minimal latency.

#include "keyboard_capture_lowlatency.h"
#include <libusb-1.0/libusb.h>
#include <iostream>
#include <iomanip>
#include <csignal>
#include <atomic>
#include <chrono>

static std::atomic<bool> g_running{true};

static void signal_handler(int) {
    g_running = false;
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    std::cout << "=== Low-Latency Keyboard Capture Demo ===\n\n";
    std::cout << "This demo will:\n";
    std::cout << "  - Auto-detect Logitech keyboard (046d:c34b)\n";
    std::cout << "  - Handle hot-plug (unplug/reconnect)\n";
    std::cout << "  - Exit on Ctrl+C or after 60 seconds\n\n";
    
    // Init libusb
    libusb_context* ctx = nullptr;
    int rc = libusb_init(&ctx);
    if (rc != 0) {
        std::cerr << "libusb_init failed\n";
        return 1;
    }
    
    // Track statistics
    std::atomic<int> event_count{0};
    std::atomic<int> key_down_count{0};
    std::atomic<int> key_up_count{0};
    
    // Configure capture module
    KeyboardCaptureLowLatency::Config cfg;
    cfg.libusb_ctx = ctx;
    cfg.device_id = "logitech_c34b";
    cfg.vendor_id = 0x046d;  // Logitech
    cfg.product_id = 0xc34b; // Specific model
    
    cfg.on_event = [&](const KeyboardEvent& event) {
        // This runs in the PROCESSING thread (not capture thread)
        // Can do slow operations here without affecting capture latency
        
        int cnt = ++event_count;
        
        // Parse basic key event (8-byte boot protocol)
        if (event.length >= 3) {
            uint8_t key1 = event.data[2];
            
            if (key1 != 0) {
                key_down_count++;
                std::cout << "[DOWN #" << cnt << "] ";
            } else {
                key_up_count++;
                std::cout << "[UP   #" << cnt << "] ";
            }
            
            // Print the data
            for (int i = 0; i < event.length; i++) {
                std::cout << std::hex << std::setfill('0') << std::setw(2) 
                          << (int)event.data[i] << " ";
            }
            std::cout << std::dec << "\n";
            std::cout.flush();
        }
    };
    
    cfg.on_device_lost = []() {
        std::cout << "\n*** DEVICE UNPLUGGED - Waiting for reconnection... ***\n";
    };
    
    cfg.on_device_found = []() {
        std::cout << "\n*** DEVICE RECONNECTED - Capture resumed! ***\n";
    };
    
    // Create and start capture
    KeyboardCaptureLowLatency capture(cfg);
    capture.start();
    
    if (!capture.is_running()) {
        std::cout << "Failed to start capture. Is the keyboard plugged in?\n";
        libusb_exit(ctx);
        return 1;
    }
    
    std::cout << "Capture started. Press Ctrl+C to stop or wait 60 seconds.\n\n";
    
    // Main thread: print stats periodically
    auto start_time = std::chrono::steady_clock::now();
    const auto TIMEOUT_DURATION = std::chrono::seconds(60);
    int last_count = 0;
    
    while (g_running && capture.is_running()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // Check 60-second timeout
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start_time);
        
        if (elapsed >= TIMEOUT_DURATION) {
            std::cout << "\nTimeout reached (60 seconds). Stopping capture.\n";
            g_running = false;
            break;
        }
        
        int current_count = event_count.load();
        
        if (current_count != last_count) {
            std::cout << "\n--- Stats (after " << elapsed.count() << "s) ---\n";
            std::cout << "Total events: " << current_count << "\n";
            std::cout << "Key down: " << key_down_count.load() << "\n";
            std::cout << "Key up: " << key_up_count.load() << "\n";
            std::cout << "Rate: " << (elapsed.count() > 0 ? current_count / (int)elapsed.count() : 0) 
                      << " events/sec\n";
            std::cout << "-------------------------\n\n";
            last_count = current_count;
        }
    }
    
    std::cout << "\nStopping...\n";
    capture.stop();
    
    // Cleanup
    libusb_exit(ctx);
    
    std::cout << "\n=== Capture Complete ===\n";
    std::cout << "Total events captured: " << event_count.load() << "\n";
    
    return 0;
}
