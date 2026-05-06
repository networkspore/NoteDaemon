// keyboard_capture_lowlatency_demo.cpp
// Demo for low-latency keyboard capture.
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

// Helper to find keyboard (same as diagnose_keyboard_clean)
bool find_keyboard(libusb_device* dev, int& interface_num, uint8_t& endpoint_in) {
    libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(dev, &desc) != 0) return false;
    
    if (desc.idVendor != 0x046d || desc.idProduct != 0xc34b) return false;
    
    libusb_config_descriptor* config = nullptr;
    if (libusb_get_active_config_descriptor(dev, &config) != 0) return false;
    
    for (int i = 0; i < config->bNumInterfaces; i++) {
        const libusb_interface& iface = config->interface[i];
        for (int j = 0; j < iface.num_altsetting; j++) {
            const libusb_interface_descriptor& alt = iface.altsetting[j];
            if (alt.bInterfaceClass == LIBUSB_CLASS_HID) {
                for (int k = 0; k < alt.bNumEndpoints; k++) {
                    const libusb_endpoint_descriptor& ep = alt.endpoint[k];
                    if ((ep.bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
                        interface_num = alt.bInterfaceNumber;
                        endpoint_in = ep.bEndpointAddress;
                        libusb_free_config_descriptor(config);
                        return true;
                    }
                }
            }
        }
    }
    
    libusb_free_config_descriptor(config);
    return false;
}

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) 
                  << (int)data[i] << " ";
    }
    std::cout << std::dec;
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    std::cout << "=== Low-Latency Keyboard Capture Demo ===\n\n";
    
    // Init libusb
    libusb_context* ctx = nullptr;
    int rc = libusb_init(&ctx);
    if (rc != 0) {
        std::cerr << "libusb_init failed\n";
        return 1;
    }
    
    // Find keyboard
    libusb_device** dev_list = nullptr;
    ssize_t count = libusb_get_device_list(ctx, &dev_list);
    if (count < 0) {
        std::cerr << "Failed to get device list\n";
        libusb_exit(ctx);
        return 1;
    }
    
    libusb_device* keyboard = nullptr;
    int interface_num = -1;
    uint8_t endpoint_in = 0x81;
    
    for (ssize_t i = 0; i < count; i++) {
        if (find_keyboard(dev_list[i], interface_num, endpoint_in)) {
            keyboard = dev_list[i];
            break;
        }
    }
    
    libusb_free_device_list(dev_list, 1);
    
    if (!keyboard || interface_num < 0) {
        std::cout << "Keyboard (046d:c34b) not found.\n";
        libusb_exit(ctx);
        return 1;
    }
    
    std::cout << "Found keyboard at interface " << interface_num 
              << ", endpoint 0x" << std::hex << (int)endpoint_in << std::dec << "\n";
    
    // Open device
    libusb_device_handle* handle = nullptr;
    rc = libusb_open(keyboard, &handle);
    if (rc != 0) {
        std::cerr << "Failed to open device: " << libusb_error_name(rc) << "\n";
        libusb_exit(ctx);
        return 1;
    }
    
    // Detach kernel driver
    if (libusb_kernel_driver_active(handle, interface_num) == 1) {
        rc = libusb_detach_kernel_driver(handle, interface_num);
        if (rc == 0) {
            std::cout << "Kernel driver detached.\n";
        }
    }
    
    // Claim interface
    rc = libusb_claim_interface(handle, interface_num);
    if (rc != 0) {
        std::cerr << "Failed to claim interface: " << libusb_error_name(rc) << "\n";
        libusb_close(handle);
        libusb_exit(ctx);
        return 1;
    }
    
    std::cout << "Interface claimed. Starting low-latency capture...\n\n";
    std::cout << "Press Ctrl+C to stop.\n\n";
    
    // Track statistics
    std::atomic<int> event_count{0};
    std::atomic<int> key_down_count{0};
    std::atomic<int> key_up_count{0};
    
    // Configure capture module
    KeyboardCaptureLowLatency::Config cfg;
    cfg.libusb_ctx = ctx;
    cfg.handle = handle;
    cfg.interface_num = interface_num;
    cfg.endpoint_in = endpoint_in;
    cfg.device_id = "logitech_c34b";
    
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
                // Check if this is a key-up by comparing with previous
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
    
    // Create and start capture
    KeyboardCaptureLowLatency capture(cfg);
    capture.start();
    
    // Main thread: print stats periodically
    auto start_time = std::chrono::steady_clock::now();
    int last_count = 0;
    
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        int current_count = event_count.load();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start_time).count();
        
        if (current_count != last_count) {
            std::cout << "\n--- Stats (after " << elapsed << "s) ---\n";
            std::cout << "Total events: " << current_count << "\n";
            std::cout << "Key down: " << key_down_count.load() << "\n";
            std::cout << "Key up: " << key_up_count.load() << "\n";
            std::cout << "Rate: " << (elapsed > 0 ? current_count / (int)elapsed : 0) 
                      << " events/sec\n";
            std::cout << "-------------------------\n\n";
            last_count = current_count;
        }
    }
    
    std::cout << "\nStopping...\n";
    capture.stop();
    
    // Cleanup
    libusb_release_interface(handle, interface_num);
    libusb_close(handle);
    libusb_exit(ctx);
    
    std::cout << "\n=== Capture Complete ===\n";
    std::cout << "Total events captured: " << event_count.load() << "\n";
    
    return 0;
}
