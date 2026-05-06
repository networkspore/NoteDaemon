// Keyboard Diagnostic Test - Cleaned Version
// Run with: sudo ./diagnose_keyboard

#include <libusb-1.0/libusb.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <array>

// Helper to print hex data cleanly
void print_hex(const uint8_t* data, size_t len) {
    if (len == 0) return;
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) 
                  << (int)data[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << "\n";
    }
    if (len % 16 != 0) std::cout << "\n";
    std::cout << std::dec;
}

// Helper to find the specific Logitech keyboard
bool find_keyboard(libusb_device* dev, int& interface_num, uint8_t& endpoint_in) {
    libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(dev, &desc) != 0) return false;
    
    // Target: Logitech (0x046d) Product c34b
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
                        
                        std::cout << "Found HID interface " << interface_num << "\n";
                        std::cout << "  Endpoint: 0x" << std::hex << (int)endpoint_in << std::dec << "\n";
                        std::cout << "  Max Packet Size: " << ep.wMaxPacketSize << "\n";
                        std::cout << "  Polling Interval: " << (int)ep.bInterval << " ms\n";
                        
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

// Read HID Report Descriptor
std::vector<uint8_t> read_hid_report_descriptor(libusb_device_handle* handle, int interface_num) {
    libusb_device* dev = libusb_get_device(handle);
    libusb_config_descriptor* config = nullptr;
    
    if (libusb_get_active_config_descriptor(dev, &config) != 0) {
        return {};
    }
    
    std::vector<uint8_t> report_desc;
    
    for (int i = 0; i < config->bNumInterfaces; i++) {
        const libusb_interface& iface = config->interface[i];
        for (int j = 0; j < iface.num_altsetting; j++) {
            const libusb_interface_descriptor& alt = iface.altsetting[j];
            if (alt.bInterfaceNumber == interface_num && alt.bInterfaceClass == LIBUSB_CLASS_HID) {
                if (alt.extra_length > 0) {
                    const uint8_t* extra = alt.extra;
                    int remaining = alt.extra_length;
                    
                    while (remaining >= 2) {
                        uint8_t len = extra[0];
                        uint8_t desc_type = extra[1];
                        
                        if (len == 0 || len > remaining) break;
                        
                        if (desc_type == 0x22) { // Report Descriptor
                            if (len >= 3) {
                                uint16_t report_desc_len = extra[2] | (extra[3] << 8);
                                std::cout << "Report Descriptor length: " << report_desc_len << " bytes\n";
                                
                                report_desc.resize(report_desc_len);
                                int rc = libusb_control_transfer(
                                    handle,
                                    0x81, // Device-to-host
                                    0x06, // GET_DESCRIPTOR
                                    0x2200,
                                    interface_num,
                                    report_desc.data(),
                                    report_desc_len,
                                    1000
                                );
                                
                                if (rc >= 0) {
                                    std::cout << "Successfully read " << rc << " bytes of Report Descriptor\n";
                                    report_desc.resize(rc);
                                } else {
                                    std::cout << "Failed to read Report Descriptor: " << libusb_error_name(rc) << "\n";
                                    report_desc.clear();
                                }
                            }
                        }
                        extra += len;
                        remaining -= len;
                    }
                }
                libusb_free_config_descriptor(config);
                return report_desc;
            }
        }
    }
    
    libusb_free_config_descriptor(config);
    return report_desc;
}

// Check and set protocol
void check_protocol(libusb_device_handle* handle, int interface_num) {
    std::cout << "\n=== Protocol Check ===\n";
    
    uint8_t protocol = 0;
    int rc = libusb_control_transfer(
        handle,
        0xA1,  // Device-to-host, Class, Interface
        0x03,  // GET_PROTOCOL
        0x00,
        interface_num,
        &protocol,
        1,
        1000
    );
    
    if (rc == 1) {
        std::cout << "Current protocol: " << (protocol == 0 ? "BOOT (0)" : "REPORT (1)") << "\n";
    } else {
        std::cout << "GET_PROTOCOL failed: " << libusb_error_name(rc) << "\n";
    }
    
    std::cout << "\nSetting boot protocol...\n";
    rc = libusb_control_transfer(
        handle,
        0x21,  // Host-to-device, Class, Interface
        0x0B,  // SET_PROTOCOL
        0x00,  // Boot protocol
        interface_num,
        nullptr,
        0,
        1000
    );
    
    if (rc == 0) {
        std::cout << "SET_PROTOCOL succeeded\n";
    } else {
        std::cout << "SET_PROTOCOL failed: " << libusb_error_name(rc) << "\n";
    }
    
    // Verify
    rc = libusb_control_transfer(
        handle,
        0xA1,
        0x03,
        0x00,
        interface_num,
        &protocol,
        1,
        1000
    );
    
    if (rc == 1) {
        std::cout << "Protocol after setting: " << (protocol == 0 ? "BOOT (0)" : "REPORT (1)") << "\n";
    }
}

// Simplified 8-byte capture test
void test_8byte_capture(libusb_device_handle* handle, uint8_t endpoint, int duration_sec) {
    std::cout << "\n=== 8-byte Boot Protocol Capture Test (" << duration_sec << " seconds) ===\n";
    std::cout << "Type on the keyboard now!\n";
    std::cout << "(Captures 1-30 will be printed)\n\n";
    
    std::atomic<bool> running{true};
    std::atomic<int> capture_count{0};
    
    struct Ctx {
        std::atomic<int>* count;
        std::atomic<bool>* running;
        libusb_device_handle* handle;
        uint8_t endpoint;
        std::array<uint8_t, 8> buffer;
        libusb_transfer* transfer;
    };
    
    Ctx* ctx = nullptr;
    try {
        ctx = new Ctx;
    } catch (...) {
        std::cerr << "Failed to allocate context\n";
        return;
    }
    
    ctx->count = &capture_count;
    ctx->running = &running;
    ctx->handle = handle;
    ctx->endpoint = endpoint;
    ctx->transfer = libusb_alloc_transfer(0);
    
    if (!ctx->transfer) {
        std::cerr << "Failed to allocate transfer\n";
        delete ctx;
        return;
    }
    
    auto callback = [](struct libusb_transfer* transfer) {
        auto* ctx = static_cast<Ctx*>(transfer->user_data);
        
        if (transfer->status == LIBUSB_TRANSFER_COMPLETED) {
            int cnt = ++(*ctx->count);
            
            if (cnt <= 30) {
                std::cout << "  Capture " << cnt << ": ";
                for (int i = 0; i < transfer->actual_length; i++) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') 
                              << (int)transfer->buffer[i] << " ";
                }
                std::cout << std::dec << " (" << transfer->actual_length << " bytes)\n";
                std::cout.flush();
            }
        }
        
        if (*ctx->running) {
            memset(ctx->buffer.data(), 0, ctx->buffer.size());
            int rc = libusb_submit_transfer(ctx->transfer);
            if (rc != 0 && *ctx->running) {
                std::cerr << "Failed to re-submit transfer: " << libusb_error_name(rc) << "\n";
            }
        }
    };
    
    libusb_fill_interrupt_transfer(
        ctx->transfer,
        handle,
        endpoint,
        ctx->buffer.data(),
        ctx->buffer.size(),
        callback,
        ctx,
        0
    );
    
    int rc = libusb_submit_transfer(ctx->transfer);
    if (rc != 0) {
        std::cerr << "Failed to submit initial transfer: " << libusb_error_name(rc) << "\n";
        libusb_free_transfer(ctx->transfer);
        delete ctx;
        return;
    }
    
    std::cout << "Listening for " << duration_sec << " seconds...\n\n";
    
    auto start = std::chrono::steady_clock::now();
    while (running) {
        libusb_handle_events_completed(nullptr, nullptr);
        
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= duration_sec) {
            running = false;
        }
    }
    
    std::cout << "\nStopping capture...\n";
    libusb_cancel_transfer(ctx->transfer);
    
    // Process remaining events
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    struct timeval tv = {0, 100000};
    libusb_handle_events_timeout(nullptr, &tv);
    
    libusb_free_transfer(ctx->transfer);
    delete ctx;
    
    int total = capture_count.load();
    std::cout << "\nTotal captures with 8-byte buffer: " << total << "\n";
    std::cout << "Expected (10ms poll): ~" << (duration_sec * 100) << " captures\n";
    std::cout << "Capture rate: " << (duration_sec > 0 ? (total / duration_sec) : 0) << " per second\n";
}

int main() {
    std::cout << "=== Keyboard Diagnostic Tool (Cleaned Version) ===\n\n";
    
    libusb_context* ctx = nullptr;
    int rc = libusb_init(&ctx);
    if (rc != 0) {
        std::cerr << "Failed to init libusb\n";
        return 1;
    }
    
    libusb_device** dev_list = nullptr;
    ssize_t count = libusb_get_device_list(ctx, &dev_list);
    if (count < 0) {
        std::cerr << "Failed to get device list\n";
        libusb_exit(ctx);
        return 1;
    }
    
    libusb_device* keyboard = nullptr;
    int interface_num = 0;
    uint8_t endpoint_in = 0x81;
    
    for (ssize_t i = 0; i < count; i++) {
        if (find_keyboard(dev_list[i], interface_num, endpoint_in)) {
            keyboard = dev_list[i];
            break;
        }
    }
    
    if (!keyboard) {
        std::cout << "Logitech keyboard (c34b) not found.\n";
        libusb_free_device_list(dev_list, 1);
        libusb_exit(ctx);
        return 1;
    }
    
    libusb_device_descriptor desc;
    libusb_get_device_descriptor(keyboard, &desc);
    std::cout << "Found: VID=" << std::hex << desc.idVendor 
              << " PID=" << desc.idProduct << std::dec << "\n";
    
    libusb_device_handle* handle = nullptr;
    rc = libusb_open(keyboard, &handle);
    if (rc != 0) {
        std::cerr << "Failed to open device: " << libusb_error_name(rc) << "\n";
        libusb_free_device_list(dev_list, 1);
        libusb_exit(ctx);
        return 1;
    }
    
    std::cout << "Device opened\n";
    
    // Detach kernel driver if active
    if (libusb_kernel_driver_active(handle, interface_num) == 1) {
        std::cout << "Detaching kernel driver...\n";
        rc = libusb_detach_kernel_driver(handle, interface_num);
        if (rc != 0) {
            std::cerr << "Failed to detach driver: " << libusb_error_name(rc) << "\n";
            libusb_close(handle);
            libusb_free_device_list(dev_list, 1);
            libusb_exit(ctx);
            return 1;
        }
    }
    
    // Claim interface
    rc = libusb_claim_interface(handle, interface_num);
    if (rc != 0) {
        std::cerr << "Failed to claim interface: " << libusb_error_name(rc) << "\n";
        libusb_close(handle);
        libusb_free_device_list(dev_list, 1);
        libusb_exit(ctx);
        return 1;
    }
    
    std::cout << "Interface claimed\n";
    
    // Read HID Report Descriptor
    auto report_desc = read_hid_report_descriptor(handle, interface_num);
    if (!report_desc.empty()) {
        std::cout << "\n=== HID Report Descriptor ===\n";
        print_hex(report_desc.data(), report_desc.size());
    }
    
    // Check protocol
    check_protocol(handle, interface_num);
    
    // Test 8-byte capture only
    test_8byte_capture(handle, endpoint_in, 10);
    
    // Cleanup
    libusb_release_interface(handle, interface_num);
    libusb_close(handle);
    libusb_free_device_list(dev_list, 1);
    libusb_exit(ctx);
    
    std::cout << "\nDiagnostic complete.\n";
    return 0;
}
