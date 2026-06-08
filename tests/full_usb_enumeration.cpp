// tests/full_usb_enumeration.cpp
// Standalone USB enumeration tool that does Level 2 HID analysis
// 
// Bypasses all daemon/module caching - talks directly to libusb.
// Performs Level 0 (passive scan), Level 1 (string descriptors),
// and Level 2 (HID report descriptor analysis) on ALL HID devices.
//
// Build:
//   g++ -std=c++17 -o full_usb_enum full_usb_enumeration.cpp \
//       $(pkg-config --cflags --libs libusb-1.0)
//
// Run as root or with proper udev permissions.

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <memory>
#include <map>
#include <chrono>
#include <thread>
#include <cassert>

#include <libusb-1.0/libusb.h>

// ─── Ledger VID ─────────────────────────────────────────────────────────────
constexpr uint16_t LEDGER_VID = 0x2c97;

// ─── Known Ledger PIDs (all known variants) ─────────────────────────────────
bool is_ledger_pid(uint16_t pid) {
    switch (pid) {
        // Nano S
        case 0x0001: case 0x1001: case 0x1011:
        // Nano X
        case 0x0004: case 0x1004: case 0x1014: case 0x4004: case 0x4014:
            return true;
        // Blue
        case 0x0000: case 0x1000:
            return true;
        // Nano S+
        case 0x0005: case 0x1005: case 0x1015: case 0x4005: case 0x4015:
        case 0x5005: case 0x5015:
            return true;
        // Stax
        case 0x0006: case 0x1006: case 0x1016: case 0x4006: case 0x4016:
        case 0x6005: case 0x6015:
            return true;
        default:
            return false;
    }
}

// ─── USB class names ───────────────────────────────────────────────────────
const char* usb_class_name(uint8_t cls) {
    switch (cls) {
        case 0:   return "Per-interface";
        case 1:   return "Audio";
        case 2:   return "Comm";
        case 3:   return "HID";
        case 5:   return "Physical";
        case 6:   return "Image";
        case 7:   return "Printer";
        case 8:   return "Mass Storage";
        case 9:   return "Hub";
        case 10:  return "CDC Data";
        case 11:  return "Smart Card";
        case 12:  return "Content Security";
        case 13:  return "Video";
        case 14:  return "Video";
        case 0xDC: return "Diagnostic";
        case 0xE0: return "Wireless";
        case 0xEF: return "Misc";
        case 0xFE: return "App Specific";
        case 0xFF: return "Vendor Specific";
        default: {
            static char buf[32];
            snprintf(buf, sizeof(buf), "Class 0x%02x", cls);
            return buf;
        }
    }
}

// ─── Device info structure ──────────────────────────────────────────────────
struct DeviceInfo {
    uint8_t bus;
    uint8_t address;
    std::string device_id;  // "bus:addr"
    
    uint16_t vid;
    uint16_t pid;
    
    std::string manufacturer;
    std::string product;
    std::string serial;
    
    uint8_t device_class;
    uint8_t device_subclass;
    uint8_t device_protocol;
    
    bool is_ledger;
    
    struct InterfaceInfo {
        int num;
        uint8_t cls;
        uint8_t subclass;
        uint8_t protocol;
        std::vector<std::pair<uint8_t, uint16_t>> endpoints; // addr, max_packet
    };
    std::vector<InterfaceInfo> interfaces;
    
    // Level 1 data
    std::vector<uint8_t> report_descriptor;
    
    // Level 2 analysis
    bool has_keys = false;
    bool has_axes = false;
    bool has_buttons = false;
    bool has_hats = false;
    bool has_wheel = false;
    int  button_count = 0;
    int  axis_count = 0;
    int  key_count = 0;
    bool is_keyboard = false;
    bool is_mouse = false;
    bool is_gamepad = false;
    bool is_touchpad = false;
    bool is_pen = false;
    std::string refined_type = "unknown";
    int scan_level = 0;  // 0=basic, 1=strings, 2=full HID analysis
};

// ─── Read USB string descriptor ────────────────────────────────────────────
std::string read_string(libusb_device_handle* handle, uint8_t idx) {
    if (idx == 0) return "";
    unsigned char buf[256];
    int len = libusb_get_string_descriptor_ascii(handle, idx, buf, sizeof(buf));
    if (len > 0) {
        return std::string((const char*)buf, len);
    }
    return "";
}

// ─── Read HID report descriptor ────────────────────────────────────────────
std::vector<uint8_t> read_report_descriptor(libusb_device_handle* handle) {
    const size_t max_size = 2048;
    std::vector<uint8_t> buffer(max_size, 0);
    
    uint8_t bmRequestType = LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE;
    uint8_t bRequest = 0x01;  // HID_GET_REPORT
    uint16_t wValue = (0x22 << 8) | 0x00;  // Report Type = Descriptor (0x22)
    uint16_t wIndex = 0;  // interface
    uint16_t wLength = max_size;
    
    int rc = libusb_control_transfer(handle, bmRequestType, bRequest, wValue, wIndex,
                                      buffer.data(), wLength, 1000);
    if (rc > 0) {
        buffer.resize(rc);
        return buffer;
    }
    return {};
}

// ─── Level 2 HID report descriptor analysis ─────────────────────────────────
void analyze_report_descriptor(const std::vector<uint8_t>& rd,
                               DeviceInfo& info) {
    if (rd.empty()) return;
    
    size_t pos = 0;
    while (pos + 1 < rd.size()) {
        uint8_t byte = rd[pos++];
        uint8_t prefix = (byte & 0xFC) >> 2;
        uint8_t size = byte & 0x03;
        if (size == 3) size = 4;
        
        if (pos + size > rd.size()) break;
        uint32_t value = 0;
        for (int i = 0; i < (int)size; ++i) {
            value |= (uint32_t)(rd[pos++]) << (i * 8);
        }
        
        // Simple parser for usage pages and usages
        switch (prefix) {
            case 0x04: {  // Long item
                uint8_t tag = (byte >> 4) & 0x07;
                switch (tag) {
                    case 0x00:  // Usage Page
                        if (value == 0x07) info.has_keys = true;     // Keyboard
                        if (value == 0x09) info.has_buttons = true;  // Button
                        if (value == 0x0C) info.has_keys = true;     // Consumer
                        break;
                    case 0x01: {  // Usage
                        if (value == 0x30 || value == 0x31 || 
                            value == 0x32 || value == 0x33 ||
                            value == 0x36 || value == 0x37) {
                            info.has_axes = true;
                            info.axis_count++;
                        }
                        if (value == 0x38) info.has_wheel = true;   // Wheel
                        if (value == 0x39) info.has_hats = true;    // Hat switch
                        break;
                    }
                    default: break;
                }
                break;
            }
            default: break;
        }
    }
    
    // Refine classification
    info.is_keyboard = info.has_keys && info.axis_count <= 2;
    info.is_mouse = info.has_buttons && (info.has_wheel || info.axis_count >= 2);
    info.is_gamepad = info.has_axes && info.has_buttons && !info.is_mouse;
    info.is_touchpad = info.has_axes && info.has_buttons && !info.is_mouse && !info.is_gamepad;
    info.is_pen = info.has_axes && !info.has_buttons && !info.is_keyboard;
    
    if (info.is_keyboard) info.refined_type = "keyboard";
    else if (info.is_mouse) info.refined_type = "mouse";
    else if (info.is_gamepad) info.refined_type = "gamepad";
    else if (info.is_touchpad) info.refined_type = "touchpad";
    else if (info.is_pen) info.refined_type = "pen";
    else if (info.has_keys || info.has_buttons) info.refined_type = "input";
    else info.refined_type = "generic_hid";
    
    if (info.button_count == 0) info.button_count = info.has_buttons ? 1 : 0;
    if (info.axis_count == 0) info.axis_count = info.has_axes ? 1 : 0;
    if (info.key_count == 0) info.key_count = info.has_keys ? 1 : 0;
}

// ─── Main enumeration ──────────────────────────────────────────────────────
std::vector<DeviceInfo> enumerate_all_devices(libusb_context* ctx) {
    std::vector<DeviceInfo> devices;
    
    libusb_device** list = nullptr;
    ssize_t count = libusb_get_device_list(ctx, &list);
    
    if (count < 0) {
        std::cerr << "ERROR: libusb_get_device_list failed: " 
                  << libusb_error_name((int)count) << std::endl;
        return devices;
    }
    
    std::cout << "\nlibusb reported " << count << " device(s)\n";
    std::cout << "========================================\n\n";
    
    for (ssize_t i = 0; i < count; ++i) {
        libusb_device* dev = list[i];
        struct libusb_device_descriptor desc;
        
        int rc = libusb_get_device_descriptor(dev, &desc);
        if (rc != LIBUSB_SUCCESS) continue;
        
        DeviceInfo info;
        info.bus = libusb_get_bus_number(dev);
        info.address = libusb_get_device_address(dev);
        info.device_id = std::to_string(info.bus) + ":" + std::to_string(info.address);
        info.vid = desc.idVendor;
        info.pid = desc.idProduct;
        info.device_class = desc.bDeviceClass;
        info.device_subclass = desc.bDeviceSubClass;
        info.device_protocol = desc.bDeviceProtocol;
        info.is_ledger = (desc.idVendor == LEDGER_VID && is_ledger_pid(desc.idProduct));
        
        // Read config for interface info
        libusb_config_descriptor* cfg = nullptr;
        if (libusb_get_active_config_descriptor(dev, &cfg) == LIBUSB_SUCCESS && cfg) {
            for (int j = 0; j < cfg->bNumInterfaces; ++j) {
                const auto& iface = cfg->interface[j];
                if (iface.num_altsetting > 0) {
                    auto& alt = iface.altsetting[0];
                    DeviceInfo::InterfaceInfo iface_info;
                    iface_info.num = alt.bInterfaceNumber;
                    iface_info.cls = alt.bInterfaceClass;
                    iface_info.subclass = alt.bInterfaceSubClass;
                    iface_info.protocol = alt.bInterfaceProtocol;
                    
                    for (int e = 0; e < alt.bNumEndpoints; ++e) {
                        iface_info.endpoints.push_back({
                            alt.endpoint[e].bEndpointAddress,
                            alt.endpoint[e].wMaxPacketSize
                        });
                    }
                    info.interfaces.push_back(iface_info);
                }
            }
            libusb_free_config_descriptor(cfg);
        }
        
        // Check if HID device
        bool is_hid = false;
        for (auto& iface : info.interfaces) {
            if (iface.cls == LIBUSB_CLASS_HID) {
                is_hid = true;
                break;
            }
        }
        
        info.scan_level = 0;
        
        // Skip non-HID devices unless they're Ledger
        // (Ledger might be class 0x00 with HID interface)
        if (!is_hid && !info.is_ledger) {
            devices.push_back(info);  // Still record for listing
            continue;
        }
        
        // Try Level 1: Open device and read string descriptors
        libusb_device_handle* handle = nullptr;
        rc = libusb_open(dev, &handle);
        if (rc == LIBUSB_SUCCESS && handle) {
            if (desc.iManufacturer > 0)
                info.manufacturer = read_string(handle, desc.iManufacturer);
            if (desc.iProduct > 0)
                info.product = read_string(handle, desc.iProduct);
            if (desc.iSerialNumber > 0)
                info.serial = read_string(handle, desc.iSerialNumber);
            
            info.scan_level = 1;
            
            // If HID, try Level 2: Read report descriptor
            // Need to detach kernel driver and claim interface first
            bool did_claim = false;
            for (auto& iface : info.interfaces) {
                if (iface.cls == LIBUSB_CLASS_HID) {
                    // Detach kernel driver if active
                    if (libusb_kernel_driver_active(handle, iface.num) == 1) {
                        libusb_detach_kernel_driver(handle, iface.num);
                    }
                    
                    // Claim interface
                    if (libusb_claim_interface(handle, iface.num) == LIBUSB_SUCCESS) {
                        did_claim = true;
                        
                        // Read report descriptor
                        auto rd = read_report_descriptor(handle);
                        if (!rd.empty()) {
                            info.report_descriptor = rd;
                            info.scan_level = 2;
                            analyze_report_descriptor(rd, info);
                        }
                        
                        // Release
                        libusb_release_interface(handle, iface.num);
                        break;  // Only need one HID interface
                    }
                }
            }
            
            // If we didn't claim specifically, still try to read report descriptor
            // via control transfer on interface 0
            if (!did_claim && is_hid) {
                auto rd = read_report_descriptor(handle);
                if (!rd.empty()) {
                    info.report_descriptor = rd;
                    info.scan_level = 2;
                    analyze_report_descriptor(rd, info);
                }
            }
            
            libusb_close(handle);
        }
        
        devices.push_back(info);
    }
    
    libusb_free_device_list(list, 1);
    return devices;
}

// ─── Print results ────────────────────────────────────────────────────────
void print_devices(const std::vector<DeviceInfo>& devices) {
    std::cout << "\n";
    std::cout << "┌────────┬──────────────┬────────────┬──────────────────────────────────┬──────────┐\n";
    std::cout << "│ Bus:Ad │ VID:PID      │ Type       │ Product                          │ Scan Lvl │\n";
    std::cout << "├────────┼──────────────┼────────────┼──────────────────────────────────┼──────────┤\n";
    
    for (auto& d : devices) {
        bool is_hid = false;
        for (auto& iface : d.interfaces) {
            if (iface.cls == LIBUSB_CLASS_HID) is_hid = true;
        }
        
        std::string dtype;
        std::string color;
        if (d.is_ledger) {
            dtype = "LEDGER!";
        } else if (d.refined_type != "unknown") {
            dtype = d.refined_type;
        } else if (d.device_class == 9) {
            dtype = "HUB";
        } else if (d.device_class == 0xE0) {
            dtype = "WIRELESS";
        } else if (is_hid) {
            dtype = "HID";
        } else {
            dtype = usb_class_name(d.device_class);
        }
        
        char vidpid[32];
        snprintf(vidpid, sizeof(vidpid), "%04x:%04x", d.vid, d.pid);
        
        std::string product = d.product;
        if (product.empty()) {
            product = d.manufacturer;
        }
        if (product.empty()) {
            product = "(no string)";
        }
        if (product.length() > 30) {
            product = product.substr(0, 27) + "...";
        }
        
        char scan_lvl_str[16];
        if (d.scan_level == 0) snprintf(scan_lvl_str, sizeof(scan_lvl_str), "%d (basic)", d.scan_level);
        else if (d.scan_level == 1) snprintf(scan_lvl_str, sizeof(scan_lvl_str), "%d (strings)", d.scan_level);
        else snprintf(scan_lvl_str, sizeof(scan_lvl_str), "%d (full HID)", d.scan_level);
        
        printf("│ %6s │ %-12s │ %-10s │ %-32s │ %-8s │\n",
               d.device_id.c_str(), vidpid, dtype.c_str(), 
               product.c_str(), scan_lvl_str);
    }
    
    std::cout << "└────────┴──────────────┴────────────┴──────────────────────────────────┴──────────┘\n";
}

// ─── Print interface details for devices of interest ───────────────────────
void print_interfaces(const std::vector<DeviceInfo>& devices) {
    std::cout << "\n\n=== HID & LEDGER DEVICE INTERFACE DETAILS ===\n";
    
    for (auto& d : devices) {
        bool is_hid = false;
        for (auto& iface : d.interfaces) {
            if (iface.cls == LIBUSB_CLASS_HID) is_hid = true;
        }
        
        if (!is_hid && !d.is_ledger) continue;
        
        std::cout << "\n--- " << d.device_id 
                  << " | " << d.product
                  << " | " << (d.is_ledger ? "LEDGER ✓" : "")
                  << " | Scan Level: " << d.scan_level << "\n";
        std::cout << "    VID:PID = " << std::hex << d.vid << ":" << d.pid << std::dec << "\n";
        if (!d.manufacturer.empty())
            std::cout << "    Manufacturer: " << d.manufacturer << "\n";
        if (!d.serial.empty())
            std::cout << "    Serial: " << d.serial << "\n";
        
        for (auto& iface : d.interfaces) {
            std::cout << "    Interface " << iface.num << ": "
                      << "class=" << (int)iface.cls << " (" << usb_class_name(iface.cls) << ")"
                      << " subclass=" << (int)iface.subclass
                      << " proto=" << (int)iface.protocol << "\n";
            for (auto& ep : iface.endpoints) {
                std::cout << "      Endpoint 0x" << std::hex << (int)ep.first << std::dec
                          << " (max_packet=" << ep.second << ")\n";
            }
        }
        
        // Level 2 analysis results
        if (d.scan_level >= 2) {
            std::cout << "    Report Descriptor: " << d.report_descriptor.size() << " bytes\n";
            std::cout << "    Level 2 Analysis:\n";
            std::cout << "      Refined type: " << d.refined_type << "\n";
            std::cout << "      Keys: " << (d.has_keys ? "yes" : "no") << "\n";
            std::cout << "      Axes: " << (d.has_axes ? "yes" : "no") << " (" << d.axis_count << ")\n";
            std::cout << "      Buttons: " << (d.has_buttons ? "yes" : "no") << " (" << d.button_count << ")\n";
            std::cout << "      Hats: " << (d.has_hats ? "yes" : "no") << "\n";
            std::cout << "      Wheel: " << (d.has_wheel ? "yes" : "no") << "\n";
            
            // Print raw report descriptor bytes
            std::cout << "      Raw bytes: ";
            for (size_t i = 0; i < std::min(d.report_descriptor.size(), size_t(32)); ++i) {
                printf("%02x ", d.report_descriptor[i]);
            }
            if (d.report_descriptor.size() > 32) std::cout << "...";
            std::cout << "\n";
        }
    }
}

// ─── Summary ──────────────────────────────────────────────────────────────
void print_summary(const std::vector<DeviceInfo>& devices) {
    int total = devices.size();
    int hid = 0;
    int ledger = 0;
    int level2 = 0;
    
    for (auto& d : devices) {
        if (d.is_ledger) ledger++;
        if (d.scan_level >= 2) level2++;
        for (auto& iface : d.interfaces) {
            if (iface.cls == LIBUSB_CLASS_HID) {
                hid++;
                break;
            }
        }
    }
    
    std::cout << "\n\n=== SUMMARY ===\n";
    std::cout << "Total USB devices: " << total << "\n";
    std::cout << "HID devices: " << hid << "\n";
    std::cout << "Level 2 scanned: " << level2 << "\n";
    std::cout << "Ledger devices: " << ledger << "\n";
    
    if (ledger == 0) {
        std::cout << "\n⚠  NO LEDGER DEVICE DETECTED!\n";
        std::cout << "   Please ensure:\n";
        std::cout << "   1. Ledger is physically connected via USB\n";
        std::cout << "   2. Ledger is unlocked (enter PIN)\n";
        std::cout << "   3. You're on the home screen (not in an app)\n";
        std::cout << "   4. Check dmesg: dmesg | grep -i usb | tail -20\n";
        std::cout << "   5. Try: lsusb | grep -i ledger\n";
        std::cout << "   6. The USB cable supports data (not just charging)\n";
    } else {
        std::cout << "\n✓ LEDGER DEVICE FOUND!\n";
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << " Full USB Enumeration + Level 2 HID Scan\n";
    std::cout << " Bypasses all daemon/module caching\n";
    std::cout << "========================================\n";
    
    // Parse args
    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        }
    }
    
    // Init libusb
    libusb_context* ctx = nullptr;
    int rc = libusb_init(&ctx);
    if (rc != 0) {
        std::cerr << "FATAL: libusb_init failed: " << libusb_error_name(rc) << "\n";
        std::cerr << "Try running with sudo or check udev rules.\n";
        return 1;
    }
    
    // Optional: set debug level
    libusb_set_option(ctx, LIBUSB_OPTION_LOG_LEVEL, verbose ? 3 : 0);
    
    // Enumerate
    auto devices = enumerate_all_devices(ctx);
    
    // Print results
    print_devices(devices);
    
    if (verbose) {
        print_interfaces(devices);
    }
    
    print_summary(devices);
    
    libusb_exit(ctx);
    return 0;
}
