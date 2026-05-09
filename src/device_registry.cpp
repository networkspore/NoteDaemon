// src/device_registry.cpp
// Implementation for device registry — file-based tracking of claimed devices.

#include "device_registry.h"
#include <algorithm>

// Registry file lives in the same directory as the socket, so it's on tmpfs
// and survives daemon restarts (but not machine reboots, which is fine).
// Path: /run/netnotes/device_registry.json
static const std::string& default_registry_path() {
    static std::string path = "/run/netnotes/device_registry.json";
    return path;
}

const std::string& DeviceRegistry::path() {
    return default_registry_path();
}

std::mutex& DeviceRegistry::registry_mutex() {
    static std::mutex mtx;
    return mtx;
}

std::string& DeviceRegistry::registry_path() {
    static std::string path = default_registry_path();
    return path;
}

// ─── Public API ────────────────────────────────────────────────────────────

void DeviceRegistry::add_device(const ClaimedDevice& device) {
    std::lock_guard<std::mutex> lock(registry_mutex());
    
    auto devices = read_registry();
    
    // Remove any existing entry for this pid+device_id (idempotent)
    devices.erase(
        std::remove_if(devices.begin(), devices.end(),
            [&device](const ClaimedDevice& d) {
                return d.pid == device.pid && d.device_id == device.device_id;
            }),
        devices.end());
    
    devices.push_back(device);
    write_registry(devices);
}

bool DeviceRegistry::remove_device(pid_t pid, const std::string& device_id) {
    std::lock_guard<std::mutex> lock(registry_mutex());
    
    auto devices = read_registry();
    auto it = std::remove_if(devices.begin(), devices.end(),
        [&pid, &device_id](const ClaimedDevice& d) {
            return d.pid == pid && d.device_id == device_id;
        });
    
    if (it == devices.end()) {
        return false;  // Not found
    }
    
    devices.erase(it, devices.end());
    write_registry(devices);
    return true;
}

std::vector<ClaimedDevice> DeviceRegistry::get_devices_by_pid(pid_t pid) {
    std::lock_guard<std::mutex> lock(registry_mutex());
    
    auto devices = read_registry();
    std::vector<ClaimedDevice> result;
    
    for (const auto& d : devices) {
        if (d.pid == pid) {
            result.push_back(d);
        }
    }
    
    return result;
}

std::vector<ClaimedDevice> DeviceRegistry::get_all_devices() {
    std::lock_guard<std::mutex> lock(registry_mutex());
    return read_registry();
}

bool DeviceRegistry::remove_all_by_pid(pid_t pid) {
    std::lock_guard<std::mutex> lock(registry_mutex());
    
    auto devices = read_registry();
    auto it = std::remove_if(devices.begin(), devices.end(),
        [&pid](const ClaimedDevice& d) {
            return d.pid == pid;
        });
    
    bool removed = (it != devices.end());
    if (removed) {
        devices.erase(it, devices.end());
        write_registry(devices);
    }
    
    return removed;
}

// ─── Private Implementation ────────────────────────────────────────────────

std::vector<ClaimedDevice> DeviceRegistry::read_registry() {
    std::vector<ClaimedDevice> devices;
    
    struct stat st;
    if (stat(registry_path().c_str(), &st) != 0) {
        // File doesn't exist yet — nothing to read
        return devices;
    }
    
    std::ifstream file(registry_path());
    if (!file.is_open()) {
        syslog(LOG_WARNING, "Failed to open device registry: %s",
               registry_path().c_str());
        return devices;
    }
    
    // Read entire file
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    
    // Simple JSON array parser — no external dependencies
    // Format: [{"pid":12345,"device_id":"1:3","interface_number":0,"kernel_driver_attached":true},...]
    
    // Find all object boundaries
    size_t pos = 0;
    while (pos < content.size()) {
        // Find the start of an object
        size_t obj_start = content.find('{', pos);
        if (obj_start == std::string::npos) break;
        
        // Find the matching end
        int depth = 0;
        size_t obj_end = obj_start;
        for (size_t i = obj_start; i < content.size(); i++) {
            if (content[i] == '{') depth++;
            if (content[i] == '}') {
                depth--;
                if (depth == 0) {
                    obj_end = i;
                    break;
                }
            }
        }
        
        if (obj_end == obj_start) {
            pos = obj_start + 1;
            continue;
        }
        
        // Parse this object
        std::string obj = content.substr(obj_start + 1, obj_end - obj_start - 1);
        
        ClaimedDevice device;
        device.pid = 0;
        device.interface_number = 0;
        device.kernel_driver_attached = false;
        
        // Parse key-value pairs
        size_t key_pos = 0;
        while (key_pos < obj.size()) {
            // Find key
            size_t key_start = obj.find('"', key_pos);
            if (key_start == std::string::npos) break;
            
            size_t key_end = obj.find('"', key_start + 1);
            if (key_end == std::string::npos) break;
            
            std::string key = obj.substr(key_start + 1, key_end - key_start - 1);
            
            // Skip to value
            size_t val_start = obj.find(':', key_end + 1);
            if (val_start == std::string::npos) break;
            
            // Parse value based on key
            if (key == "pid") {
                size_t val_end = obj.find(',', val_start + 1);
                if (val_end == std::string::npos) val_end = obj.find('}', val_start + 1);
                std::string val = obj.substr(val_start + 1, val_end - val_start - 1);
                try {
                    device.pid = std::stoll(val);
                } catch (...) {
                    device.pid = 0;
                }
            } else if (key == "device_id") {
                size_t val_start2 = obj.find('"', val_start + 1);
                size_t val_end2 = obj.find('"', val_start2 + 1);
                if (val_start2 != std::string::npos && val_end2 != std::string::npos) {
                    device.device_id = obj.substr(val_start2 + 1, val_end2 - val_start2 - 1);
                }
            } else if (key == "interface_number") {
                size_t val_end = obj.find(',', val_start + 1);
                if (val_end == std::string::npos) val_end = obj.find('}', val_start + 1);
                std::string val = obj.substr(val_start + 1, val_end - val_start - 1);
                try {
                    device.interface_number = std::stoi(val);
                } catch (...) {
                    device.interface_number = 0;
                }
            } else if (key == "kernel_driver_attached") {
                std::string val = obj.substr(val_start + 1);
                // Trim whitespace and closing brace
                size_t end = val.find('}');
                if (end != std::string::npos) val = val.substr(0, end);
                size_t end2 = val.find(',');
                if (end2 != std::string::npos) val = val.substr(0, end2);
                // Trim
                size_t start = val.find_first_not_of(" \t\r\n");
                if (start != std::string::npos) {
                    val = val.substr(start);
                }
                device.kernel_driver_attached = (val == "true");
            }
            
            // Move past this key-value pair
            key_pos = (key_end + 1 < obj.size()) ? obj.find('"', key_end + 1) : std::string::npos;
        }
        
        // Only add if we got a valid device
        if (!device.device_id.empty()) {
            devices.push_back(device);
        }
        
        pos = obj_end + 1;
    }
    
    return devices;
}

bool DeviceRegistry::write_registry(const std::vector<ClaimedDevice>& devices) {
    // Ensure directory exists
    std::string dir = registry_path();
    size_t last_slash = dir.find_last_of('/');
    if (last_slash != std::string::npos) {
        std::string dir_path = dir.substr(0, last_slash);
        mkdir(dir_path.c_str(), 0755);
    }
    
    std::ofstream file(registry_path());
    if (!file.is_open()) {
        syslog(LOG_WARNING, "Failed to write device registry: %s",
               registry_path().c_str());
        return false;
    }
    
    file << "[";
    for (size_t i = 0; i < devices.size(); i++) {
        if (i > 0) file << ", ";
        file << json_object(devices[i]);
    }
    file << "]" << std::endl;
    
    return true;
}

std::string DeviceRegistry::json_object(const ClaimedDevice& device) {
    std::ostringstream oss;
    oss << "{"
        << "\"pid\":" << device.pid << ","
        << "\"device_id\":\"" << device.device_id << "\","
        << "\"interface_number\":" << device.interface_number << ","
        << "\"kernel_driver_attached\":" << (device.kernel_driver_attached ? "true" : "false")
        << "}";
    return oss.str();
}
