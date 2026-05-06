// Parse keyboard_capture.log and convert to readable text
// Assumes Boot Protocol format (8-byte reports)
// Usage: ./parse_keyboard_log [logfile]

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>

// HID Keycode to character mapping (US QWERTY)
// Based on HID Usage Page 0x07 (Keyboard/Keypad)
struct KeyMapping {
    uint8_t usage;
    const char* name;
    char normal;
    char shift;
};

static const KeyMapping key_map[] = {
    {0x00, "None", 0, 0},
    {0x04, "A", 'a', 'A'},
    {0x05, "B", 'b', 'B'},
    {0x06, "C", 'c', 'C'},
    {0x07, "D", 'd', 'D'},
    {0x08, "E", 'e', 'E'},
    {0x09, "F", 'f', 'F'},
    {0x0A, "G", 'g', 'G'},
    {0x0B, "H", 'h', 'H'},
    {0x0C, "I", 'i', 'I'},
    {0x0D, "J", 'j', 'J'},
    {0x0E, "K", 'k', 'K'},
    {0x0F, "L", 'l', 'L'},
    {0x10, "M", 'm', 'M'},
    {0x11, "N", 'n', 'N'},
    {0x12, "O", 'o', 'O'},
    {0x13, "P", 'p', 'P'},
    {0x14, "Q", 'q', 'Q'},
    {0x15, "R", 'r', 'R'},
    {0x16, "S", 's', 'S'},
    {0x17, "T", 't', 'T'},
    {0x18, "U", 'u', 'U'},
    {0x19, "V", 'v', 'V'},
    {0x1A, "W", 'w', 'W'},
    {0x1B, "X", 'x', 'X'},
    {0x1C, "Y", 'y', 'Y'},
    {0x1D, "Z", 'z', 'Z'},
    {0x1E, "1", '1', '!'},
    {0x1F, "2", '2', '@'},
    {0x20, "3", '3', '#'},
    {0x21, "4", '4', '$'},
    {0x22, "5", '5', '%'},
    {0x23, "6", '6', '^'},
    {0x24, "7", '7', '&'},
    {0x25, "8", '8', '*'},
    {0x26, "9", '9', '('},
    {0x27, "0", '0', ')'},
    {0x28, "Enter", '\n', '\n'},
    {0x29, "Esc", 0, 0},
    {0x2A, "Backspace", '\b', '\b'},
    {0x2B, "Tab", '\t', '\t'},
    {0x2C, "Space", ' ', ' '},
    {0x2D, "-", '-', '_'},
    {0x2E, "=", '=', '+'},
    {0x2F, "[", '[', '{'},
    {0x30, "]", ']', '}'},
    {0x31, "\\", '\\', '|'},
    {0x32, "#", 0, 0},  // Non-US # and ~
    {0x33, ";", ';', ':'},
    {0x34, "'", '\'', '"'},
    {0x35, "`", '`', '~'},
    {0x36, ",", ',', '<'},
    {0x37, ".", '.', '>'},
    {0x38, "/", '/', '?'},
    {0x39, "CapsLock", 0, 0},
    {0x4F, "Right", 0, 0},
    {0x50, "Left", 0, 0},
    {0x51, "Down", 0, 0},
    {0x52, "Up", 0, 0},
};

char get_char(uint8_t usage, bool shift) {
    for (const auto& key : key_map) {
        if (key.usage == usage) {
            if (shift) {
                return key.shift;
            } else {
                return key.normal;
            }
        }
    }
    return 0;
}

std::string get_key_name(uint8_t usage) {
    for (const auto& key : key_map) {
        if (key.usage == usage) {
            return key.name;
        }
    }
    std::stringstream ss;
    ss << "0x" << std::hex << (int)usage;
    return ss.str();
}

// Parse a single Boot Protocol report (8 bytes)
std::string parse_boot_report(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 8 > data.size()) {
        return "";
    }
    
    uint8_t modifiers = data[offset];
    // data[offset+1] is reserved
    
    bool lctrl = modifiers & 0x01;
    bool lshift = modifiers & 0x02;
    bool lalt = modifiers & 0x04;
    bool lgui = modifiers & 0x08;
    bool rctrl = modifiers & 0x10;
    bool rshift = modifiers & 0x20;
    bool ralt = modifiers & 0x40;
    bool rgui = modifiers & 0x80;
    
    bool shift = lshift || rshift;
    // bool ctrl = lctrl || rctrl;
    // bool alt = lalt || ralt;
    
    std::string result;
    std::string debug_info;
    
    for (int i = 2; i < 8; i++) {
        uint8_t key = data[offset + i];
        if (key != 0) {
            char c = get_char(key, shift);
            if (c != 0) {
                result += c;
            }
            debug_info += get_key_name(key) + " ";
        }
    }
    
    if (!debug_info.empty() && false) { // Set to true for debug output
        std::cout << "  [Modifiers: " << std::hex << (int)modifiers << std::dec
                  << " Keys: " << debug_info << "]\n";
    }
    
    return result;
}

int main(int argc, char* argv[]) {
    std::string filename = "keyboard_capture.log";
    if (argc > 1) {
        filename = argv[1];
    }
    
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open " << filename << "\n";
        return 1;
    }
    
    std::cout << "=== Parsing " << filename << " ===\n\n";
    std::cout << "Interpreted text (assuming Boot Protocol, 8-byte reports):\n";
    std::cout << "------------------------------------------------------------------------\n";
    
    std::string line;
    int line_num = 0;
    std::string full_text;
    
    while (std::getline(file, line)) {
        line_num++;
        
        // Parse timestamp and data
        size_t bracket_start = line.find('[');
        size_t bracket_end = line.find(']');
        if (bracket_start == std::string::npos || bracket_end == std::string::npos) {
            continue;
        }
        
        std::string timestamp = line.substr(bracket_start + 1, bracket_end - bracket_start - 1);
        
        // Find the hex data (after the "] " and any text like " bytes: ")
        size_t data_start = line.find("] ", bracket_end);
        if (data_start == std::string::npos) continue;
        data_start += 2;
        
        // Skip to the hex data (after the "XX bytes: " part)
        size_t bytes_label = line.find(" bytes: ", data_start - 2);
        if (bytes_label != std::string::npos) {
            data_start = bytes_label + 8; // " bytes: " is 8 chars
        }
        
        std::string hex_data = line.substr(data_start);
        
        // Parse hex bytes
        std::vector<uint8_t> bytes;
        std::stringstream ss(hex_data);
        std::string byte_str;
        while (ss >> byte_str) {
            try {
                uint8_t val = std::stoi(byte_str, nullptr, 16);
                bytes.push_back(val);
            } catch (...) {
                // Skip non-hex strings
            }
        }
        
        if (bytes.size() < 8) {
            continue;
        }
        
        // Try to split into 8-byte Boot Protocol reports
        // The data might contain multiple reports concatenated
        std::string line_text;
        for (size_t i = 0; i + 8 <= bytes.size(); i += 8) {
            std::string report_text = parse_boot_report(bytes, i);
            line_text += report_text;
        }
        
        if (!line_text.empty()) {
            std::cout << "[" << std::setw(3) << line_num << "] " << timestamp << ": " << line_text << "\n";
            full_text += line_text;
        }
    }
    
    std::cout << "------------------------------------------------------------------------\n";
    std::cout << "\nFull text reconstructed:\n";
    std::cout << full_text << "\n";
    std::cout << "\n(If this doesn't match what you typed, the data format might not be Boot Protocol)\n";
    
    file.close();
    return 0;
}
