// include/module_framework/error.h
// Error struct for module framework

#ifndef ERROR_H
#define ERROR_H

#include <cstdint>
#include <chrono>
#include <string>
#include <string_view>

namespace NoteDaemon {

/**
 * Error codes for the module framework
 */
namespace ErrorCodes {
    constexpr int SUCCESS = 0;
    
    // General errors (1-99)
    constexpr int UNKNOWN = 1;
    constexpr int NOT_INITIALIZED = 2;
    constexpr int ALREADY_INITIALIZED = 3;
    constexpr int INVALID_STATE = 4;
    
    // Module loading errors (100-199)
    constexpr int MODULE_LOAD_FAILED = 100;
    constexpr int MODULE_NOT_FOUND = 101;
    constexpr int MODULE_SYMBOL_NOT_FOUND = 102;
    constexpr int MODULE_INIT_FAILED = 103;
    constexpr int MODULE_START_FAILED = 104;
    constexpr int MODULE_HEALTH_CHECK_FAILED = 105;
    constexpr int MODULE_INCOMPATIBLE_VERSION = 106;
    
    // Configuration errors (200-299)
    constexpr int CONFIG_LOAD_FAILED = 200;
    constexpr int CONFIG_PARSE_ERROR = 201;
    constexpr int CONFIG_MISSING_REQUIRED = 202;
    
    // Handler errors (300-399)
    constexpr int HANDLER_NOT_FOUND = 300;
    constexpr int HANDLER_ALREADY_REGISTERED = 301;
    constexpr int HANDLER_DISPATCH_FAILED = 302;
    
    // Message errors (350-359)
    constexpr int INVALID_MESSAGE = 350;
    
    // Module registry errors (400-499)
    constexpr int MODULE_NOT_REGISTERED = 400;
    constexpr int MODULE_ALREADY_REGISTERED = 401;
    
    // Encryption errors (500-599)
    constexpr int ENCRYPTION_INIT_FAILED = 500;
    constexpr int ENCRYPTION_NOT_INITIALIZED = 501;
    constexpr int ENCRYPTION_FAILED = 502;
    constexpr int ENCRYPTION_DEVICE_NOT_FOUND = 503;
}

/**
 * Error struct for module framework
 * Used instead of exceptions for cleaner error handling
 */
struct Error {
    int code = ErrorCodes::SUCCESS;
    std::string description;
    std::string module;      // Which module generated the error (if applicable)
    uint64_t timestamp = 0;   // Unix timestamp in milliseconds
    
    Error() = default;
    
    Error(int code_, std::string_view desc, std::string_view mod = "")
        : code(code_), description(desc), module(mod), timestamp(get_timestamp()) {}
    
    bool success() const { return code == ErrorCodes::SUCCESS; }
    bool failed() const { return code != ErrorCodes::SUCCESS; }
    
    std::string_view message() const { return description; }
    
    // Static method removed - use default constructor or from_code() directly
    
    static Error from_code(int code, std::string_view desc, std::string_view mod = "") {
        return Error(code, desc, mod);
    }
    
private:
    static uint64_t get_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    }
};

/**
 * Error category for additional context
 */
enum class ErrorCategory {
    NONE,
    MODULE_LOAD,
    MODULE_INIT,
    MODULE_RUNTIME,
    CONFIG,
    HANDLER,
    ENCRYPTION,
    INTERNAL
};

} // namespace NoteDaemon

#endif // ERROR_H