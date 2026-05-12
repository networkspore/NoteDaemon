// include/async_logger.h
// Asynchronous logging system - runs on its own thread to avoid mutex contention
// All threads can log without blocking - messages are queued and written by dedicated thread

#ifndef ASYNC_LOGGER_H
#define ASYNC_LOGGER_H

#include <string>
#include <string_view>
#include <vector>
#include <queue>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <sys/syslog.h>

namespace AsyncLogger {

/**
 * Log level enum
 */
enum class Level {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

/**
 * Log message structure
 */
struct LogMessage {
    Level level;
    std::string message;
    std::string component;  // e.g., "NoteDaemon", "NoteUSB", "DeviceSession"
    
    // Default constructor
    LogMessage() : level(Level::INFO), message(), component() {}
    
    // Parameterized constructor
    LogMessage(Level lvl, std::string_view msg, std::string_view comp)
        : level(lvl), message(msg), component(comp) {}
};

/**
 * AsyncLogger - thread-safe async logging with dedicated background thread
 * 
 * Usage:
 *   AsyncLogger::start();           // Start the logger (call once at startup)
 *   AsyncLogger::log_info("message", "component");
 *   AsyncLogger::log_error("message", "component");
 *   AsyncLogger::stop();            // Stop the logger (call at shutdown)
 */
class Logger {
private:
    static std::queue<LogMessage> message_queue_;
    static std::mutex queue_mutex_;
    static std::condition_variable queue_cv_;
    static std::atomic<bool> running_;
    static std::thread logger_thread_;
    static bool initialized_;
    
    // Prevent construction - use static methods
    Logger() = delete;
    ~Logger() = delete;
    
    /**
     * Logger thread function - processes messages from queue
     */
    static void logger_thread_func() {
        while (running_.load()) {
            LogMessage msg;
            bool has_message = false;
            
            // Try to get a message from the queue
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                
                // Wait until there's a message or we're stopping
                queue_cv_.wait_for(lock, std::chrono::milliseconds(100), [] {
                    return !message_queue_.empty() || !running_.load();
                });
                
                if (!running_.load() && message_queue_.empty()) {
                    break;
                }
                
                if (!message_queue_.empty()) {
                    msg = std::move(message_queue_.front());
                    message_queue_.pop();
                    has_message = true;
                }
            }

            // Spurious wakeup/timeout with no queued message.
            // Do not emit placeholder logs.
            if (!has_message) {
                continue;
            }
            
            // Ignore empty log payloads.
            if (msg.message.empty()) {
                continue;
            }

            // Write the message to syslog (outside the lock)
            if (msg.component.empty()) {
                msg.component = "NoteDaemon";
            }
            
            int syslog_priority;
            switch (msg.level) {
                case Level::DEBUG:    syslog_priority = LOG_DEBUG; break;
                case Level::INFO:     syslog_priority = LOG_INFO; break;
                case Level::WARNING:  syslog_priority = LOG_WARNING; break;
                case Level::ERROR:    syslog_priority = LOG_ERR; break;
                case Level::CRITICAL: syslog_priority = LOG_CRIT; break;
                default:              syslog_priority = LOG_INFO; break;
            }
            
            // Format: [component] message
            std::string formatted = "[" + msg.component + "] " + msg.message;
            syslog(syslog_priority, "%s", formatted.c_str());
        }
        
        // Drain any remaining messages before stopping
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            while (!message_queue_.empty()) {
                auto msg = std::move(message_queue_.front());
                
                int syslog_priority;
                switch (msg.level) {
                    case Level::DEBUG:    syslog_priority = LOG_DEBUG; break;
                    case Level::INFO:     syslog_priority = LOG_INFO; break;
                    case Level::WARNING:  syslog_priority = LOG_WARNING; break;
                    case Level::ERROR:    syslog_priority = LOG_ERR; break;
                    case Level::CRITICAL: syslog_priority = LOG_CRIT; break;
                    default:              syslog_priority = LOG_INFO; break;
                }
                if (msg.message.empty()) {
                    message_queue_.pop();
                    continue;
                }

                if (msg.component.empty()) {
                    msg.component = "NoteDaemon";
                }

                std::string formatted = "[" + msg.component + "] " + msg.message;
                syslog(syslog_priority, "%s", formatted.c_str());
                
                message_queue_.pop();
            }
        }
    }
    
public:
    /**
     * Start the async logger - must be called before any logging
     * Call once at program startup
     */
    static void start() {
        if (initialized_) {
            return;  // Already started
        }
        
        running_.store(true);
        logger_thread_ = std::thread(logger_thread_func);
        initialized_ = true;
        
        syslog(LOG_INFO, "AsyncLogger: started");
    }
    
    /**
     * Stop the async logger - must be called at program shutdown
     * Call once at program exit
     */
    static void stop() {
        if (!initialized_) {
            return;  // Not started
        }
        
        running_.store(false);
        queue_cv_.notify_all();
        
        if (logger_thread_.joinable()) {
            logger_thread_.join();
        }
        
        initialized_ = false;
    }
    
    /**
     * Log a debug message
     */
    static void log_debug(std::string_view message, std::string_view component = "NoteDaemon") {
        if (!initialized_) {
            return;
        }
        
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            message_queue_.push(LogMessage(Level::DEBUG, message, component));
        }
        queue_cv_.notify_one();
    }
    
    /**
     * Log an info message
     */
    static void log_info(std::string_view message, std::string_view component = "NoteDaemon") {
        if (!initialized_) {
            return;
        }
        
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            message_queue_.push(LogMessage(Level::INFO, message, component));
        }
        queue_cv_.notify_one();
    }
    
    /**
     * Log a warning message
     */
    static void log_warning(std::string_view message, std::string_view component = "NoteDaemon") {
        if (!initialized_) {
            return;
        }
        
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            message_queue_.push(LogMessage(Level::WARNING, message, component));
        }
        queue_cv_.notify_one();
    }
    
    /**
     * Log an error message
     */
    static void log_error(std::string_view message, std::string_view component = "NoteDaemon") {
        if (!initialized_) {
            return;
        }
        
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            message_queue_.push(LogMessage(Level::ERROR, message, component));
        }
        queue_cv_.notify_one();
    }
    
    /**
     * Log a critical message
     */
    static void log_critical(std::string_view message, std::string_view component = "NoteDaemon") {
        if (!initialized_) {
            return;
        }
        
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            message_queue_.push(LogMessage(Level::CRITICAL, message, component));
        }
        queue_cv_.notify_one();
    }
    
    /**
     * Convenience method for formatted messages (like printf)
     */
    template<typename... Args>
    static void log_debugFormatted(std::string_view format, Args&&... args, 
                                    std::string_view component = "NoteDaemon") {
        if (!initialized_) {
            return;
        }
        
        char buffer[1024];
        snprintf(buffer, sizeof(buffer), format.data(), std::forward<Args>(args)...);
        
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            message_queue_.push(LogMessage(Level::DEBUG, buffer, component));
        }
        queue_cv_.notify_one();
    }
    
    template<typename... Args>
    static void log_infoFormatted(std::string_view format, Args&&... args,
                                   std::string_view component = "NoteDaemon") {
        if (!initialized_) {
            return;
        }
        
        char buffer[1024];
        snprintf(buffer, sizeof(buffer), format.data(), std::forward<Args>(args)...);
        
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            message_queue_.push(LogMessage(Level::INFO, buffer, component));
        }
        queue_cv_.notify_one();
    }
};

// Static member initialization
inline std::queue<LogMessage> Logger::message_queue_;
inline std::mutex Logger::queue_mutex_;
inline std::condition_variable Logger::queue_cv_;
inline std::atomic<bool> Logger::running_(false);
inline std::thread Logger::logger_thread_;
inline bool Logger::initialized_(false);

// Convenience macros for easy logging
#define ASYNC_LOG_DEBUG(msg) AsyncLogger::Logger::log_debug(msg)
#define ASYNC_LOG_INFO(msg) AsyncLogger::Logger::log_info(msg)
#define ASYNC_LOG_WARNING(msg) AsyncLogger::Logger::log_warning(msg)
#define ASYNC_LOG_ERROR(msg) AsyncLogger::Logger::log_error(msg)
#define ASYNC_LOG_CRITICAL(msg) AsyncLogger::Logger::log_critical(msg)

// With component
#define ASYNC_LOG_DEBUG_COMP(msg, comp) AsyncLogger::Logger::log_debug(msg, comp)
#define ASYNC_LOG_INFO_COMP(msg, comp) AsyncLogger::Logger::log_info(msg, comp)
#define ASYNC_LOG_WARNING_COMP(msg, comp) AsyncLogger::Logger::log_warning(msg, comp)
#define ASYNC_LOG_ERROR_COMP(msg, comp) AsyncLogger::Logger::log_error(msg, comp)

} // namespace AsyncLogger

#endif // ASYNC_LOGGER_H
