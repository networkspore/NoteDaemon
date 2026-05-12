// include/logger.h
// Thread-safe logger with dedicated logging thread
// Uses a producer-consumer queue - callers push to queue, dedicated thread writes to syslog

#ifndef LOGGER_H
#define LOGGER_H

#include <syslog.h>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <string>
#include <string_view>
#include <atomic>
#include <memory>

namespace NoteDaemon {

/**
 * Thread-safe logger with dedicated logging thread
 * 
 * Usage:
 *   Logger::init("mydaemon");  // Initialize at startup
 *   Logger::log(LOG_INFO, "My message");  // Log from any thread
 *   Logger::shutdown();  // Cleanup at shutdown
 * 
 * All log messages are queued and written to syslog by a single dedicated thread,
 * which provides natural synchronization without mutexes in the caller.
 */
class Logger {
public:
    /**
     * Initialize the logger - must be called before using the logger
     * @param ident Syslog ident string (typically the program name)
     */
    static void init(std::string_view ident) {
        getInstance().start(ident);
    }
    
    /**
     * Shutdown the logger - must be called before exit
     */
    static void shutdown() {
        getInstance().stop();
    }
    
    /**
     * Log a message - thread-safe, can be called from any thread
     * @param priority Syslog priority (LOG_INFO, LOG_DEBUG, etc.)
     * @param format Printf-style format string
     * @param ... Format arguments
     */
    static void log(int priority, const char* format, ...) {
        va_list args;
        va_start(args, format);
        getInstance().logVa(priority, format, args);
        va_end(args);
    }
    
    /**
     * Log a message with varargs - used internally
     */
    static void logVa(int priority, const char* format, va_list args) {
        getInstance().pushLog(priority, format, args);
    }
    
    // Convenience macros for common priorities
    #define LOG_INFO(fmt, ...) Logger::log(LOG_INFO, fmt, ##__VA_ARGS__)
    #define LOG_DEBUG(fmt, ...) Logger::log(LOG_DEBUG, fmt, ##__VA_ARGS__)
    #define LOG_WARNING(fmt, ...) Logger::log(LOG_WARNING, fmt, ##__VA_ARGS__)
    #define LOG_ERROR(fmt, ...) Logger::log(LOG_ERR, fmt, ##__VA_ARGS__)

private:
    Logger() = default;
    ~Logger() = default;
    
    // Singleton access
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }
    
    // Start the logging thread
    void start(std::string_view ident) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (running_) {
            return;  // Already running
        }
        
        ident_ = ident;
        running_ = true;
        log_thread_ = std::thread([this]() { workerThread(); });
    }
    
    // Stop the logging thread
    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_) {
                return;
            }
            running_ = false;
            cv_.notify_all();  // Wake up worker thread to exit
        }
        
        if (log_thread_.joinable()) {
            log_thread_.join();
        }
    }
    
    // Push a log message to the queue (non-blocking)
    void pushLog(int priority, const char* format, va_list args) {
        // Format the message first (in the caller's thread)
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), format, args);
        
        std::string message(buffer);
        
        // Push to queue (with minimal locking)
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            log_queue_.push({priority, message});
        }
        
        // Notify worker thread
        cv_.notify_one();
    }
    
    // Worker thread - reads from queue and writes to syslog
    void workerThread() {
        // Open syslog with our ident
        openlog(ident_.c_str(), LOG_PID, LOG_DAEMON);
        
        while (true) {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            // Wait for messages or shutdown signal
            cv_.wait_for(lock, std::chrono::milliseconds(100), [this] {
                return !log_queue_.empty() || !running_;
            });
            
            // Process all queued messages
            while (!log_queue_.empty()) {
                auto msg = log_queue_.front();
                log_queue_.pop();
                
                // Unlock while writing to syslog (syslog is thread-safe)
                lock.unlock();
                syslog(msg.priority, "%s", msg.message.c_str());
                lock.lock();
            }
            
            // Exit if signaled and queue is empty
            if (!running_ && log_queue_.empty()) {
                break;
            }
        }
        
        closelog();
    }
    
    // Instance state
    std::string ident_;
    std::atomic<bool> running_{false};
    std::thread log_thread_;
    
    // Queue and synchronization
    struct LogMessage {
        int priority;
        std::string message;
    };
    
    std::queue<LogMessage> log_queue_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::mutex mutex_;  // For initialization
};

} // namespace NoteDaemon

#endif // LOGGER_H