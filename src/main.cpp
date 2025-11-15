// notedaemon/main.cpp
// IO Daemon with realistic config and Linux requirement validation

#include <grp.h>
#include <errno.h>  
#include <signal.h> 
#include <libusb-1.0/libusb.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <cstring>
#include <atomic>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include "../include/utils.h"
#include "../include/device_session.h"




// Global state for signal handling
std::atomic<bool> g_running{true};

void signal_handler(int signum) {
    syslog(LOG_INFO, "Received signal %d, shutting down gracefully", signum);
    g_running = false;
}

/**
 * Linux requirements checker
 */
class LinuxRequirements {
public:
    struct CheckResult {
        bool passed;
        std::string message;
        std::string fix_suggestion;
    };
    

    static void log_privileges() {
     
        // 1. Root always OK
        if (getuid() == 0) {
            syslog(LOG_INFO, "[Warning] %s: %s", "Root", 
                "Access with root user, is a security risk."
                "\nSee README.md for secure setup");
        }else{

            // 2. CAP_SYS_ADMIN can also access USB
            #ifdef _LINUX_CAPABILITY_VERSION_3
            cap_t caps = cap_get_proc();
            if (caps) {
                cap_flag_value_t cap_value;
                if (cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &cap_value) == 0) {
                    if (cap_value == CAP_SET) {
                        cap_free(caps);
                        syslog(LOG_INFO, "[Warning] %s: %s", "CAP_SYS_ADMIN", 
                            "Access with CAP_SYS_ADMIN, is a security risk."
                            "\nSee README.md for secure setup");
                    }
                }
                cap_free(caps);
            }
            #endif
        }
      
  
    }

     static bool can_access_any_usb_device() {
        libusb_device **devs;
        libusb_context* ctx = nullptr;
        int rc = libusb_init(&ctx);
        if (rc < 0) {
            syslog(LOG_ERR, "[ERROR] %s: %s", "LIBUSB Context", libusb_error_name(rc));
            return false;
        }

        ssize_t count = libusb_get_device_list(ctx, devs ? &devs : nullptr);
        
        if (count < 0) {
            syslog(LOG_INFO, "[ERROR] %s: %zd", "LIBUSB list",  count);
            libusb_exit(ctx);
            return false;
        }

        bool accessible = false;

        libusb_device** list = nullptr;
        ssize_t cnt = libusb_get_device_list(ctx, &list);
        for (ssize_t i = 0; i < cnt; i++) {
            libusb_device* dev = list[i];
            libusb_device_handle* handle = nullptr;
            rc = libusb_open(dev, &handle);
            if (rc != 0) {
                // Skip devices that cannot be opened (likely root hubs)
                continue;
            }
            accessible = true;
            // process accessible device
            libusb_close(handle);
        }
        libusb_free_device_list(list, 1);

        libusb_exit(ctx);

        return accessible;
    }


    static bool can_access_usb_device(uint16_t vendor, uint16_t product) {
        libusb_device **devs;
        libusb_context *ctx = nullptr;

        if (libusb_init(&ctx) != 0) return false;

        ssize_t count = libusb_get_device_list(ctx, &devs);
        if (count < 0) {
            libusb_exit(ctx);
            return false;
        }

        bool accessible = false;

        for (ssize_t i = 0; i < count; i++) {
            libusb_device *d = devs[i];
            libusb_device_descriptor desc;

            if (libusb_get_device_descriptor(d, &desc) == 0 &&
                desc.idVendor == vendor &&
                desc.idProduct == product)
            {
                libusb_device_handle* handle = nullptr;
                int r = libusb_open(d, &handle);

                if (r == 0) {
                    accessible = true;
                    libusb_close(handle);
                    break;
                }
            }
        }

        libusb_free_device_list(devs, 1);
        libusb_exit(ctx);
        return accessible;
    }
    
    /**
     * Check if socket group exists
     */
    static CheckResult check_socket_group(const std::string& group_name) {
        CheckResult result;
        
        struct group* grp = getgrnam(group_name.c_str());
        if (grp) {
            result.passed = true;
            result.message = "Group '" + group_name + "' exists (gid=" + 
                           std::to_string(grp->gr_gid) + ")";
            return result;
        }
        
        result.passed = false;
        result.message = "Group '" + group_name + "' does not exist";
        result.fix_suggestion = 
            "Create group: sudo groupadd " + group_name + "\n"
            "Add users: sudo usermod -aG " + group_name + " USERNAME";
        
        return result;
    }
    
    /**
     * Check if socket directory is writable
     */
    static CheckResult check_socket_directory(const std::string& dir_path) {
        CheckResult result;
        
        // Try to create directory
        if (mkdir(dir_path.c_str(), 0755) < 0 && errno != EEXIST) {
            result.passed = false;
            result.message = "Cannot create socket directory: " + std::string(strerror(errno));
            result.fix_suggestion = "Ensure " + dir_path + " is writable";
            return result;
        }
        
        // Check if writable
        if (access(dir_path.c_str(), W_OK) < 0) {
            result.passed = false;
            result.message = "Socket directory not writable";
            result.fix_suggestion = "Check permissions on " + dir_path;
            return result;
        }
        
        result.passed = true;
        result.message = "Socket directory OK";
        return result;
    }
    
    /**
     * Check libusb initialization
     */
    static CheckResult check_libusb() {
        CheckResult result;

        libusb_context* ctx = nullptr;
        int rc = libusb_init(&ctx);

        if (rc < 0) {
            result.passed = false;
            // Distinguish missing library vs init error
            if (rc == LIBUSB_ERROR_NO_MEM) {
                result.message = "libusb init failed: out of memory";
            } else if (rc == LIBUSB_ERROR_ACCESS) {
                result.message = "libusb init failed: insufficient privileges or udev rules";
            } else if (rc == LIBUSB_ERROR_NO_DEVICE) {
                result.message = "libusb init succeeded, but no USB devices found";
                result.passed = true;  // still OK at startup
            } else {
                result.message = std::string("libusb init failed: ") + libusb_error_name(rc);
            }

            result.fix_suggestion = "Ensure libusb-1.0 runtime is installed:\n"
                                    "Ubuntu/Debian: sudo apt install libusb-1.0-0\n"
                                    "Fedora: sudo dnf install libusbx\n"
                                    "Arch: sudo pacman -S libusb";

            if (ctx) libusb_exit(ctx);
            return result;
        }

        result.passed = true;
        result.message = "initialized";
        libusb_exit(ctx);
        return result;
    }
        
    /**
     * Run all checks and report
     */
    static bool validate_all(const std::string& socket_dir, const std::string& socket_group) {
        bool all_passed = true;
        
        syslog(LOG_INFO, "=== System Requirements Check ===");
        
     
        // Check libusb
        auto libusb_result = check_libusb();
        log_check_result("libusb", libusb_result);
        all_passed &= libusb_result.passed;

        // Log privileges only
        log_privileges();

        if(!all_passed){
            if(can_access_any_usb_device()) {
                syslog(LOG_INFO, "[OK] %s: %s", "USB ACCESS", "passed");
            }else{
                syslog(LOG_ALERT, "[CRITICAL] %s: %s", "USB ACCESS", "failed. Unable to open any USB device");
            }
        }
        
        // Check socket group (warning only)
        auto group_result = check_socket_group(socket_group);
        log_check_result("Socket Group", group_result);
        if (!group_result.passed) {
            syslog(LOG_WARNING, "Socket group missing - clients may have access issues");
        }
        
        // Check socket directory
        auto dir_result = check_socket_directory(socket_dir);
        log_check_result("Socket Directory", dir_result);
        all_passed &= dir_result.passed;
        
        syslog(LOG_INFO, "=================================");
        
        return all_passed;
    }
    
private:
    static void log_check_result(const char* check_name, const CheckResult& result) {
        if (result.passed) {
            syslog(LOG_INFO, "[OK] %s: %s", check_name, result.message.c_str());
        } else {
            syslog(LOG_ERR, "[FAIL] %s: %s", check_name, result.message.c_str());
            if (!result.fix_suggestion.empty()) {
                syslog(LOG_ERR, "  Fix: %s", result.fix_suggestion.c_str());
            }
        }
    }
};

/**
 * Simple config parser that works with or without JSON library
 */
class SimpleConfigParser {
public:
    std::map<std::string, std::string> values;
    
    bool parse_file(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            return false;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#' || line[0] == ';') {
                continue;
            }
            
            // Parse key=value
            size_t eq_pos = line.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = trim(line.substr(0, eq_pos));
                std::string value = trim(line.substr(eq_pos + 1));
                values[key] = value;
            }
        }
        
        return true;
    }
    
    std::string get(const std::string& key, const std::string& default_val = "") const {
        auto it = values.find(key);
        return (it != values.end()) ? it->second : default_val;
    }
    
    int get_int(const std::string& key, int default_val = 0) const {
        auto it = values.find(key);
        if (it != values.end()) {
            try {
                return std::stoi(it->second);
            } catch (...) {
                return default_val;
            }
        }
        return default_val;
    }
    
    bool get_bool(const std::string& key, bool default_val = false) const {
        auto it = values.find(key);
        if (it != values.end()) {
            std::string val = it->second;
            return (val == "true" || val == "1" || val == "yes" || val == "on");
        }
        return default_val;
    }
    
private:
    std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, last - first + 1);
    }
};

/**
 * Daemon configuration - ONLY configurable settings
 */

class DaemonConfig {
public:
    // Socket configuration
    std::string socket_path = "/run/netnotes/notedaemon.sock";
    std::string socket_dir = "/run/netnotes";
    std::string socket_group = "netnotes";
    mode_t socket_permissions = 0660;  // rw-rw----
    
    // Logging
    int log_level = LOG_INFO;
    bool log_to_stderr = false;
    
    // USB/libusb settings
    int usb_timeout_ms = 100;
    int usb_discovery_interval_ms = 1000;
    bool usb_auto_detach_kernel = true;  // REQUIRED for claiming
 
    // Security
    bool require_group_membership = true;
    std::vector<std::string> allowed_groups;
    bool allow_root_bypass = true;
    
    // Performance
    int max_clients = 10;
    size_t max_queue_size = 1000;
    int polling_interval_us = 1000;
    int thread_pool_size = 4;
    
    // Heartbeat
    bool heartbeat_enabled = true;
    int heartbeat_interval_ms = 5000;
    int heartbeat_timeout_ms = 15000;
    int heartbeat_max_missed = 3;
    
    // Backpressure
    int backpressure_max_unacked = 100;
    int backpressure_resume_threshold = 50;
    int backpressure_stale_timeout_ms = 30000;
    
    // Monitoring
    bool stats_enabled = true;
    int stats_interval_ms = 60000;
    bool event_logging = false;
    
    // Advanced
    int buffer_size = 8192;
    int event_batch_size = 10;
    bool use_epoll = true;
    
    // Debug
    bool debug_dump_packets = false;
    int debug_simulate_latency_ms = 0;
    
    /**
     * Load configuration from file
     */
    bool load_from_file(const std::string& config_path) {
        std::ifstream file(config_path);
        if (!file.is_open()) {
            syslog(LOG_INFO, "Config file not found at %s, using defaults", 
                   config_path.c_str());
            return false;
        }
        file.close();
        
        syslog(LOG_INFO, "Loading config from %s", config_path.c_str());
        
        
        if (try_load_config(config_path)) {
            syslog(LOG_INFO, "Configuration loaded from key=value format");
            validate_config();
            return true;
        }
        
        syslog(LOG_WARNING, "Failed to parse config file, using defaults");
        return false;
    }
    
    
    bool try_load_config(const std::string& path) {
        SimpleConfigParser parser;
        if (!parser.parse_file(path)) {
            return false;
        }
        
        // Socket
        socket_path = parser.get("socket.path", socket_path);
        socket_dir = parser.get("socket.dir", socket_dir);
        socket_group = parser.get("socket.group", socket_group);
        socket_permissions = static_cast<mode_t>(
            parser.get_int("socket.permissions", socket_permissions));
        
        // Logging
        std::string level = parser.get("logging.level", "info");
        if (level == "debug") log_level = LOG_DEBUG;
        else if (level == "info") log_level = LOG_INFO;
        else if (level == "warning") log_level = LOG_WARNING;
        else if (level == "error") log_level = LOG_ERR;
        log_to_stderr = parser.get_bool("logging.stderr", log_to_stderr);
        
        // USB
        usb_timeout_ms = parser.get_int("usb.timeout_ms", usb_timeout_ms);
        usb_discovery_interval_ms = parser.get_int("usb.discovery_interval_ms", 
                                                   usb_discovery_interval_ms);
        usb_auto_detach_kernel = parser.get_bool("usb.auto_detach_kernel", 
                                                usb_auto_detach_kernel);

        // Security
        require_group_membership = parser.get_bool("security.require_group", 
                                                   require_group_membership);
        allow_root_bypass = parser.get_bool("security.allow_root_bypass", 
                                           allow_root_bypass);
        
        // Performance
        max_clients = parser.get_int("performance.max_clients", max_clients);
        max_queue_size = parser.get_int("performance.max_queue_size", max_queue_size);
        polling_interval_us = parser.get_int("performance.polling_interval_us", 
                                            polling_interval_us);
        thread_pool_size = parser.get_int("performance.thread_pool_size", 
                                         thread_pool_size);
        
        // Heartbeat
        heartbeat_enabled = parser.get_bool("heartbeat.enabled", heartbeat_enabled);
        heartbeat_interval_ms = parser.get_int("heartbeat.interval_ms", 
                                              heartbeat_interval_ms);
        heartbeat_timeout_ms = parser.get_int("heartbeat.timeout_ms", 
                                             heartbeat_timeout_ms);
        heartbeat_max_missed = parser.get_int("heartbeat.max_missed", 
                                             heartbeat_max_missed);
        
        // Backpressure
        backpressure_max_unacked = parser.get_int("backpressure.max_unacknowledged", 
                                                 backpressure_max_unacked);
        backpressure_resume_threshold = parser.get_int("backpressure.resume_threshold", 
                                                      backpressure_resume_threshold);
        backpressure_stale_timeout_ms = parser.get_int("backpressure.stale_timeout_ms", 
                                                      backpressure_stale_timeout_ms);
        
        // Monitoring
        stats_enabled = parser.get_bool("monitoring.stats_enabled", stats_enabled);
        stats_interval_ms = parser.get_int("monitoring.stats_interval_ms", 
                                          stats_interval_ms);
        event_logging = parser.get_bool("monitoring.event_logging", event_logging);
        
        // Advanced
        buffer_size = parser.get_int("advanced.buffer_size", buffer_size);
        event_batch_size = parser.get_int("advanced.event_batch_size", event_batch_size);
        use_epoll = parser.get_bool("advanced.use_epoll", use_epoll);
        
        // Debug
        debug_dump_packets = parser.get_bool("debug.dump_packets", debug_dump_packets);
        debug_simulate_latency_ms = parser.get_int("debug.simulate_latency_ms", 
                                                   debug_simulate_latency_ms);
        
        return true;
    }
    
    /**
     * Validate configuration and warn about problematic settings
     */
    void validate_config() {
        // Warn if kernel detach is disabled (won't work)
        if (!usb_auto_detach_kernel) {
            syslog(LOG_WARNING, 
                   "usb.auto_detach_kernel=false will prevent device claiming!");
        }
        
        // Warn if permissions too restrictive
        if ((socket_permissions & 0060) == 0) {
            syslog(LOG_WARNING, 
                   "Socket permissions 0%o may prevent group access", socket_permissions);
        }
        
        // Warn if heartbeat disabled
        if (!heartbeat_enabled) {
            syslog(LOG_WARNING, 
                   "Heartbeat disabled - stale connections won't be detected");
        }
        
        // Warn about debug settings in production
        if (debug_dump_packets) {
            syslog(LOG_WARNING, 
                   "Packet dumping enabled - will generate lots of logs!");
        }
        
        if (event_logging) {
            syslog(LOG_WARNING, 
                   "Event logging enabled - VERY verbose!");
        }
    }
    
    /**
     * Print configuration to syslog
     */
    void log_config() const {
        syslog(LOG_INFO, "=== Daemon Configuration ===");
        syslog(LOG_INFO, "Socket: %s (group=%s, perms=0%o)", 
               socket_path.c_str(), socket_group.c_str(), socket_permissions);
        syslog(LOG_INFO, "USB: timeout=%dms, discovery=%dms, auto_detach=%d", 
               usb_timeout_ms, usb_discovery_interval_ms, usb_auto_detach_kernel);
        syslog(LOG_INFO, "Security: require_group=%d, root_bypass=%d", 
               require_group_membership, allow_root_bypass);
        syslog(LOG_INFO, "Performance: clients=%d, queue=%zu, poll=%dus, threads=%d", 
               max_clients, max_queue_size, polling_interval_us, thread_pool_size);
        syslog(LOG_INFO, "Heartbeat: enabled=%d, interval=%dms, timeout=%dms", 
               heartbeat_enabled, heartbeat_interval_ms, heartbeat_timeout_ms);
        syslog(LOG_INFO, "Backpressure: max_unacked=%d, resume=%d", 
               backpressure_max_unacked, backpressure_resume_threshold);
        syslog(LOG_INFO, "===========================");
    }
};

/**
 * Get config path from user's home directory
 */
std::string get_config_path() {
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }
    
    if (home) {
        return std::string(home) + "/.netnotes/config";
    }
    
    return "";
}

/**
 * Main daemon class
 */
class NoteDaemon {
private:
    libusb_context* usb_ctx = nullptr;
    int server_socket = -1;
    DaemonConfig config;

public:
    int run() {
        signal(SIGTERM, signal_handler);
        signal(SIGINT, signal_handler);

        // Open syslog
        int log_options = LOG_PID;
        if (config.log_to_stderr) {
            log_options |= LOG_PERROR;
        }
        openlog("notedaemon", log_options, LOG_DAEMON);
        setlogmask(LOG_UPTO(config.log_level));
        
        syslog(LOG_INFO, "NoteDaemon starting (capability-aware protocol)");

        // Load configuration
        std::string config_path = get_config_path();
        if (!config_path.empty()) {
            config.load_from_file(config_path);
        } else {
            syslog(LOG_WARNING, "Could not determine config path, using defaults");
        }
        
        config.log_config();

        // Validate Linux requirements
        if (!LinuxRequirements::validate_all(config.socket_dir, config.socket_group)) {
            syslog(LOG_ERR, "System requirements not met, cannot start");
            return 1;
        }

        // Initialize libusb
        int result = libusb_init(&usb_ctx);
        if (result < 0) {
            syslog(LOG_ERR, "Failed to initialize libusb: %s", 
                   libusb_error_name(result));
            return 1;
        }

        // Setup socket
        if (!setup_socket()) {
            libusb_exit(usb_ctx);
            return 1;
        }

        syslog(LOG_INFO, "Daemon ready on %s", config.socket_path.c_str());

        // Main event loop
        while (g_running) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(server_socket, &read_fds);

            struct timeval timeout = {1, 0};
            int activity = select(server_socket + 1, &read_fds, nullptr, nullptr, &timeout);

            if (activity < 0 && errno != EINTR) {
                syslog(LOG_ERR, "Select error: %s", strerror(errno));
                break;
            }

            if (activity > 0 && FD_ISSET(server_socket, &read_fds)) {
                handle_client();
            }
        }

        cleanup();
        syslog(LOG_INFO, "NoteDaemon stopped");
        closelog();
        return 0;
    }

private:
    bool setup_socket() {
        // Create socket directory
        if (mkdir(config.socket_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            syslog(LOG_ERR, "Failed to create socket directory %s: %s",
                   config.socket_dir.c_str(), strerror(errno));
            return false;
        }

        // Remove old socket
        unlink(config.socket_path.c_str());

        // Create socket
        server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_socket < 0) {
            syslog(LOG_ERR, "Failed to create socket: %s", strerror(errno));
            return false;
        }

        // Bind socket
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, config.socket_path.c_str(), sizeof(addr.sun_path) - 1);

        if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            syslog(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
            safe_close(server_socket);
            return false;
        }

        // Set socket permissions
        if (chmod(config.socket_path.c_str(), config.socket_permissions) < 0) {
            syslog(LOG_WARNING, "Failed to set socket permissions: %s", 
                   strerror(errno));
        }

        // Set socket group
        struct group* grp = getgrnam(config.socket_group.c_str());
        if (grp) {
            if (chown(config.socket_path.c_str(), -1, grp->gr_gid) < 0) {
                syslog(LOG_WARNING, "Failed to set socket group: %s", 
                       strerror(errno));
            }
        }

        // Listen
        if (listen(server_socket, 5) < 0) {
            syslog(LOG_ERR, "Failed to listen on socket: %s", strerror(errno));
            safe_close(server_socket);
            return false;
        }

        return true;
    }

    void handle_client() {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(server_socket, 
                              (struct sockaddr*)&client_addr, 
                              &client_len);
        if (client_fd < 0) {
            syslog(LOG_WARNING, "Failed to accept client: %s", strerror(errno));
            return;
        }
        
        // Get peer credentials
        struct ucred creds;
        socklen_t len = sizeof(creds);
        if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &creds, &len) < 0) {
            syslog(LOG_WARNING, "Failed to get peer credentials: %s", 
                   strerror(errno));
            safe_close(client_fd);
            return;
        }
        
        syslog(LOG_INFO, "Client connected: uid=%d, gid=%d, pid=%d", 
               creds.uid, creds.gid, creds.pid);
        
        // Check group membership if required
        if (config.require_group_membership && !check_group_access(creds.uid)) {
            syslog(LOG_WARNING, "Client uid=%d denied: not in allowed groups", 
                   creds.uid);
            safe_close(client_fd);
            return;
        }
        
        // Create device session
        DeviceSession session(usb_ctx, client_fd, creds.pid);
        session.handle_client_protocol_negotiation();
        
        syslog(LOG_INFO, "Client session ended: pid=%d", creds.pid);
        safe_close(client_fd);
    }
    
    bool check_group_access(uid_t uid) {
        // Root bypass
        if (uid == 0 && config.allow_root_bypass) {
            return true;
        }
        
        // Get user info
        struct passwd* pw = getpwuid(uid);
        if (!pw) {
            return false;
        }
        
        // Check primary group
        struct group* primary_grp = getgrgid(pw->pw_gid);
        if (primary_grp && config.socket_group == primary_grp->gr_name) {
            return true;
        }
        
        // Check socket group membership
        struct group* sock_grp = getgrnam(config.socket_group.c_str());
        if (sock_grp) {
            for (int i = 0; sock_grp->gr_mem[i] != nullptr; i++) {
                if (strcmp(sock_grp->gr_mem[i], pw->pw_name) == 0) {
                    return true;
                }
            }
        }
        
        // Check allowed_groups list
        for (const auto& group_name : config.allowed_groups) {
            struct group* grp = getgrnam(group_name.c_str());
            if (!grp) continue;
            
            for (int i = 0; grp->gr_mem[i] != nullptr; i++) {
                if (strcmp(grp->gr_mem[i], pw->pw_name) == 0) {
                    return true;
                }
            }
        }
        
        return false;
    }

    void cleanup() {
        if (server_socket >= 0) {
            safe_close(server_socket);
            unlink(config.socket_path.c_str());
        }
        
        if (usb_ctx) {
            libusb_exit(usb_ctx);
        }
    }
};

/**
 * Main entry point
 */
int main(int argc, char* argv[]) {
    // Parse command line arguments
    bool show_help = false;
    bool check_only = false;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            show_help = true;
        } else if (arg == "--check" || arg == "-c") {
            check_only = true;
        }
    }
    
    if (show_help) {
        fprintf(stderr, "NetNotes IO Daemon\n");
        fprintf(stderr, "Usage: %s [OPTIONS]\n\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -h, --help     Show this help message\n");
        fprintf(stderr, "  -c, --check    Check system requirements and exit\n\n");
        fprintf(stderr, "Configuration:\n");
        fprintf(stderr, "  Config file: ~/.netnotes/config (key=value)\n");
        fprintf(stderr, "  Socket: /run/netnotes/notedaemon.sock\n\n");
        fprintf(stderr, "Requirements:\n");
        fprintf(stderr, "  - Root privileges OR proper udev rules\n");
        fprintf(stderr, "  - Group 'netnotes' for socket access\n");
        fprintf(stderr, "  - libusb-1.0\n\n");
        fprintf(stderr, "Setup:\n");
        fprintf(stderr, "  1. Create group: sudo groupadd netnotes\n");
        fprintf(stderr, "  2. Add users: sudo usermod -aG netnotes USERNAME\n");
        fprintf(stderr, "  3. Run daemon: sudo ./notedaemon\n");
        return 0;
    }
    
    // No root-only check: rely on udev rules and device node permissions
    // If device access fails, LinuxRequirements will print a warning and exit.
    
    // Check-only mode
    if (check_only) {
        openlog("notedaemon-check", LOG_PERROR | LOG_PID, LOG_DAEMON);
        
        DaemonConfig config;
        std::string config_path = get_config_path();
        if (!config_path.empty()) {
            config.load_from_file(config_path);
        }
        
        bool passed = LinuxRequirements::validate_all(
            config.socket_dir, 
            config.socket_group
        );
        
        closelog();
        return passed ? 0 : 1;
    }
    
    // Run daemon
    NoteDaemon daemon;
    return daemon.run();
}