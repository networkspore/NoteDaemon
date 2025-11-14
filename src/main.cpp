// notedaemon/main.cpp
// IO Daemon main entry point with configuration support

#include <grp.h>
#include <errno.h>  
#include <signal.h> 
#include <libusb-1.0/libusb.h>
#include <sys/socket.h>
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

#include "../include/utils.h"
#include "../include/device_session.h"

// Try to include nlohmann/json if available
#ifdef HAVE_NLOHMANN_JSON
#include <nlohmann/json.hpp>
using json = nlohmann::json;
#define JSON_AVAILABLE 1
#else
#define JSON_AVAILABLE 0
#endif

// Global state for signal handling
std::atomic<bool> g_running{true};

void signal_handler(int signum) {
    syslog(LOG_INFO, "Received signal %d, shutting down gracefully", signum);
    g_running = false;
}

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
 * Configuration manager
 */
class DaemonConfig {
public:
    // Socket configuration
    std::string socket_path = "/run/netnotes/notedaemon.sock";
    std::string socket_dir = "/run/netnotes";
    std::string socket_group = "input";  // Group that can access socket
    mode_t socket_permissions = 0660;    // rw-rw----
    
    // Logging configuration
    int log_level = LOG_INFO;
    bool log_to_stderr = false;
    
    // USB configuration
    bool auto_detach_kernel = true;      // Automatically detach kernel drivers
    int usb_timeout_ms = 100;            // USB transfer timeout
    
    // Security configuration
    bool require_group_membership = true; // Require clients to be in socket_group
    std::vector<std::string> allowed_groups;
    
    // Performance configuration
    size_t max_queue_size = 1000;        // Max event queue size per device
    int polling_interval_us = 1000;      // Polling interval in microseconds
    
    /**
     * Load configuration from file (supports both JSON and simple key=value)
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
        
#if JSON_AVAILABLE
        // Try JSON format first
        if (try_load_json(config_path)) {
            syslog(LOG_INFO, "Configuration loaded from JSON");
            return true;
        }
#endif
        
        // Fall back to simple key=value format
        if (try_load_simple(config_path)) {
            syslog(LOG_INFO, "Configuration loaded from key=value format");
            return true;
        }
        
        syslog(LOG_WARNING, "Failed to parse config file, using defaults");
        return false;
    }
    
#if JSON_AVAILABLE
    /**
     * Load from JSON format
     */
    bool try_load_json(const std::string& path) {
        try {
            std::ifstream file(path);
            json config = json::parse(file);
            
            // Socket configuration
            if (config.contains("socket")) {
                auto sock = config["socket"];
                if (sock.contains("path")) socket_path = sock["path"];
                if (sock.contains("dir")) socket_dir = sock["dir"];
                if (sock.contains("group")) socket_group = sock["group"];
                if (sock.contains("permissions")) {
                    socket_permissions = static_cast<mode_t>(sock["permissions"].get<int>());
                }
            }
            
            // Logging configuration
            if (config.contains("logging")) {
                auto log = config["logging"];
                if (log.contains("level")) {
                    std::string level = log["level"];
                    if (level == "debug") log_level = LOG_DEBUG;
                    else if (level == "info") log_level = LOG_INFO;
                    else if (level == "warning") log_level = LOG_WARNING;
                    else if (level == "error") log_level = LOG_ERR;
                }
                if (log.contains("stderr")) log_to_stderr = log["stderr"];
            }
            
            // USB configuration
            if (config.contains("usb")) {
                auto usb = config["usb"];
                if (usb.contains("auto_detach_kernel")) {
                    auto_detach_kernel = usb["auto_detach_kernel"];
                }
                if (usb.contains("timeout_ms")) usb_timeout_ms = usb["timeout_ms"];
            }
            
            // Security configuration
            if (config.contains("security")) {
                auto sec = config["security"];
                if (sec.contains("require_group")) {
                    require_group_membership = sec["require_group"];
                }
                if (sec.contains("allowed_groups") && sec["allowed_groups"].is_array()) {
                    allowed_groups.clear();
                    for (const auto& grp : sec["allowed_groups"]) {
                        allowed_groups.push_back(grp);
                    }
                }
            }
            
            // Performance configuration
            if (config.contains("performance")) {
                auto perf = config["performance"];
                if (perf.contains("max_queue_size")) {
                    max_queue_size = perf["max_queue_size"];
                }
                if (perf.contains("polling_interval_us")) {
                    polling_interval_us = perf["polling_interval_us"];
                }
            }
            
            return true;
            
        } catch (const std::exception& e) {
            syslog(LOG_WARNING, "JSON parse error: %s", e.what());
            return false;
        }
    }
#endif
    
    /**
     * Load from simple key=value format
     */
    bool try_load_simple(const std::string& path) {
        SimpleConfigParser parser;
        if (!parser.parse_file(path)) {
            return false;
        }
        
        // Socket configuration
        socket_path = parser.get("socket.path", socket_path);
        socket_dir = parser.get("socket.dir", socket_dir);
        socket_group = parser.get("socket.group", socket_group);
        socket_permissions = static_cast<mode_t>(
            parser.get_int("socket.permissions", socket_permissions));
        
        // Logging configuration
        std::string level = parser.get("logging.level", "info");
        if (level == "debug") log_level = LOG_DEBUG;
        else if (level == "info") log_level = LOG_INFO;
        else if (level == "warning") log_level = LOG_WARNING;
        else if (level == "error") log_level = LOG_ERR;
        
        log_to_stderr = parser.get_bool("logging.stderr", log_to_stderr);
        
        // USB configuration
        auto_detach_kernel = parser.get_bool("usb.auto_detach_kernel", auto_detach_kernel);
        usb_timeout_ms = parser.get_int("usb.timeout_ms", usb_timeout_ms);
        
        // Security configuration
        require_group_membership = parser.get_bool("security.require_group", 
                                                    require_group_membership);
        
        // Performance configuration
        max_queue_size = static_cast<size_t>(
            parser.get_int("performance.max_queue_size", max_queue_size));
        polling_interval_us = parser.get_int("performance.polling_interval_us",
                                             polling_interval_us);
        
        return true;
    }
    
    /**
     * Print current configuration to syslog
     */
    void log_config() const {
        syslog(LOG_INFO, "=== Daemon Configuration ===");
        syslog(LOG_INFO, "Socket: %s (group=%s, perms=%04o)", 
               socket_path.c_str(), socket_group.c_str(), socket_permissions);
        syslog(LOG_INFO, "USB: auto_detach=%d, timeout=%dms", 
               auto_detach_kernel, usb_timeout_ms);
        syslog(LOG_INFO, "Security: require_group=%d", require_group_membership);
        syslog(LOG_INFO, "Performance: queue=%zu, poll=%dus", 
               max_queue_size, polling_interval_us);
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
        std::string config_path = std::string(home) + "/.netnotes/config";
        return config_path;
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
        
        syslog(LOG_INFO, "NoteDaemon starting (capability-aware server)");

        // Load configuration
        std::string config_path = get_config_path();
        if (!config_path.empty()) {
            config.load_from_file(config_path);
        } else {
            syslog(LOG_WARNING, "Could not determine config path, using defaults");
        }
        
        config.log_config();

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

        syslog(LOG_INFO, "Listening on %s", config.socket_path.c_str());

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
    /**
     * Setup Unix domain socket
     */
    bool setup_socket() {
        // Create socket directory if it doesn't exist
        if (mkdir(config.socket_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            syslog(LOG_ERR, "Failed to create socket directory %s: %s",
                   config.socket_dir.c_str(), strerror(errno));
            return false;
        }

        // Remove old socket if it exists
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
        } else {
            syslog(LOG_WARNING, "Group '%s' not found", config.socket_group.c_str());
        }

        // Listen
        if (listen(server_socket, 5) < 0) {
            syslog(LOG_ERR, "Failed to listen on socket: %s", strerror(errno));
            safe_close(server_socket);
            return false;
        }

        return true;
    }

    /**
     * Handle incoming client connection
     */
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
        
        syslog(LOG_INFO, "Client connected: uid=%d, pid=%d", creds.uid, creds.pid);
        
        // Check group membership if required
        if (config.require_group_membership && !check_group_access(creds.uid)) {
            syslog(LOG_WARNING, "Client uid=%d denied: not in allowed groups", 
                   creds.uid);
            safe_close(client_fd);
            return;
        }
        
        // Create device session (from daemon_server.cpp)
        DeviceSession session(usb_ctx, client_fd, creds.pid);
        session.handle_client_protocol_negotiation();
        
        syslog(LOG_INFO, "Client session ended: pid=%d", creds.pid);
        safe_close(client_fd);
    }
    
    /**
     * Check if user has access based on group membership
     */
    bool check_group_access(uid_t uid) {
        // Root always has access
        if (uid == 0) {
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
        
        // Check supplementary groups
        struct group* sock_grp = getgrnam(config.socket_group.c_str());
        if (!sock_grp) {
            return false;
        }
        
        for (int i = 0; sock_grp->gr_mem[i] != nullptr; i++) {
            if (strcmp(sock_grp->gr_mem[i], pw->pw_name) == 0) {
                return true;
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

    /**
     * Cleanup resources
     */
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
int main(int /* argc */, char* argv[]) {
    // Check for root privileges
    if (getuid() != 0) {
        fprintf(stderr, "NoteDaemon must run as root\n");
        fprintf(stderr, "Run with: sudo %s\n", argv[0]);
        return 1;
    }
    
    // Run daemon
    NoteDaemon daemon;
    return daemon.run();
}