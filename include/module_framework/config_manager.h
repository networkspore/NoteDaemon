// include/module_framework/config_manager.h
// Module configuration loading and management

#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <string>
#include <string_view>
#include <variant>
#include <memory>
#include <unordered_map>
#include "error.h"
#include "json.hpp"

namespace NoteDaemon {

// Use nlohmann::json directly from json.hpp

/**
 * Configuration manager - loads and provides module configurations
 */
class ConfigManager {
public:
    ConfigManager() = default;
    ~ConfigManager() = default;
    
    // Prevent copying
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    /**
     * Load configuration for a module
     * 
     * @param module_name Name of the module
     * @param config_path Path to config.json
     * @return Loaded JSON config, or error
     */
    std::variant<nlohmann::json, Error> load_module_config(std::string_view module_name,
                                                            std::string_view config_path);
    
    /**
     * Get cached configuration for a module
     * 
     * @param module_name Name of the module
     * @return Pointer to config, or nullptr if not loaded
     */
    const nlohmann::json* get_config(std::string_view module_name) const;
    
    /**
     * Check if a module has configuration loaded
     * 
     * @param module_name Name of the module
     * @return true if loaded
     */
    bool has_config(std::string_view module_name) const;
    
    /**
     * Get all loaded module names
     * 
     * @return Vector of module names
     */
    std::vector<std::string> get_loaded_modules() const;
    
    /**
     * Reload configuration for a module
     * 
     * @param module_name Name of the module
     * @param config_path Path to config.json
     * @return Reloaded config, or error
     */
    std::variant<nlohmann::json, Error> reload_module_config(std::string_view module_name,
                                                              std::string_view config_path);
    
    /**
     * Clear all cached configurations
     */
    void clear();

private:
    std::variant<nlohmann::json, Error> parse_json_file(std::string_view path);
    
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<nlohmann::json>> configs_;
};

/**
 * Core configuration - from /etc/netnotes/netnotes.conf
 */
class CoreConfig {
public:
    CoreConfig() = default;
    ~CoreConfig() = default;
    
    // Prevent copying
    CoreConfig(const CoreConfig&) = delete;
    CoreConfig& operator=(const CoreConfig&) = delete;
    
    /**
     * Load core configuration from file
     * 
     * @param config_path Path to netnotes.conf
     * @return Error::success() or error
     */
    Error load_from_file(std::string_view config_path);
    
    // Socket settings
    std::string socket_type = "unix";  // "unix" or "tcp"
    std::string socket_path = "/run/netnotes/notedaemon.sock";
    std::string socket_dir = "/run/netnotes";
    std::string socket_group = "netnotes";
    mode_t socket_permissions = 0660;
    
    // TCP settings (when socket_type = "tcp")
    std::string bind_address = "127.0.0.1";
    int listen_port = 0;  // 0 = disabled (unix mode default)
    
    // IP allowlisting (TCP mode only)
    std::vector<std::string> allowed_ips;  // IP addresses or CIDR ranges
    bool deny_unlisted = true;  // deny connections not in allow list
    
    // TLS settings (TCP mode only)
    bool tls_enabled = false;
    std::string tls_cert_file = "/etc/netnotes/certs/server.crt";
    std::string tls_key_file = "/etc/netnotes/certs/server.key";
    std::string tls_ca_file = "/etc/netnotes/certs/ca.crt";
    bool tls_require_client_cert = false;  // true = mutual TLS (mTLS)
    
    // Logging
    int log_level = LOG_INFO;
    bool log_to_stderr = false;
    
    // Module settings
    std::string module_directory = "/etc/netnotes/modules";
    bool strict_load = true;
    bool health_check = true;
    
    // USB defaults (will be overridden by module config)
    int usb_timeout_ms = 100;
    int usb_discovery_interval_ms = 1000;
    bool usb_auto_detach_kernel = true;
    
    // Performance
    int max_clients = 10;
    size_t max_queue_size = 1000;
    int polling_interval_us = 1000;
    
    // Heartbeat
    bool heartbeat_enabled = true;
    int heartbeat_interval_ms = 5000;
    int heartbeat_timeout_ms = 15000;

    // Security
    bool security_require_group = true;
    
    /**
     * Get config value as string
     */
    std::string get_string(std::string_view key, std::string_view default_val = "") const;
    
    /**
     * Get config value as int
     */
    int get_int(std::string_view key, int default_val = 0) const;
    
    /**
     * Get config value as bool
     */
    bool get_bool(std::string_view key, bool default_val = false) const;

private:
    std::unordered_map<std::string, std::string> values_;
    
    std::string trim(std::string_view str) const;
};

/**
 * Configuration load error
 */
inline Error make_config_load_error(const std::string& path, const std::string& reason) {
    return Error::from_code(ErrorCodes::CONFIG_LOAD_FAILED,
                            "Failed to load config from " + path + ": " + reason,
                            "config_manager");
}

/**
 * Configuration parse error
 */
inline Error make_config_parse_error(const std::string& path, const std::string& reason) {
    return Error::from_code(ErrorCodes::CONFIG_PARSE_ERROR,
                            "Failed to parse config " + path + ": " + reason,
                            "config_manager");
}

} // namespace NoteDaemon

#endif // CONFIG_MANAGER_H
