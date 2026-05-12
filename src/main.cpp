// notedaemon/main.cpp
// Refactored to use modular architecture

#include <grp.h>
#include <errno.h>  
#include <signal.h> 
#include <libusb-1.0/libusb.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <cstring>
#include <atomic>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <optional>

#include "utils.h"
#include "device_session.h"
#include "note_messaging.h"
#include "event_bytes.h"
#include "async_logger.h"

// Module framework includes
#include "module_framework/error.h"
#include "module_framework/imodule.h"
#include "module_framework/module_loader.h"
#include "module_framework/module_registry.h"
#include "module_framework/handler_registry.h"
#include "module_framework/config_manager.h"
#include "module_framework/error_collector.h"

using namespace NoteDaemon;
using Json = nlohmann::json;

// Core API version - modules check this for compatibility
constexpr std::string_view CORE_API_VERSION = "1.0.0";

// Global state for signal handling
std::atomic<bool> g_running{true};

void signal_handler(int signum) {
    AsyncLogger::Logger::log_info("[Signal Handler] Signal " + std::to_string(signum) + " received, setting g_running=false", "NoteDaemon");
    (void)signum;
    g_running = false;
    AsyncLogger::Logger::log_info("[Signal Handler] g_running set to false", "NoteDaemon");
}

// Forward declarations from existing code
class LinuxRequirements;
class DaemonConfig;

/**
 * Simplified main for modular architecture
 * Loads modules and routes messages through them
 */
class NoteDaemonApp {
private:
    // Core framework components
    ModuleLoader module_loader_;
    ModuleRegistry module_registry_;
    ModuleRoutingRegistry routing_registry_;
    ErrorCollector error_collector_;
    CoreConfig config_;
    ConfigManager config_manager_;
    
    libusb_context* usb_ctx_ = nullptr;
    int server_socket_ = -1;

public:
    int run() {
        // RAII cleanup
        struct CleanupGuard {
            NoteDaemonApp* daemon;
            CleanupGuard(NoteDaemonApp* d) : daemon(d) {}
            ~CleanupGuard() { daemon->cleanup(); }
        } guard(this);
        
        signal(SIGTERM, signal_handler);
        signal(SIGINT, signal_handler);

        // Setup logging
        int log_options = LOG_PID;
        if (config_.log_to_stderr) {
            log_options |= LOG_PERROR;
        }
        openlog("notedaemon", log_options, LOG_DAEMON);
        setlogmask(LOG_UPTO(config_.log_level));
        
        // Start async logger (runs on its own thread)
        AsyncLogger::Logger::start();
        
        AsyncLogger::Logger::log_info("NoteDaemon starting (modular architecture) v" + std::string(CORE_API_VERSION.data()), "NoteDaemon");

        // Load configuration
        load_configuration();

        // Validate system requirements
        if (!validate_requirements()) {
            syslog(LOG_ERR, "System requirements not met, cannot start");
            return 1;
        }

        // Initialize libusb
        if (!init_libusb()) {
            return 1;
        }

        // Setup socket
        if (!setup_socket()) {
            return 1;
        }

        // Load and initialize modules
        AsyncLogger::Logger::log_info("About to call load_modules()", "NoteDaemon");
        try {
            load_modules();
            AsyncLogger::Logger::log_info("load_modules() returned, continuing...", "NoteDaemon");
        } catch (const std::exception& e) {
            AsyncLogger::Logger::log_error("load_modules() threw exception: " + std::string(e.what()), "NoteDaemon");
            throw;
        } catch (...) {
            AsyncLogger::Logger::log_error("load_modules() threw unknown exception", "NoteDaemon");
            throw;
        }
        
        // Register GET_MODULES handler
        if (auto* core_module = module_registry_.get("notedaemon")) {
            core_module->get_handler_registry()
                .register_handler(NoteMessaging::ProtocolMessages::GET_MODULES,
                                 [this](const NoteBytes::Object& /*msg*/) {
                                     // Get client_fd from somewhere - for now just log
                                     syslog(LOG_DEBUG, "GET_MODULES received");
                                 });
        } else {
            syslog(LOG_DEBUG, "Core module 'notedaemon' not registered; skipping GET_MODULES handler registration");
        }

        syslog(LOG_INFO, "Daemon ready on %s", config_.socket_path.c_str());

        // Fork process monitor if needed
        AsyncLogger::Logger::log_info("About to call fork_process_monitor()", "NoteDaemon");
        fork_process_monitor();
        AsyncLogger::Logger::log_info("fork_process_monitor() completed", "NoteDaemon");

        // Main event loop
        AsyncLogger::Logger::log_info("About to call main_loop()", "NoteDaemon");
        main_loop();
        AsyncLogger::Logger::log_info("main_loop() returned", "NoteDaemon");

        AsyncLogger::Logger::log_info("NoteDaemon main_loop returned, about to stop...", "NoteDaemon");

        syslog(LOG_INFO, "NoteDaemon stopped");
        closelog();
        return 0;
    }

private:
    void load_configuration() {
        // Load core config
        std::string config_path = get_config_path();
        if (!config_path.empty()) {
            config_.load_from_file(config_path);
        }
        
        // Log config manually since CoreConfig doesn't have log_config
        syslog(LOG_INFO, "=== Daemon Configuration ===");
        syslog(LOG_INFO, "Socket: %s (group=%s, perms=0%o)", 
               config_.socket_path.c_str(), config_.socket_group.c_str(), 
               (int)config_.socket_permissions);
        syslog(LOG_INFO, "Module directory: %s", config_.module_directory.c_str());
        syslog(LOG_INFO, "Module strict_load: %d", config_.strict_load);
        syslog(LOG_INFO, "Module health_check: %d", config_.health_check);
        syslog(LOG_INFO, "===========================");
    }
    
    bool validate_requirements() {
        // Check libusb
        libusb_context* ctx = nullptr;
        int rc = libusb_init(&ctx);
        if (rc < 0) {
            syslog(LOG_ERR, "libusb init failed: %s", libusb_error_name(rc));
            return false;
        }
        
        // Check USB access
        bool has_access = false;
        libusb_device** list = nullptr;
        ssize_t cnt = libusb_get_device_list(ctx, &list);
        if (cnt >= 0) {
            for (ssize_t i = 0; i < cnt; i++) {
                libusb_device_handle* handle = nullptr;
                if (libusb_open(list[i], &handle) == 0) {
                    has_access = true;
                    libusb_close(handle);
                }
            }
            libusb_free_device_list(list, 1);
        }
        
        libusb_exit(ctx);
        
        if (!has_access) {
            syslog(LOG_WARNING, "No accessible USB devices found");
        }
        
        // Check socket directory
        if (mkdir(config_.socket_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            syslog(LOG_ERR, "Cannot create socket directory: %s", strerror(errno));
            return false;
        }
        
        if (access(config_.socket_dir.c_str(), W_OK) < 0) {
            syslog(LOG_ERR, "Socket directory not writable");
            return false;
        }
        
        return true;
    }
    
    bool init_libusb() {
        int result = libusb_init(&usb_ctx_);
        if (result < 0) {
            syslog(LOG_ERR, "Failed to initialize libusb: %s", 
                   libusb_error_name(result));
            return false;
        }
        
        // Register hotplug callbacks (keep existing functionality)
        DeviceSession::register_hotplug_callbacks(usb_ctx_);
        
        return true;
    }
    
    bool setup_socket() {
        // Remove old socket
        unlink(config_.socket_path.c_str());

        // Create socket
        server_socket_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_socket_ < 0) {
            syslog(LOG_ERR, "Failed to create socket: %s", strerror(errno));
            return false;
        }

        // Bind socket
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, config_.socket_path.c_str(), sizeof(addr.sun_path) - 1);

        if (bind(server_socket_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            syslog(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
            safe_close(server_socket_);
            return false;
        }

        // Set permissions
        if (chmod(config_.socket_path.c_str(), config_.socket_permissions) < 0) {
            syslog(LOG_WARNING, "Failed to set socket permissions: %s", strerror(errno));
        }

        // Set group
        struct group* grp = getgrnam(config_.socket_group.c_str());
        if (grp) {
            if (chown(config_.socket_path.c_str(), -1, grp->gr_gid) < 0) {
                syslog(LOG_WARNING, "Failed to set socket group: %s", strerror(errno));
            }
        }

        // Listen
        if (listen(server_socket_, 5) < 0) {
            syslog(LOG_ERR, "Failed to listen on socket: %s", strerror(errno));
            safe_close(server_socket_);
            return false;
        }

        return true;
    }
    
    void load_modules() {
        syslog(LOG_INFO, "Loading modules from: %s", config_.module_directory.c_str());
        
        auto modules = module_loader_.load_all(config_.module_directory);
        
        if (modules.empty()) {
            syslog(LOG_WARNING, "No modules loaded - running in legacy mode");
            return;
        }
        
        // Initialize each module
        for (IModule* module : modules) {
            std::string name(module->name());
            syslog(LOG_INFO, "Initializing module: %s", name.c_str());
            
            // Load module config
            std::string config_path = config_.module_directory + "/" + name + "/config.json";
            auto config_result = config_manager_.load_module_config(name, config_path);
            
            if (auto* err = std::get_if<Error>(&config_result)) {
                syslog(LOG_ERR, "Failed to load config for %s: %s", 
                       name.c_str(), err->message().data());
                if (config_.strict_load) {
                    syslog(LOG_ERR, "strict_load=true, failing startup");
                    continue;
                }
            }
            
            // Get config for init
            const auto* config_json = config_manager_.get_config(name);
            Json init_config = config_json ? *config_json : Json::object();
            
            // Initialize module
            Error init_err = module->init(init_config);
            if (init_err.failed()) {
                syslog(LOG_ERR, "Failed to init module %s: %s",
                       name.c_str(), init_err.message().data());
                if (config_.strict_load) {
                    continue;
                }
            }
            
            // Health check
            if (config_.health_check) {
                Error health_err = module->check_health(std::string(CORE_API_VERSION));
                if (health_err.failed()) {
                    syslog(LOG_ERR, "Module %s health check failed: %s",
                           name.c_str(), health_err.message().data());
                    if (config_.strict_load) {
                        continue;
                    }
                }
            }
            
            // Register module
            Error reg_err = module_registry_.register_module(module);
            if (reg_err.failed()) {
                syslog(LOG_ERR, "Failed to register module %s: %s",
                       name.c_str(), reg_err.message().data());
                continue;
            }
            
            // Register message types for routing
            auto types = module->get_handled_message_types();
            routing_registry_.register_module(name, types);
            syslog(LOG_INFO, "Module %s handles: %zu message types", 
                   name.c_str(), types.size());
            
            // Register with error collector
            error_collector_.register_module(module);
            
            // Start module
            Error start_err = module->start();
            if (start_err.failed()) {
                syslog(LOG_ERR, "Failed to start module %s: %s",
                       name.c_str(), start_err.message().data());
            } else {
                syslog(LOG_INFO, "Module %s started successfully", name.c_str());
            }
        }
        
        AsyncLogger::Logger::log_info("[Main] About to log routing table", "NoteDaemon");
        syslog(LOG_INFO, "[Main] Logging routing table - about to call get_all_routes()");
        auto routes = routing_registry_.get_all_routes();
        syslog(LOG_INFO, "[Main] get_all_routes() returned, about to log routing table size");
        AsyncLogger::Logger::log_info("[Main] Routing table has " + std::to_string(routes.size()) + " entries", "NoteDaemon");
        syslog(LOG_INFO, "Routing table has %zu entries", routes.size());
    }
    
    void fork_process_monitor() {
        // Fork a monitor process
        AsyncLogger::Logger::log_info("[Process Monitor] About to fork process monitor", "NoteDaemon");
        pid_t monitor_pid = fork();
        if (monitor_pid < 0) {
            AsyncLogger::Logger::log_warning("[Process Monitor] Failed to fork: " + std::string(strerror(errno)), "NoteDaemon");
        } else if (monitor_pid == 0) {
            // Child - exec monitor
            char pid_str[32];
            snprintf(pid_str, sizeof(pid_str), "%d", getpid());
            execl("/usr/local/bin/process_monitor", "process_monitor", pid_str, nullptr);
            AsyncLogger::Logger::log_error("[Process Monitor] Failed to exec process_monitor: " + std::string(strerror(errno)), "NoteDaemon");
            _exit(1);
        } else {
            AsyncLogger::Logger::log_info("[Process Monitor] Process monitor started (PID " + std::to_string(monitor_pid) + ")", "NoteDaemon");
        }
    }
    
    void main_loop() {
        AsyncLogger::Logger::log_info("Main loop started, waiting for connections...", "NoteDaemon");
        while (g_running) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(server_socket_, &read_fds);

            struct timeval timeout = {1, 0};
            int activity = select(server_socket_ + 1, &read_fds, nullptr, nullptr, &timeout);

            if (activity < 0 && errno != EINTR) {
                AsyncLogger::Logger::log_error("Select error: " + std::string(strerror(errno)), "NoteDaemon");
                break;
            }

            if (activity > 0 && FD_ISSET(server_socket_, &read_fds)) {
                handle_client();
            }
        }
        AsyncLogger::Logger::log_info("Main loop exited... g_running=" + std::string(g_running ? "true" : "false"), "NoteDaemon");
    }
    
    void handle_client() {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(server_socket_, 
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
            syslog(LOG_WARNING, "Failed to get peer credentials: %s", strerror(errno));
            safe_close(client_fd);
            return;
        }
        
        syslog(LOG_INFO, "Client connected: uid=%d, gid=%d, pid=%d", 
               creds.uid, creds.gid, creds.pid);
        
        // Check group access
        if (!check_group_access(creds.uid)) {
            syslog(LOG_WARNING, "Client uid=%d denied: not in allowed groups", creds.uid);
            safe_close(client_fd);
            return;
        }
        
        // Route based on whether modules are loaded
        if (module_registry_.size() > 0) {
            // Use modular routing
            // IMPORTANT: Don't close client_fd here!
            // The module (e.g., NoteUSB) takes ownership of the socket and will
            // close it when the session ends (when the background thread exits).
            syslog(LOG_INFO, "[NoteDaemon] Using modular routing for client pid=%d", creds.pid);
            handle_client_modular(client_fd, creds.pid);
            // Note: The module owns the socket lifecycle now - don't close it here
            syslog(LOG_INFO, "Client session ended: pid=%d (socket transferred to module)", creds.pid);
        } else {
            // Fall back to legacy DeviceSession
            // For legacy mode, we own the socket lifecycle
            syslog(LOG_INFO, "[NoteDaemon] Using legacy DeviceSession for client pid=%d", creds.pid);
            DeviceSession session(usb_ctx_, client_fd, creds.pid);
            session.readSocket();
            
            syslog(LOG_INFO, "Client session ended: pid=%d", creds.pid);
            safe_close(client_fd);
        }
    }
    
    void handle_client_modular(int client_fd, pid_t client_pid) {
        syslog(LOG_INFO, "[NoteDaemon] Client connected: pid=%d", client_pid);
        
        syslog(LOG_DEBUG, "Using modular routing for client pid=%d", client_pid);
        
        // Check for GET_MODULES command (daemon-level, before module handling)
        NoteBytes::Reader reader(client_fd, false);
        auto cmd = reader.read_object();
        auto* cmd_val = cmd.get(NoteMessaging::Keys::CMD);
        if (cmd_val) {
            if (*cmd_val == NoteMessaging::ProtocolMessages::GET_MODULES) {
                syslog(LOG_INFO, "[NoteDaemon] Handling GET_MODULES for client pid=%d", client_pid);
                handle_get_modules(client_fd);
                return;
            }
        }
        
        // Route to module
        auto* note_usb_module = module_registry_.get("note_usb");
        if (note_usb_module) {
            // Call module's handle_client to create session
            Error err = note_usb_module->handle_client(client_fd, client_pid);
            if (err.failed()) {
                syslog(LOG_ERR, "NoteUSB: failed to handle client pid=%d: %s",
                       client_pid, err.message().data());
                safe_close(client_fd);
            }
        } else {
            syslog(LOG_WARNING, "No module handles client pid=%d", client_pid);
            safe_close(client_fd);
        }
        
        // =============================================================================
        // ORIGINAL MESSAGE LOOP CODE (commented out for testing)
        // =============================================================================
        // // Read messages and route to modules
        // for (;;) {
        //     try {
        //         auto routed = InputPacket::receive_message(client_fd);
        //
        //         if (!routed.isValid()) {
        //             syslog(LOG_ERR, "[NoteDaemon] Invalid message received");
        //             break;
        //         }
        //
        //         NoteBytes::Object message = NoteBytes::Object::deserialize(
        //             routed.message.data().data(),
        //             routed.message.data().size());
        //
        //         // Log received message
        //         auto* event_val = message.get(NoteMessaging::Keys::EVENT);
        //         auto* cmd_val = message.get(NoteMessaging::Keys::CMD);
        //
        //         std::string event_type = event_val ? event_val->as_string() : "";
        //         std::string cmd_type = cmd_val ? cmd_val->as_string() : "";
        //
        //         syslog(LOG_INFO, "[NoteDaemon] <<< Received: event=%s, cmd=%s",
        //                event_type.c_str(), cmd_type.c_str());
        //
        //         // Check for GET_MODULES request
        //         if (event_type == NoteMessaging::ProtocolMessages::GET_MODULES.as_string() ||
        //             cmd_type == NoteMessaging::ProtocolMessages::GET_MODULES.as_string()) {
        //             syslog(LOG_INFO, "[NoteDaemon] Handling GET_MODULES");
        //             handle_get_modules(client_fd);
        //             break;
        //         }
        //
        //         // Log device_id if present
        //         auto* device_id_val = message.get(NoteMessaging::Keys::DEVICE_ID);
        //         if (device_id_val) {
        //             syslog(LOG_DEBUG, "[NoteDaemon] <<< device_id=%s",
        //                    device_id_val->as_string().c_str());
        //         }
        //
        //         // Route to appropriate module
        //         std::string module_id = routed.module_id.as_string();
        //         if (!module_id.empty()) {
        //             // Route to specific module
        //             auto* module = module_registry_.get(module_id);
        //             if (module) {
        //                 // Dispatch to module's handler registry
        //                 Error err = module->get_handler_registry().dispatch(message);
        //                 if (err.failed()) {
        //                     syslog(LOG_WARNING, "Module %s failed to handle message: %s",
        //                            module_id.c_str(), err.message().data());
        //                 }
        //             } else {
        //                 syslog(LOG_WARNING, "Module %s not found for routing", module_id.c_str());
        //             }
        //         } else {
        //             // No module_id specified, try to route by message type
        //             // This is for legacy compatibility
        //             syslog(LOG_DEBUG, "No module_id in message, trying legacy routing");
        //
        //             // Try to find a module that handles this message type
        //             std::string message_type = event_type.empty() ? cmd_type : event_type;
        //             std::string module_id = routing_registry_.lookup_module(message_type);
        //
        //             if (!module_id.empty()) {
        //                 auto* module = module_registry_.get(module_id);
        //                 if (module) {
        //                     Error err = module->get_handler_registry().dispatch(message);
        //                     if (err.failed()) {
        //                         syslog(LOG_WARNING, "Module %s failed to handle message: %s",
        //                                module_id.c_str(), err.message().data());
        //                     }
        //                 }
        //             } else {
        //                 syslog(LOG_WARNING, "No module handles message type: %s",
        //                        message_type.c_str());
        //             }
        //         }
        //
        //     } catch (const std::exception& e) {
        //         syslog(LOG_ERR, "Error in message loop: %s", e.what());
        //         break;
        //     }
        // }
        // =============================================================================
        // END OF COMMENTED CODE
        // =============================================================================

        // Note: Message handling is done by the module itself
        // The module's handle_client() sets up the message loop internally
        // 
        // IMPORTANT: Do NOT call cleanup_client here!
        // The session should remain alive while the client is connected.
        // The module will handle cleanup when the client's socket is closed
        // (i.e., when the session's read loop exits).
        syslog(LOG_INFO, "[NoteDaemon] Module handling complete - leaving session alive");
    }
    
    void handle_get_modules(int client_fd) {
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT, NoteMessaging::ProtocolMessages::MODULE_LIST);
        
        NoteBytes::Array modules_array;
        
        // Get all registered modules
        auto modules = module_registry_.get_all_modules();
        for (const auto& module : modules) {
            NoteBytes::Object module_info;
            module_info.add(NoteMessaging::Keys::NAME, module->name());
            module_info.add(NoteMessaging::Keys::VERSION, module->version());
            module_info.add(NoteMessaging::Keys::DESCRIPTION, module->description());
            module_info.add(NoteMessaging::Keys::CAPABILITIES, module->capabilities());
            
            // Get handled message types
            std::vector<std::string> handlers = module->get_handled_message_types();
            NoteBytes::Array handlers_array;
            for (const auto& handler : handlers) {
                handlers_array.add(NoteBytes::Value(handler));
            }
            module_info.add(NoteMessaging::Keys::HANDLERS, handlers_array.as_value());
            
            modules_array.add(module_info.as_value());
        }
        
        response.add(NoteMessaging::ProtocolMessages::MODULE_LIST, modules_array.as_value());
        
        // Send response
        NoteBytes::Writer writer(client_fd, false);
        writer.write(response);
        writer.flush();
        
        syslog(LOG_INFO, "Sent module list: %zu modules", modules.size());
    }
    
    bool check_group_access(uid_t uid) {
        if (uid == 0) {
            return true;  // Root bypass
        }
        
        struct passwd* pw = getpwuid(uid);
        if (!pw) {
            return false;
        }
        
        // Check socket group
        struct group* sock_grp = getgrnam(config_.socket_group.c_str());
        if (sock_grp) {
            // Check primary group
            if (pw->pw_gid == sock_grp->gr_gid) {
                return true;
            }
            
            // Check member list
            for (int i = 0; sock_grp->gr_mem[i] != nullptr; i++) {
                if (strcmp(sock_grp->gr_mem[i], pw->pw_name) == 0) {
                    return true;
                }
            }
        }
        
        return false;
    }

    void cleanup() {
        AsyncLogger::Logger::log_info("cleanup() called - shutting down modules...", "NoteDaemon");
        
        // Clear non-owning registries before unloading module shared libraries.
        error_collector_.clear();
        module_registry_.clear();
        
        // Shutdown all modules
        module_loader_.unload_all();
        
        // Legacy cleanup
        DeviceSession::shutdown_all_sessions();
        
        if (server_socket_ >= 0) {
            safe_close(server_socket_);
            unlink(config_.socket_path.c_str());
        }
        
        if (usb_ctx_) {
            libusb_exit(usb_ctx_);
            usb_ctx_ = nullptr;
        }
        
        // Stop async logger
        AsyncLogger::Logger::stop();
    }
    
    // ===== MODULE REGISTRY HELPERS =====
    
    std::vector<NoteDaemon::IModule*> get_all_modules() {
        return module_registry_.get_all_modules();
    }
    
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
};

// Include LinuxRequirements from the original code
// For now, we'll include it inline or from utils
// This is a minimal implementation for the refactor

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
        fprintf(stderr, "NetNotes IO Daemon (Modular)\n");
        fprintf(stderr, "Usage: %s [OPTIONS]\n\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -h, --help     Show this help message\n");
        fprintf(stderr, "  -c, --check    Check system requirements and exit\n\n");
        fprintf(stderr, "Configuration:\n");
        fprintf(stderr, "  Config file: ~/.netnotes/config (key=value)\n");
        fprintf(stderr, "  Module directory: /etc/netnotes/modules\n");
        fprintf(stderr, "  Socket: /run/netnotes/notedaemon.sock\n\n");
        return 0;
    }
    
    // Check-only mode
    if (check_only) {
        openlog("notedaemon-check", LOG_PERROR | LOG_PID, LOG_DAEMON);
        
        CoreConfig config;
        std::string config_path;
        const char* home = getenv("HOME");
        if (home) {
            config_path = std::string(home) + "/.netnotes/config";
        }
        if (!config_path.empty()) {
            config.load_from_file(config_path);
        }
        
        // Simple check - just check if we can init libusb
        libusb_context* ctx = nullptr;
        bool passed = (libusb_init(&ctx) == 0);
        if (passed) {
            libusb_exit(ctx);
        }
        
        closelog();
        return passed ? 0 : 1;
    }
    
    // Run daemon
    NoteDaemonApp daemon;
    return daemon.run();
}
