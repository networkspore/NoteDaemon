// notedaemon/main.cpp
// NoteDaemon – two-socket modular architecture.
//
// Connection model:
//   Every accept()ed fd is read for its first message to classify the connection:
//
//   • CMD == DEVICE_HANDSHAKE  →  device socket
//       The message carries {session_id, device_id}.  The core looks up which
//       module owns device_id via DeviceOwnershipRegistry and hands the fd to
//       module->handle_client().  The module owns the fd from that point on.
//
//   • anything else            →  management socket
//       The fd stays in the core.  A per-connection background thread runs a
//       read loop calling handle_management_message() for each message, routing
//       to the right module (or handling directly for GET_MODULES / handshake).

#include <grp.h>
#include <errno.h>
#include <signal.h>
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
#include <thread>
#include <vector>
#include <optional>

#include <libusb-1.0/libusb.h>

#include "utils.h"
#include "note_messaging.h"
#include "async_logger.h"

// Module framework
#include "module_framework/error.h"
#include "module_framework/imodule.h"
#include "module_framework/module_loader.h"
#include "module_framework/module_registry.h"
#include "module_framework/handler_registry.h"
#include "module_framework/device_ownership_registry.h"
#include "module_framework/config_manager.h"
#include "module_framework/error_collector.h"

// NoteBytes I/O
#include "notebytes.h"
#include "notebytes_writer.h"

using namespace NoteDaemon;
using Json = nlohmann::json;

constexpr std::string_view CORE_API_VERSION = "1.0.0";

std::atomic<bool> g_running{true};

void signal_handler(int signum) {
    (void)signum;
    g_running = false;
}

// ─────────────────────────────────────────────────────────────────────────────
// NoteDaemonApp
// ─────────────────────────────────────────────────────────────────────────────

class NoteDaemonApp {
public:
    int run() {
        struct CleanupGuard {
            NoteDaemonApp* d;
            CleanupGuard(NoteDaemonApp* d_) : d(d_) {}
            ~CleanupGuard() { d->cleanup(); }
        } guard(this);

        signal(SIGTERM, signal_handler);
        signal(SIGINT,  signal_handler);
        signal(SIGPIPE, SIG_IGN);  // avoid crashes on broken management sockets

        openlog("notedaemon",
                LOG_PID | (config_.log_to_stderr ? LOG_PERROR : 0),
                LOG_DAEMON);
        setlogmask(LOG_UPTO(config_.log_level));

        AsyncLogger::Logger::start();
        AsyncLogger::Logger::log_info(
            "NoteDaemon starting (two-socket architecture) v" +
            std::string(CORE_API_VERSION), "NoteDaemon");

        load_configuration();

        if (!validate_requirements()) {
            syslog(LOG_ERR, "System requirements not met");
            return 1;
        }
        if (!init_libusb())  return 1;
        if (!setup_socket()) return 1;

        load_modules();

        syslog(LOG_INFO, "Daemon ready on %s", config_.socket_path.c_str());

        fork_process_monitor();
        main_loop();

        syslog(LOG_INFO, "NoteDaemon stopped");
        closelog();
        return 0;
    }

private:
    // ── Members ───────────────────────────────────────────────────────────────

    ModuleLoader            module_loader_;
    ModuleRegistry          module_registry_;
    ModuleRoutingRegistry   routing_registry_;
    DeviceOwnershipRegistry ownership_registry_;
    ErrorCollector          error_collector_;
    CoreConfig              config_;
    ConfigManager           config_manager_;

    libusb_context* usb_ctx_      = nullptr;
    int             server_socket_ = -1;

    // ── Configuration & setup ─────────────────────────────────────────────────

    void load_configuration() {
        std::string path = get_config_path();
        if (!path.empty()) config_.load_from_file(path);

        syslog(LOG_INFO, "=== Daemon Configuration ===");
        syslog(LOG_INFO, "Socket: %s (group=%s, perms=0%o)",
               config_.socket_path.c_str(),
               config_.socket_group.c_str(),
               (int)config_.socket_permissions);
        syslog(LOG_INFO, "Module directory: %s", config_.module_directory.c_str());
        syslog(LOG_INFO, "strict_load=%d  health_check=%d",
               config_.strict_load, config_.health_check);
        syslog(LOG_INFO, "============================");
    }

    bool validate_requirements() {
        // Quick libusb probe
        libusb_context* ctx = nullptr;
        if (libusb_init(&ctx) < 0) {
            syslog(LOG_ERR, "libusb probe failed");
            return false;
        }
        libusb_exit(ctx);

        if (mkdir(config_.socket_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            syslog(LOG_ERR, "Cannot create socket dir: %s", strerror(errno));
            return false;
        }
        if (access(config_.socket_dir.c_str(), W_OK) < 0) {
            syslog(LOG_ERR, "Socket dir not writable");
            return false;
        }
        return true;
    }

    bool init_libusb() {
        int rc = libusb_init(&usb_ctx_);
        if (rc < 0) {
            syslog(LOG_ERR, "libusb_init: %s", libusb_error_name(rc));
            return false;
        }
        return true;
    }

    bool setup_socket() {
        unlink(config_.socket_path.c_str());

        server_socket_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_socket_ < 0) {
            syslog(LOG_ERR, "socket(): %s", strerror(errno));
            return false;
        }

        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, config_.socket_path.c_str(),
                sizeof(addr.sun_path) - 1);

        if (bind(server_socket_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            syslog(LOG_ERR, "bind(): %s", strerror(errno));
            safe_close(server_socket_);
            return false;
        }

        chmod(config_.socket_path.c_str(), config_.socket_permissions);

        struct group* grp = getgrnam(config_.socket_group.c_str());
        if (grp) chown(config_.socket_path.c_str(), -1, grp->gr_gid);

        if (listen(server_socket_, 32) < 0) {
            syslog(LOG_ERR, "listen(): %s", strerror(errno));
            safe_close(server_socket_);
            return false;
        }
        return true;
    }

    // ── Module loading ────────────────────────────────────────────────────────

    void load_modules() {
        syslog(LOG_INFO, "Loading modules from: %s", config_.module_directory.c_str());

        auto modules = module_loader_.load_all(config_.module_directory);
        if (modules.empty()) {
            syslog(LOG_WARNING, "No modules loaded");
            return;
        }

        for (IModule* module : modules) {
            std::string name(module->name());
            syslog(LOG_INFO, "Initialising module: %s", name.c_str());

            // Load config
            std::string cfg_path = config_.module_directory + "/" + name + "/config.json";
            auto cfg_result = config_manager_.load_module_config(name, cfg_path);
            if (auto* err = std::get_if<Error>(&cfg_result)) {
                syslog(LOG_ERR, "Config load failed for %s: %s",
                       name.c_str(), err->message().data());
                if (config_.strict_load) continue;
            }

            const auto* cfg_json = config_manager_.get_config(name);
            Json init_cfg = cfg_json ? *cfg_json : Json::object();

            // init()
            if (auto err = module->init(init_cfg); err.failed()) {
                syslog(LOG_ERR, "init() failed for %s: %s",
                       name.c_str(), err.message().data());
                if (config_.strict_load) continue;
            }

            // Inject ownership registry immediately after successful init
            module->set_ownership_registry(&ownership_registry_);

            // Health check
            if (config_.health_check) {
                if (auto err = module->check_health(std::string(CORE_API_VERSION));
                    err.failed()) {
                    syslog(LOG_ERR, "Health check failed for %s: %s",
                           name.c_str(), err.message().data());
                    if (config_.strict_load) continue;
                }
            }

            // Register
            if (auto err = module_registry_.register_module(module); err.failed()) {
                syslog(LOG_ERR, "Registration failed for %s: %s",
                       name.c_str(), err.message().data());
                continue;
            }

            // Build routing table
            auto types = module->get_handled_message_types();
            routing_registry_.register_module(name, types);
            syslog(LOG_INFO, "Module %s registered; handles %zu message type(s)",
                   name.c_str(), types.size());

            error_collector_.register_module(module);

            // Start
            if (auto err = module->start(); err.failed()) {
                syslog(LOG_ERR, "start() failed for %s: %s",
                       name.c_str(), err.message().data());
            } else {
                syslog(LOG_INFO, "Module %s started", name.c_str());
            }
        }

        auto routes = routing_registry_.get_all_routes();
        syslog(LOG_INFO, "Routing table: %zu entries", routes.size());
    }

    // ── Main accept loop ──────────────────────────────────────────────────────

    void fork_process_monitor() {
        pid_t pid = fork();
        if (pid == 0) {
            char ps[32];
            snprintf(ps, sizeof(ps), "%d", getppid());
            execl("/usr/local/bin/process_monitor", "process_monitor", ps, nullptr);
            _exit(1);
        } else if (pid > 0) {
            syslog(LOG_INFO, "Process monitor started (pid=%d)", pid);
        }
    }

    void main_loop() {
        AsyncLogger::Logger::log_info("Main loop started", "NoteDaemon");

        while (g_running) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(server_socket_, &rfds);

            struct timeval tv = {1, 0};
            int rc = select(server_socket_ + 1, &rfds, nullptr, nullptr, &tv);

            if (rc < 0 && errno != EINTR) {
                AsyncLogger::Logger::log_error(
                    "select() error: " + std::string(strerror(errno)), "NoteDaemon");
                break;
            }

            if (rc > 0 && FD_ISSET(server_socket_, &rfds)) {
                accept_connection();
            }
        }

        AsyncLogger::Logger::log_info("Main loop exited", "NoteDaemon");
    }

    // ── Connection dispatch ───────────────────────────────────────────────────

    /**
     * Accept one connection and classify it as management or device socket.
     * Spawns a background thread for management connections so main_loop
     * is never blocked.
     */
    void accept_connection() {
        struct sockaddr_un addr{};
        socklen_t len = sizeof(addr);

        int client_fd = accept(server_socket_, (struct sockaddr*)&addr, &len);
        if (client_fd < 0) {
            syslog(LOG_WARNING, "accept(): %s", strerror(errno));
            return;
        }

        // Peer credentials
        struct ucred creds{};
        socklen_t clen = sizeof(creds);
        if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &creds, &clen) < 0) {
            syslog(LOG_WARNING, "SO_PEERCRED: %s", strerror(errno));
            safe_close(client_fd);
            return;
        }

        if (!check_group_access(creds.uid)) {
            syslog(LOG_WARNING, "Access denied: uid=%d", creds.uid);
            safe_close(client_fd);
            return;
        }

        syslog(LOG_INFO, "Connection from uid=%d pid=%d fd=%d",
               creds.uid, creds.pid, client_fd);

        // Read the first message to classify the connection.
        // This is done in a worker thread so accept_connection() returns
        // immediately.  Timeout/error handling is inside the thread.
        std::thread([this, client_fd, pid = creds.pid]() mutable {
            dispatch_new_connection(client_fd, pid);
        }).detach();
    }

    /**
     * Read the first message from a fresh connection and route accordingly.
     * Runs in a worker thread.
     */
    void dispatch_new_connection(int client_fd, pid_t client_pid) {
        NoteBytes::Object first_msg;
        try {
            NoteBytes::Reader reader(client_fd, /*owns_fd=*/false);
            first_msg = reader.read_object();
        } catch (const std::exception& e) {
            syslog(LOG_WARNING, "Failed to read first message from pid=%d: %s",
                   client_pid, e.what());
            safe_close(client_fd);
            return;
        }

        auto* cmd_val = first_msg.get(NoteMessaging::Keys::CMD);

        // ── DEVICE SOCKET ──────────────────────────────────────────────────────
        if (cmd_val && *cmd_val == NoteMessaging::ProtocolMessages::DEVICE_HANDSHAKE) {
            handle_device_socket(client_fd, client_pid, first_msg);
            return;
        }

        // ── MANAGEMENT SOCKET ─────────────────────────────────────────────────
        // Process the already-read first message, then loop.
        handle_management_message(client_fd, first_msg);
        run_management_loop(client_fd, client_pid);
    }

    // ── Device socket path ────────────────────────────────────────────────────

    /**
     * Route a device socket to its owning module.
     * The module takes full ownership of client_fd.
     */
    void handle_device_socket(int client_fd, pid_t client_pid,
                              const NoteBytes::Object& handshake) {
        auto* device_id_val = handshake.get(NoteMessaging::Keys::DEVICE_ID);
        if (!device_id_val) {
            syslog(LOG_WARNING, "DEVICE_HANDSHAKE missing device_id (pid=%d)", client_pid);
            safe_close(client_fd);
            return;
        }

        std::string device_id = device_id_val->as_string();
        std::string module_id = ownership_registry_.lookup_module(device_id);

        if (module_id.empty()) {
            syslog(LOG_WARNING,
                   "No module owns device=%s (pid=%d) – client sent "
                   "DEVICE_HANDSHAKE before CLAIM_ITEM was processed",
                   device_id.c_str(), client_pid);
            safe_close(client_fd);
            return;
        }

        IModule* module = module_registry_.get(module_id);
        if (!module) {
            syslog(LOG_ERR, "Module %s not found for device %s",
                   module_id.c_str(), device_id.c_str());
            safe_close(client_fd);
            return;
        }

        syslog(LOG_INFO, "Device socket: device=%s → module=%s (pid=%d)",
               device_id.c_str(), module_id.c_str(), client_pid);

        // Module owns client_fd entirely from here
        Error err = module->handle_client(client_fd, client_pid);
        if (err.failed()) {
            syslog(LOG_ERR, "handle_client() failed for module=%s device=%s: %s",
                   module_id.c_str(), device_id.c_str(), err.message().data());
            safe_close(client_fd);
        }
    }

    // ── Management socket path ────────────────────────────────────────────────

    /**
     * Persistent management read loop for one client connection.
     * Exits when the client disconnects or an error occurs.
     */
    void run_management_loop(int client_fd, pid_t client_pid) {
        NoteBytes::Reader reader(client_fd, /*owns_fd=*/false);

        for (;;) {
            NoteBytes::Object msg;
            try {
                msg = reader.read_object();
            } catch (const std::exception& e) {
                syslog(LOG_INFO, "Management socket closed (pid=%d): %s",
                       client_pid, e.what());
                break;
            }
            handle_management_message(client_fd, msg);
        }

        safe_close(client_fd);
    }

    /**
     * Dispatch one management-socket message.
     *
     * Core handles:  HELLO handshake, GET_MODULES
     * Module handles: CLAIM_ITEM, RELEASE_ITEM, REQUEST_DISCOVERY, …
     *   – routed via routing_registry_ → module->handle_management_message()
     */
    void handle_management_message(int reply_fd, const NoteBytes::Object& msg) {
        // Prefer CMD field; fall back to EVENT
        const NoteBytes::Value* type_val = msg.get(NoteMessaging::Keys::CMD);
        if (!type_val) type_val = msg.get(NoteMessaging::Keys::EVENT);
        if (!type_val) {
            syslog(LOG_WARNING, "Management message has no CMD or EVENT field");
            return;
        }

        // ── Core-handled messages ────────────────────────────────────────────

        if (*type_val == NoteMessaging::ProtocolMessages::HELLO) {
            handle_hello(reply_fd, msg);
            return;
        }

        if (*type_val == NoteMessaging::ProtocolMessages::GET_MODULES) {
            handle_get_modules(reply_fd);
            return;
        }

        // ── Module-routed messages ───────────────────────────────────────────

        std::string msg_type = type_val->as_string();
        std::string module_id = routing_registry_.lookup_module(msg_type);

        if (module_id.empty()) {
            syslog(LOG_WARNING, "No module handles management message: %s",
                   msg_type.c_str());
            send_error(reply_fd, NoteMessaging::ErrorCodes::HANDLER_NOT_FOUND,
                       "Unknown command: " + msg_type);
            return;
        }

        IModule* module = module_registry_.get(module_id);
        if (!module) {
            syslog(LOG_ERR, "Module %s in routing table but not in registry",
                   module_id.c_str());
            return;
        }

        Error err = module->handle_management_message(msg, reply_fd);
        if (err.failed()) {
            syslog(LOG_WARNING, "Module %s management handler error for %s: %s",
                   module_id.c_str(), msg_type.c_str(), err.message().data());
        }
    }

    // ── Core management handlers ─────────────────────────────────────────────

    void handle_hello(int reply_fd, const NoteBytes::Object& /*msg*/) {
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT,
                     NoteMessaging::ProtocolMessages::ACCEPT);
        response.add(NoteMessaging::Keys::VERSION,
                     NoteBytes::Value(std::string(CORE_API_VERSION)));
        write_to_fd(reply_fd, response);
        syslog(LOG_DEBUG, "Sent ACCEPT (handshake)");
    }

    void handle_get_modules(int reply_fd) {
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT,
                     NoteMessaging::ProtocolMessages::MODULE_LIST);

        NoteBytes::Array arr;
        for (auto* module : module_registry_.get_all_modules()) {
            NoteBytes::Object info;
            info.add(NoteMessaging::Keys::NAME,         module->name());
            info.add(NoteMessaging::Keys::VERSION,      module->version());
            info.add(NoteMessaging::Keys::DESCRIPTION,  module->description());
            info.add(NoteMessaging::Keys::CAPABILITIES, module->capabilities());

            NoteBytes::Array handlers_arr;
            for (const auto& h : module->get_handled_message_types()) {
                handlers_arr.add(NoteBytes::Value(h));
            }
            info.add(NoteMessaging::Keys::HANDLERS, handlers_arr.as_value());
            arr.add(info.as_value());
        }

        response.add(NoteMessaging::ProtocolMessages::MODULE_LIST, arr.as_value());
        write_to_fd(reply_fd, response);

        syslog(LOG_INFO, "Sent module list (%zu modules)",
               module_registry_.size());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Write a NoteBytes::Object to a fd, ignoring EPIPE (client gone). */
    void write_to_fd(int fd, const NoteBytes::Object& obj) {
        try {
            NoteBytes::Writer writer(fd, /*owns_fd=*/false);
            writer.write(obj);
            writer.flush();
        } catch (const std::exception& e) {
            syslog(LOG_DEBUG, "write_to_fd fd=%d: %s", fd, e.what());
        }
    }

    void send_error(int fd, int code, const std::string& message) {
        NoteBytes::Object err_msg;
        err_msg.add(NoteMessaging::Keys::EVENT,
                    NoteMessaging::ProtocolMessages::ERROR);
        err_msg.add(NoteMessaging::Keys::ERROR,      code);
        err_msg.add(NoteMessaging::Keys::MSG,        message);
        write_to_fd(fd, err_msg);
    }

    bool check_group_access(uid_t uid) {
        if (uid == 0) return true;

        struct passwd* pw = getpwuid(uid);
        if (!pw) return false;

        struct group* grp = getgrnam(config_.socket_group.c_str());
        if (!grp) return false;

        if (pw->pw_gid == grp->gr_gid) return true;

        for (int i = 0; grp->gr_mem[i]; ++i) {
            if (strcmp(grp->gr_mem[i], pw->pw_name) == 0) return true;
        }
        return false;
    }

    std::string get_config_path() {
        const char* home = getenv("HOME");
        if (!home) {
            if (struct passwd* pw = getpwuid(getuid())) home = pw->pw_dir;
        }
        return home ? std::string(home) + "/.netnotes/config" : std::string{};
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────

    void cleanup() {
        AsyncLogger::Logger::log_info("Shutting down...", "NoteDaemon");

        error_collector_.clear();
        module_registry_.clear();
        ownership_registry_.clear();
        module_loader_.unload_all();

        if (server_socket_ >= 0) {
            safe_close(server_socket_);
            unlink(config_.socket_path.c_str());
        }

        if (usb_ctx_) {
            libusb_exit(usb_ctx_);
            usb_ctx_ = nullptr;
        }

        AsyncLogger::Logger::stop();
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// main()
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    bool show_help   = false;
    bool check_only  = false;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--help" || arg == "-h") show_help  = true;
        if (arg == "--check"|| arg == "-c") check_only = true;
    }

    if (show_help) {
        fprintf(stderr,
            "NetNotes IO Daemon (two-socket modular architecture)\n"
            "Usage: %s [OPTIONS]\n\n"
            "Options:\n"
            "  -h, --help    Show this help\n"
            "  -c, --check   Check requirements and exit\n\n"
            "Socket: /run/netnotes/notedaemon.sock\n",
            argv[0]);
        return 0;
    }

    if (check_only) {
        openlog("notedaemon-check", LOG_PERROR | LOG_PID, LOG_DAEMON);
        libusb_context* ctx = nullptr;
        bool ok = (libusb_init(&ctx) == 0);
        if (ok) libusb_exit(ctx);
        closelog();
        return ok ? 0 : 1;
    }

    NoteDaemonApp daemon;
    return daemon.run();
}
