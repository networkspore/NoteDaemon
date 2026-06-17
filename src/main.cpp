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
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include "tls_transport.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#ifdef WITH_LIBUSB
#include <libusb-1.0/libusb.h>
#endif

#include "utils.h"
#include "note_messaging.h"
#include "async_logger.h"
#include "notebytes_reader.h"

// Module framework
#include "module_framework/error.h"
#include "module_framework/imodule.h"
#include "module_framework/module_loader.h"
#include "module_framework/module_registry.h"

#include "module_framework/handler_registry.h"
#include "module_framework/device_ownership_registry.h"
#include "module_framework/config_manager.h"
#include "module_framework/error_collector.h"
#include "module_framework/path_resolver.h"
#include "module_framework/channel.h"
#include "module_framework/webrtc_manager.h"

// NoteBytes I/O
#include "notebytes.h"
#include "notebytes_writer.h"

// NoteFile service (encrypted file storage + auth provider)
#include "note_file_service.h"
#include "note_file_handle.h"

using namespace NoteDaemon;
using Json = nlohmann::json;

constexpr std::string_view CORE_API_VERSION = "1.0.0";

std::atomic<bool> g_running{true};
std::atomic<bool> g_cleanup_done{false};

// Shutdown pipe: used to wake main_loop immediately on SIGTERM/SIGINT.
// This avoids relying on SA_RESTART or timing of select() timeout.
int g_shutdown_pipe[2] = {-1, -1};

// Optional: fd to write a tiny async-signal-safe shutdown trace.
// Initially -1; set in run() after open("/dev/kmsg", ...) or a dedicated log fd.
int g_signal_log_fd = -1;

// Last-resort SIGALRM handler: force-exit if shutdown doesn't complete in time.
static void sigalrm_handler(int) {
    // Write a final trace before force-exit (no syslog, no C++).
    if (g_signal_log_fd >= 0) {
        const char msg[] = "SHUTDOWN-FORCE: alarm deadline reached, force-exiting with success\n";
        ssize_t n = write(g_signal_log_fd, msg, sizeof(msg) - 1);
        (void)n;
    }
    // Use _exit() NOT exit() — async-signal-safe.
    // This alarm is armed only by SIGTERM/SIGINT shutdown handling.
    // Exit 0 so systemd records a clean stop instead of status=1/FAILURE.
    _exit(0);
}

static void signal_handler(int signum) {
    (void)signum;
    // IMPORTANT: This handler must be strictly async-signal-safe.
    // Do NOT use syslog, malloc, stdio, C++ objects, or locks here.
    g_running.store(false, std::memory_order_relaxed);

    // Async-signal-safe trace (best-effort; ignore errors).
    if (g_signal_log_fd >= 0) {
        const char msg[] = "SHUTDOWN-01: signal_handler called\n";
        ssize_t n = write(g_signal_log_fd, msg, sizeof(msg) - 1);
        (void)n;
    }

    // Write to shutdown pipe to wake select() in main_loop.
    // This is async-signal-safe and ensures shutdown begins promptly
    // even if main_loop is blocked in a long-lived syscall.
    if (g_shutdown_pipe[1] >= 0) {
        const char c = 'x';
        ssize_t n = write(g_shutdown_pipe[1], &c, 1);
        (void)n;  // ignore errors; best-effort
    }

    // ---- Hard deadline ----
    // If the normal shutdown path (g_running + pipe -> main_loop -> cleanup)
    // fails to complete, this alarm guarantees the process exits within 5s
    // so systemctl stop never hangs.
    // alarm() is async-signal-safe.
    alarm(5);
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreadManager - tracks worker threads and safely detaches them
// ─────────────────────────────────────────────────────────────────────────────

class ThreadManager {
public:
    using ThreadId = int; // e.g. client fd

    void track_thread(ThreadId id, std::thread t) {
        if (!t.joinable()) return;
        std::lock_guard<std::mutex> lock(mutex_);

        // FDs are frequently reused by the kernel. If we overwrite an existing
        // joinable std::thread for the same fd, std::thread's destructor will
        // call std::terminate(). Resolve any previous entry first.
        auto existing = threads_.find(id);
        if (existing != threads_.end()) {
            if (existing->second.joinable()) {
                // Prevent std::terminate() on overwrite when an fd is reused.
                existing->second.detach();
            }
            threads_.erase(existing);
        }

        threads_.emplace(id, std::move(t));
    }

    // On shutdown: detach all tracked threads to avoid blocking teardown.
    void shutdown_all(std::chrono::milliseconds per_thread_timeout) {
        (void)per_thread_timeout;
        std::map<ThreadId, std::thread> threads;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            threads = std::move(threads_);
        }

        if (threads.empty()) return;

        syslog(LOG_INFO, "ThreadManager: detaching %zu tracked thread(s)", threads.size());

        for (auto& [id, t] : threads) {
            if (!t.joinable()) continue;
            t.detach();
            syslog(LOG_DEBUG, "ThreadManager: detached thread for id=%d", id);
        }
    }

private:
    std::mutex mutex_;
    std::map<ThreadId, std::thread> threads_;
};

// ─────────────────────────────────────────────────────────────────────────────
// NoteDaemonApp
// ─────────────────────────────────────────────────────────────────────────────

class NoteDaemonApp {
public:
    void set_cli_root(const std::string& root) { cli_root_ = root; }

    int run() {
        struct CleanupGuard {
            NoteDaemonApp* d;
            CleanupGuard(NoteDaemonApp* d_) : d(d_) {}

            ~CleanupGuard() {
                // Start a hard-shutdown watchdog: if cleanup takes too long,
                // force-exit so systemctl stop never hangs indefinitely.
                constexpr auto hard_shutdown_timeout = std::chrono::seconds(8);
                std::thread watchdog([&]() {
                    auto deadline = std::chrono::steady_clock::now() + hard_shutdown_timeout;
                    while (!g_cleanup_done.load()) {
                        auto now = std::chrono::steady_clock::now();
                        if (now >= deadline) {
                            syslog(LOG_CRIT, "Cleanup timed out; forcing hard shutdown");
                            _exit(0);  // force exit to avoid hanging systemd
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                    // Cleanup finished in time; watchdog can exit cleanly.
                });
                watchdog.detach();  // we never want to block here

                d->cleanup();
                g_cleanup_done.store(true, std::memory_order_relaxed);
                // Cleanup finished; disarm SIGALRM shutdown deadline.
                alarm(0);
            }
        } guard(this);

        // Create a shutdown pipe used by signal handlers to wake main_loop
        // immediately on SIGTERM/SIGINT, so shutdown always starts promptly.
        if (pipe(g_shutdown_pipe) < 0) {
            syslog(LOG_ERR, "pipe() for shutdown failed: %s", strerror(errno));
            return 1;
        }

        // Make read end non-blocking so we never get stuck reading it.
        {
            int flags = fcntl(g_shutdown_pipe[0], F_GETFL, 0);
            if (flags >= 0) {
                fcntl(g_shutdown_pipe[0], F_SETFL, flags | O_NONBLOCK);
            }
        }

        // Open an async-signal-safe log fd for shutdown tracing.
        // Using /dev/kmsg (common on systemd/Linux) so we can see
        // signal_handler activity even if syslog is blocked.
        {
            int kmsg_fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
            if (kmsg_fd >= 0) {
                g_signal_log_fd = kmsg_fd;
            }
            // If /dev/kmsg is not available, g_signal_log_fd stays -1;
            // shutdown will still work via the shutdown pipe + g_running.
        }

        // Install signal handlers via sigaction (not signal())
        // - not reset after first delivery
        // - no SA_RESTART: we want the signal to interrupt blocking syscalls
        //   so the shutdown pipe + g_running can be processed promptly.
        {
            struct sigaction sa{};
            sa.sa_handler = signal_handler;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = 0;  // allow interrupting syscalls (no SA_RESTART)

            if (sigaction(SIGTERM, &sa, nullptr) < 0) {
                syslog(LOG_ERR, "sigaction(SIGTERM) failed: %s", strerror(errno));
                return 1;
            }

            if (sigaction(SIGINT, &sa, nullptr) < 0) {
                syslog(LOG_ERR, "sigaction(SIGINT) failed: %s", strerror(errno));
                return 1;
            }
        }

        // Install SIGALRM handler (async-signal-safe hard deadline).
        {
            struct sigaction sa{};
            sa.sa_handler = sigalrm_handler;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = 0;
            if (sigaction(SIGALRM, &sa, nullptr) < 0) {
                syslog(LOG_ERR, "sigaction(SIGALRM) failed: %s", strerror(errno));
                return 1;
            }
        }

        // Ignore SIGPIPE so we don't die when a client disconnects mid-write
        signal(SIGPIPE, SIG_IGN);

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
        #ifdef WITH_LIBUSB
        if (!init_libusb())  return 1;
        #endif
        if (!setup_socket()) return 1;

        // Initialize NoteFile service BEFORE modules so they can use it
        // during their init() / start() for state persistence.
        {
            NoteFileConfig file_config;
            file_config.data_directory = paths_.root + "/data/files";
            file_config.clients_registry = paths_.root + "/clients.dat";
            // removed
            
            file_service_ = std::make_unique<NoteFileService>(file_config);
            if (file_service_->init()) {
                set_file_service(file_service_.get());
                syslog(LOG_INFO, "NoteFileService initialized as core service");
            } else {
                syslog(LOG_WARNING, "NoteFileService init returned false");
            }
        }

        load_modules();

        if (config_.socket_type == "tcp") {
            syslog(LOG_INFO, "Daemon ready on TCP %s:%d",
                   config_.bind_address.c_str(), config_.listen_port);
        } else {
            syslog(LOG_INFO, "Daemon ready on Unix %s", config_.socket_path.c_str());
        }

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
  WebRTCManager webrtc_manager_;
    
    // NoteFile service (auth + encrypted file storage)
    std::unique_ptr<NoteFileService> file_service_;
    Paths                   paths_;
    std::string             cli_root_;

    #ifdef WITH_LIBUSB
    libusb_context* usb_ctx_      = nullptr;
    #endif
    int             server_socket_ = -1;
    
    // TLS support
    std::unique_ptr<TLS::TLSContext> tls_context_;
    TLS::IPAllowlist ip_allowlist_;
    bool tcp_mode_ = false;

    ThreadManager thread_manager_;
    std::mutex    client_fds_mutex_;
    std::set<int> client_fds_;

    // ── Configuration & setup ─────────────────────────────────────────────────

    void load_configuration() {
        // 1) Determine binary directory
        std::string binary_dir = get_binary_directory();
        syslog(LOG_INFO, "Binary directory: %s", binary_dir.c_str());

        // 2) Config file: same directory as the binary
        std::string cfg_path = get_config_path(binary_dir);
        if (!cfg_path.empty()) {
            syslog(LOG_INFO, "Loading config from: %s", cfg_path.c_str());
            config_.load_from_file(cfg_path);
        } else {
            syslog(LOG_WARNING, "No config file found near binary; using defaults");
        }

        // 3) Modules directory: static, always <binary_dir>/modules
        //    Non-configurable; always derived from the running binary location.
        config_.module_directory = join_path(binary_dir, "modules");
        syslog(LOG_INFO, "Module directory (static): %s", config_.module_directory.c_str());

        // 4) Resolve root directory (for logs, runtime, registries)
        paths_ = build_paths(resolve_root(cli_root_, config_.get_string("root.path", "")));

        // 5) Use runtime_dir only if socket_dir/socket_path not explicitly configured
        if (config_.socket_dir.empty()) {
            config_.socket_dir = paths_.runtime_dir;
        }
        if (config_.socket_path.empty()) {
            config_.socket_path = join_path(config_.socket_dir, "notedaemon.sock");
        }

        // 6) Load socket type and TCP settings
        config_.socket_type = config_.get_string("socket.type", "unix");
        config_.bind_address = config_.get_string("socket.bind_address", "127.0.0.1");
        config_.listen_port = config_.get_int("socket.listen_port", 0);
        tcp_mode_ = (config_.socket_type == "tcp");

        // Generate socket path for TCP mode if not set
        if (tcp_mode_ && config_.listen_port > 0) {
            config_.socket_path = "tcp://" + config_.bind_address + ":" + std::to_string(config_.listen_port);
        }

        // Initialize IP allowlist for TCP mode
        if (tcp_mode_ && !config_.allowed_ips.empty()) {
            for (const auto& ip : config_.allowed_ips) {
                ip_allowlist_.add(ip);
            }
            syslog(LOG_INFO, "IP allowlist: %zu entries loaded", ip_allowlist_.size());
        }

        syslog(LOG_INFO, "=== Daemon Configuration ===");
        syslog(LOG_INFO, "Root: %s", paths_.root.c_str());
        if (tcp_mode_) {
            syslog(LOG_INFO, "Socket: TCP %s:%d",
                   config_.bind_address.c_str(), config_.listen_port);
            if (config_.tls_enabled) {
                syslog(LOG_INFO, "TLS: enabled (cert=%s)", config_.tls_cert_file.c_str());
                if (config_.tls_require_client_cert) {
                    syslog(LOG_INFO, "TLS: client certificate required (mTLS)");
                }
            } else {
                syslog(LOG_INFO, "TLS: disabled");
            }
            if (!ip_allowlist_.empty()) {
                syslog(LOG_INFO, "IP allowlist: %zu entries", ip_allowlist_.size());
            }
        } else {
            syslog(LOG_INFO, "Socket: Unix %s (group=%s, perms=0%o)",
                   config_.socket_path.c_str(),
                   config_.socket_group.c_str(),
                   (int)config_.socket_permissions);
        }
        syslog(LOG_INFO, "Module directory: %s", config_.module_directory.c_str());
        syslog(LOG_INFO, "strict_load=%d  health_check=%d",
               config_.strict_load, config_.health_check);
        syslog(LOG_INFO, "============================");
    }

    bool validate_requirements() {
        #ifdef WITH_LIBUSB
        // Quick libusb probe
        libusb_context* ctx = nullptr;
        if (libusb_init(&ctx) < 0) {
            syslog(LOG_ERR, "libusb probe failed");
            return false;
        }
        libusb_exit(ctx);
        #endif

        // Only check socket dir for unix sockets
        if (config_.socket_type != "tcp") {
            if (mkdir(config_.socket_dir.c_str(), 0755) < 0 && errno != EEXIST) {
                syslog(LOG_ERR, "Cannot create socket dir: %s", strerror(errno));
                return false;
            }
            if (access(config_.socket_dir.c_str(), W_OK) < 0) {
                syslog(LOG_ERR, "Socket dir not writable");
                return false;
            }
        }
        return true;
    }

    #ifdef WITH_LIBUSB
    bool init_libusb() {
        int rc = libusb_init(&usb_ctx_);
        if (rc < 0) {
            syslog(LOG_ERR, "libusb_init: %s", libusb_error_name(rc));
            return false;
        }
        return true;
    }
#endif

    bool setup_socket() {
        if (config_.socket_type == "tcp") {
            return setup_tcp_socket();
        }
        return setup_unix_socket();
    }

    bool setup_unix_socket() {
        unlink(config_.socket_path.c_str());

        server_socket_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_socket_ < 0) {
            syslog(LOG_ERR, "socket(AF_UNIX): %s", strerror(errno));
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
        if (grp) {
            int rc = chown(config_.socket_path.c_str(), -1, grp->gr_gid);
            (void)rc;  // chown failure not fatal - socket still works with new owner
        }

        if (listen(server_socket_, 32) < 0) {
            syslog(LOG_ERR, "listen(): %s", strerror(errno));
            safe_close(server_socket_);
            return false;
        }
        return true;
    }

    bool setup_tcp_socket() {
        if (config_.listen_port <= 0) {
            syslog(LOG_ERR, "TCP mode requires socket.listen_port > 0");
            return false;
        }

        // TLS is not yet fully integrated with NoteBytes I/O
        // Disable for now until NoteBytesReader supports SSL_read
        if (config_.tls_enabled) {
            syslog(LOG_WARNING, "TLS is configured but not yet fully supported for NoteBytes protocol. "
                                "Using plain TCP with IP allowlisting for security.");
            config_.tls_enabled = false;
        }

        server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket_ < 0) {
            syslog(LOG_ERR, "socket(AF_INET): %s", strerror(errno));
            return false;
        }

        // Allow address reuse
        int opt = 1;
        if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            syslog(LOG_WARNING, "setsockopt(SO_REUSEADDR): %s", strerror(errno));
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.listen_port);

        if (config_.bind_address == "0.0.0.0" || config_.bind_address.empty()) {
            addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            if (inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr) <= 0) {
                syslog(LOG_ERR, "Invalid bind address: %s", config_.bind_address.c_str());
                safe_close(server_socket_);
                return false;
            }
        }

        if (bind(server_socket_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            syslog(LOG_ERR, "bind(%s:%d): %s",
                   config_.bind_address.c_str(), config_.listen_port, strerror(errno));
            safe_close(server_socket_);
            return false;
        }

        if (listen(server_socket_, 32) < 0) {
            syslog(LOG_ERR, "listen(): %s", strerror(errno));
            safe_close(server_socket_);
            return false;
        }

        if (config_.tls_enabled) {
            syslog(LOG_INFO, "TCP+TLS socket enabled on %s:%d",
                   config_.bind_address.c_str(), config_.listen_port);
        } else {
            syslog(LOG_WARNING, "TCP socket enabled (no TLS) - peer credential checks disabled. "
                                "Ensure network-level access control is in place.");
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

            // Inject runtime paths for the external note_usb module.
            // The module implementation lives in ../NoteUSB; core only
            // provides resolved paths via init config.
            if (name == "note_usb") {
                init_cfg["discovery_registry_path"] = paths_.note_usb_discovery_registry_file;
            }

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

            // Populate routing registry for introspection/diagnostics only.
            // This is NOT used for message dispatch – clients must supply
            // MODULE_ID to target a module explicitly.
            auto types = module->get_handled_message_types();
            routing_registry_.register_module(name, types);
            syslog(LOG_INFO, "Module %s registered; advertises %zu message type(s)",
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
        syslog(LOG_INFO, "Module capability registry: %zu advertised message type(s) "
                         "(introspection only – dispatch uses MODULE_ID)",
               routes.size());
    }

    // ── Main accept loop ──────────────────────────────────────────────────────

    void fork_process_monitor() {
        pid_t pid = fork();
        if (pid == 0) {
            char ps[32];
            snprintf(ps, sizeof(ps), "%d", getppid());
            execl("/etc/netnotes/process_monitor", "process_monitor", ps, nullptr);
            _exit(1);
        } else if (pid > 0) {
            syslog(LOG_INFO, "Process monitor started (pid=%d)", pid);
        }
    }

    void main_loop() {
        AsyncLogger::Logger::log_info("Main loop started", "NoteDaemon");
        syslog(LOG_INFO, "SHUTDOWN-00: main_loop entered");

        int max_fd = std::max(server_socket_, g_shutdown_pipe[0]);

        while (g_running.load()) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(server_socket_, &rfds);
            FD_SET(g_shutdown_pipe[0], &rfds);

            struct timeval tv = {1, 0};
            int rc = select(max_fd + 1, &rfds, nullptr, nullptr, &tv);

            if (rc < 0) {
                if (errno == EINTR) {
                    // Signal interrupted select(); check g_running.
                    if (!g_running.load()) {
                        AsyncLogger::Logger::log_info("SHUTDOWN-02: SIGTERM/SIGINT via EINTR, stopping", "NoteDaemon");
                        syslog(LOG_INFO, "SHUTDOWN-02E: select EINTR, g_running=0, exiting main_loop");
                        break;
                    }
                    continue;
                }
                AsyncLogger::Logger::log_error(
                    "select() error: " + std::string(strerror(errno)), "NoteDaemon");
                break;
            }

            if (rc > 0) {
                // Shutdown pipe signaled: treat as explicit stop request.
                if (FD_ISSET(g_shutdown_pipe[0], &rfds)) {
                    // Drain any bytes so we don't re-trigger
                    char buf[64];
                    while (true) {
                        ssize_t n = read(g_shutdown_pipe[0], buf, sizeof(buf));
                        if (n <= 0) break;
                    }
                    AsyncLogger::Logger::log_info("SHUTDOWN-02: shutdown pipe signaled, stopping", "NoteDaemon");
                    syslog(LOG_INFO, "SHUTDOWN-02P: shutdown pipe active, exiting main_loop");
                    g_running.store(false, std::memory_order_relaxed);
                    break;
                }

                if (FD_ISSET(server_socket_, &rfds)) {
                    accept_connection();
                }
            }
        }

        AsyncLogger::Logger::log_info("SHUTDOWN-03: main_loop exited, starting cleanup", "NoteDaemon");
        syslog(LOG_INFO, "SHUTDOWN-03: main_loop exited, about to return to run()");
    }

    // ── Connection dispatch ───────────────────────────────────────────────────

    /**
     * Accept one connection and classify it as management or device socket.
     * Spawns a background thread for management connections so main_loop
     * is never blocked.
     */
    void accept_connection() {
        int client_fd = -1;
        pid_t client_pid = 0;

        if (tcp_mode_) {
            // TCP accept
            struct sockaddr_in addr{};
            socklen_t len = sizeof(addr);

            client_fd = accept(server_socket_, (struct sockaddr*)&addr, &len);
            if (client_fd < 0) {
                syslog(LOG_WARNING, "accept(): %s", strerror(errno));
                return;
            }

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));

            // Check IP allowlist
            if (!ip_allowlist_.empty() && !ip_allowlist_.is_allowed(ip_str)) {
                syslog(LOG_WARNING, "TCP connection rejected: %s not in allowlist", ip_str);
                safe_close(client_fd);
                return;
            }

            syslog(LOG_INFO, "TCP connection from %s:%d fd=%d",
                   ip_str, ntohs(addr.sin_port), client_fd);

            // No peer credentials for TCP - use 0 as placeholder
            client_pid = 0;
        } else {
            // Unix socket accept
            struct sockaddr_un addr{};
            socklen_t len = sizeof(addr);

            client_fd = accept(server_socket_, (struct sockaddr*)&addr, &len);
            if (client_fd < 0) {
                syslog(LOG_WARNING, "accept(): %s", strerror(errno));
                return;
            }

            // Peer credentials (Unix only)
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

            client_pid = creds.pid;
            syslog(LOG_INFO, "Connection from uid=%d pid=%d fd=%d",
                   creds.uid, creds.pid, client_fd);
        }

        // Track client fd for shutdown-time cleanup
        {
            std::lock_guard<std::mutex> lock(client_fds_mutex_);
            client_fds_.insert(client_fd);
        }

        // Read the first message to classify the connection.
        // This is done in a worker thread so accept_connection() returns
        // immediately.  Timeout/error handling is inside the thread.
        // If TLS is enabled, wrap the connection first.
        auto t = std::thread([this, client_fd, pid = client_pid, use_tls = tls_context_ != nullptr]() mutable {
            try {
                // Perform TLS handshake if enabled
                if (use_tls && tls_context_) {
                    auto tls_conn = std::make_unique<TLS::TLSConnection>(tls_context_->get(), client_fd);
                    if (!tls_conn->accept()) {
                        syslog(LOG_ERR, "TLS handshake failed for fd=%d", client_fd);
                        safe_close(client_fd);
                        return;
                    }
                    // For TLS, we need to use SSL for all I/O
                    // TODO: Refactor NoteBytesReader to support SSL_read
                    syslog(LOG_ERR, "TLS connections not yet fully supported for NoteBytes protocol");
                    safe_close(client_fd);
                    return;
                }
                dispatch_new_connection(client_fd, pid);
            } catch (const std::exception& e) {
                syslog(LOG_ERR, "Unhandled exception in connection thread (pid=%d): %s",
                       pid, e.what());
            } catch (...) {
                syslog(LOG_ERR, "Unknown unhandled exception in connection thread (pid=%d)", pid);
            }
        });
        thread_manager_.track_thread(client_fd, std::move(t));
    }

    /**
     * Read the first message from a fresh connection and route accordingly.
     * Runs in a worker thread.
     */
    void dispatch_new_connection(int client_fd, pid_t client_pid) {
        // Ensure fd is removed on exit, regardless of path
        struct FdGuard {
            NoteDaemonApp* d;
            int fd;
            ~FdGuard() {
                std::lock_guard<std::mutex> lock(d->client_fds_mutex_);
                d->client_fds_.erase(fd);
            }
        } guard{this, client_fd};

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

        // Support both CMD and EVENT for DEVICE_HANDSHAKE (EVENT is canonical in Java)
        auto* cmd_val = first_msg.get(NoteMessaging::Keys::CMD);
        auto* event_val = first_msg.get(NoteMessaging::Keys::EVENT);
        auto is_handshake = [&](){
            if (cmd_val && *cmd_val == NoteMessaging::ProtocolMessages::DEVICE_HANDSHAKE) return true;
            if (event_val && *event_val == NoteMessaging::ProtocolMessages::DEVICE_HANDSHAKE) return true;
            return false;
        };

        // ── DEVICE SOCKET ──────────────────────────────────────────────────────
        if (is_handshake()) {
            handle_device_socket(client_fd, client_pid, first_msg);
            return;
        }

        // ── MANAGEMENT SOCKET ─────────────────────────────────────────────────
        // Process the already-read first message, then loop.
        handle_management_message(client_fd, first_msg, client_pid);
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

        // Check if this is a NoteFile stream: prefix
        if (device_id.find("stream:") == 0) {
            std::string rest = device_id.substr(7);  // "client:uuid"
            size_t colon = rest.find(':');
            if (colon != std::string::npos) {
                std::string client_id = rest.substr(0, colon);
                std::string stream_id = rest.substr(colon + 1);
                syslog(LOG_INFO, "File stream from client=%s stream=%s",
                       client_id.c_str(), stream_id.c_str());
                auto* svc = get_file_service();
                if (svc) {
                    auto* session = svc->get_stream(stream_id);
                    if (session && session->client_id == client_id) {
                        auto* ch = new UnixChannel(client_fd, client_pid, device_id);
                        if (!svc->route_channel(stream_id, ch)) {
                            syslog(LOG_WARNING, "route failed: %s", stream_id.c_str());
                        }
                        delete ch;
                    } else {
                        syslog(LOG_WARNING, "Stream %s not found or client mismatch",
                               stream_id.c_str());
                    }
                }
            }
            safe_close(client_fd);
            return;
        }

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
        Error err = module->handle_client(client_fd, client_pid, device_id);
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
        // Ensure fd is removed from tracked set on exit
        struct FdGuard {
            NoteDaemonApp* d;
            int fd;
            ~FdGuard() {
                std::lock_guard<std::mutex> lock(d->client_fds_mutex_);
                d->client_fds_.erase(fd);
            }
        } guard{this, client_fd};

        try {
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
                handle_management_message(client_fd, msg, client_pid);
            }
        } catch (const std::exception& e) {
            syslog(LOG_WARNING, "run_management_loop exception (pid=%d): %s",
                   client_pid, e.what());
        } catch (...) {
            syslog(LOG_WARNING, "run_management_loop unknown exception (pid=%d)", client_pid);
        }

        // Best-effort per-module client cleanup when a management connection
        // closes unexpectedly. This prevents stale claims from surviving
        // crashed/disconnected clients.
        for (auto* mod : module_registry_.get_all_modules()) {
            if (!mod) continue;
            try {
                mod->cleanup_client(client_pid);
            } catch (const std::exception& e) {
                syslog(LOG_WARNING,
                       "cleanup_client() exception for module=%s pid=%d: %s",
                       std::string(mod->name()).c_str(),
                       client_pid, e.what());
            } catch (...) {
                syslog(LOG_WARNING,
                       "cleanup_client() unknown exception for module=%s pid=%d",
                       std::string(mod->name()).c_str(),
                       client_pid);
            }
        }

        safe_close(client_fd);
    }

    /**
     * Dispatch one management-socket message.
     *
     * Routing is determined by the presence of MODULE_ID:
     *
     *   MODULE_ID present → forward to the named module's
     *                        handle_management_message() directly.
     *   MODULE_ID absent  → core-handled message:
     *                         HELLO, GET_MODULES, QUERY_DEVICES (fan-out)
     *
     * Multiple modules may handle the same CMD/EVENT type without conflict
     * because the client always addresses a specific module by name.
     *
     * @param reply_fd   File descriptor to write response to.
     * @param msg        Parsed message object.
     * @param client_pid Actual client PID from SO_PEERCRED (not from message).
     */
    void handle_management_message(int reply_fd, const NoteBytes::Object& msg,
                                    pid_t client_pid) {
        // Prefer CMD field; fall back to EVENT
        const NoteBytes::Value* type_val = msg.get(NoteMessaging::Keys::CMD);
        if (!type_val) type_val = msg.get(NoteMessaging::Keys::EVENT);
        if (!type_val) {
            syslog(LOG_WARNING, "Management message has no CMD or EVENT field");
            return;
        }

        std::string msg_type = type_val->as_string();

        // ── MODULE_ID present → module message ───────────────────────────────
        //
        // Client explicitly names the target module; route directly without
        // consulting any message-type routing table.

        const auto* module_id_val = msg.get(NoteMessaging::Keys::MODULE_ID);
        if (module_id_val && !module_id_val->as_string().empty()) {
            std::string target_module = module_id_val->as_string();

            IModule* module = module_registry_.get(target_module);
            if (!module) {
                syslog(LOG_WARNING,
                       "Client specified module '%s' which is not loaded (cmd=%s)",
                       target_module.c_str(), msg_type.c_str());
                send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                           "Module not found: " + target_module);
                return;
            }

            syslog(LOG_DEBUG, "Module message: module=%s cmd=%s",
                   target_module.c_str(), msg_type.c_str());

            Error err = module->handle_management_message(msg, reply_fd, client_pid);
            if (err.failed()) {
                syslog(LOG_WARNING, "Module %s failed to handle %s: %s",
                       target_module.c_str(), msg_type.c_str(),
                       err.message().data());
            }
            return;
        }

        // ── No MODULE_ID → core message ──────────────────────────────────────

        if (*type_val == NoteMessaging::ProtocolMessages::HELLO) {
            handle_hello(reply_fd, msg);
            return;
        }

        if (*type_val == NoteMessaging::ProtocolMessages::GET_MODULES) {
            handle_get_modules(reply_fd);
            return;
        }

        // QUERY_DEVICES is a core fan-out: no MODULE_ID required.
        // (Clients that want a single module's devices can still pass a
        //  module_filter inside the FILTER object, handled inside
        //  handle_query_devices().)
        if (*type_val == NoteMessaging::ProtocolMessages::QUERY_DEVICES) {
            handle_query_devices(reply_fd, msg, client_pid);
            return;
        }

        // TEST_MESSAGE: send a known test message for protocol verification
        if (*type_val == NoteMessaging::ProtocolMessages::TEST_MESSAGE) {
            syslog(LOG_INFO, "Received TEST_MESSAGE from client pid=%d", client_pid);
            handle_test_message(reply_fd, msg, client_pid);
            return;
        }

        // SHUTDOWN: allow Java client to request graceful shutdown
        if (*type_val == NoteMessaging::ProtocolMessages::SHUTDOWN) {
            syslog(LOG_INFO,
                   "Received SHUTDOWN from client pid=%d; initiating shutdown", client_pid);
            g_running = false;
            // Wake main_loop via shutdown pipe if available
            if (g_shutdown_pipe[1] >= 0) {
                char c = 'x';
                ssize_t n = write(g_shutdown_pipe[1], &c, 1);
                (void)n; // ignore errors in shutdown path
            }
            return;
        }

  // WEBRTC_OFFER: core-level signaling intercept
  if (msg_type == "webrtc_offer") {
    handle_webrtc_offer(reply_fd, msg, client_pid);
    return;
  }

  // ── NoteFile / Auth core handlers ──────────────────────────────────
  if (msg_type == "admin_auth") {
    handle_note_file_auth(reply_fd, msg, client_pid);
    return;
  }
  if (msg_type == "set_admin_api_key") {
    handle_note_file_set_password(reply_fd, msg, client_pid);
    return;
  }
  if (msg_type == "get_file") {
    handle_note_file_get(reply_fd, msg, client_pid);
    return;
  }
  if (msg_type == "put_file") {
    handle_note_file_put(reply_fd, msg, client_pid);
    return;
  }
  if (msg_type == "delete_file") {
    handle_note_file_delete(reply_fd, msg, client_pid);
    return;
  }
  if (msg_type == "open_file_stream") {
    handle_open_file_stream(reply_fd, msg, client_pid);
    return;
  }
  if (msg_type == "close_stream") {
    handle_close_stream(reply_fd, msg, client_pid);
    return;
  }

        // Unknown core message
        syslog(LOG_WARNING,
               "Unknown core message (no MODULE_ID): %s", msg_type.c_str());
        send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                   "Unknown core command: " + msg_type);
    }

    // ── QUERY_DEVICES handler with module filter support ─────────────────────

    void handle_query_devices(int reply_fd, const NoteBytes::Object& msg,
                              pid_t client_pid) {
        // Check for optional module_filter
        const auto* filter_val = msg.get(NoteMessaging::Keys::FILTER);
        std::string module_filter;
        if (filter_val && filter_val->type() == NoteBytes::Type::OBJECT) {
            auto filter_obj = NoteBytes::as_object(*filter_val);
            const auto* mf = filter_obj.get(NoteMessaging::Keys::MODULE_FILTER);
            if (mf) {
                module_filter = mf->as_string();
            }
        }

        if (!module_filter.empty()) {
            // Route to specific module only
            auto* mod = module_registry_.get(module_filter);
            if (!mod) {
                syslog(LOG_WARNING,
                       "QUERY_DEVICES: module_filter '%s' not found",
                       module_filter.c_str());
                // Respond with empty result instead of error
                NoteBytes::Object response;
                response.add(NoteMessaging::Keys::EVENT,
                             NoteMessaging::ProtocolMessages::QUERY_RESULT);
                NoteBytes::Array empty;
                response.add(NoteMessaging::Keys::ITEMS, empty.as_value());
                write_to_fd(reply_fd, response);
                return;
            }

            Error err = mod->handle_management_message(msg, reply_fd, client_pid);
            if (err.failed()) {
                syslog(LOG_WARNING,
                       "QUERY_DEVICES: module %s error: %s",
                       module_filter.c_str(),
                       std::string(err.message()).data());
            }
            return;
        }

        // No module_filter: fan-out to all modules that handle QUERY_DEVICES
        // and merge results into one QUERY_RESULT.
        std::vector<IModule*> target_modules;
        for (auto* m : module_registry_.get_all_modules()) {
            const auto& handlers = m->get_handled_message_types();
            for (const auto& h : handlers) {
                if (h == "query_devices") {
                    target_modules.push_back(m);
                    break;
                }
            }
        }

        if (target_modules.empty()) {
            syslog(LOG_WARNING,
                   "QUERY_DEVICES: no modules registered for query_devices");
            // Send empty result
            NoteBytes::Object response;
            response.add(NoteMessaging::Keys::EVENT,
                         NoteMessaging::ProtocolMessages::QUERY_RESULT);
            NoteBytes::Array empty;
            response.add(NoteMessaging::Keys::ITEMS, empty.as_value());
            write_to_fd(reply_fd, response);
            return;
        }

        // Fast-path single module to avoid unnecessary serialize/deserialize
        // merging overhead (and preserve module response bytes exactly).
        if (target_modules.size() == 1) {
            auto* mod = target_modules.front();
            Error err = mod->handle_management_message(msg, reply_fd, client_pid);
            if (err.failed()) {
                syslog(LOG_WARNING,
                       "QUERY_DEVICES: module %s error: %s",
                       mod->name().data(),
                       std::string(err.message()).data());
            }
            return;
        }

        // Each module writes QUERY_RESULT with ITEMS to its own fd;
        // we use a temp pipe to capture and merge results.
        int pfd[2];
        if (pipe(pfd) < 0) {
            syslog(LOG_ERR, "QUERY_DEVICES: pipe() failed: %s", strerror(errno));
            return;
        }

        // Close unused ends; we will:
        // - write to pfd[1] from this thread
        // - read from pfd[0] after all modules reply
        // Each module will be called with pfd[1] as reply_fd.
        // To avoid races, we call modules sequentially.

        for (auto* mod : target_modules) {
            Error err = mod->handle_management_message(msg, pfd[1], client_pid);
            if (err.failed()) {
                syslog(LOG_WARNING,
                       "QUERY_DEVICES: module %s error: %s",
                       mod->name().data(),
                       std::string(err.message()).data());
            }
        }

        // Read all responses from modules and merge ITEMS
        NoteBytes::Array merged_items;
        {
            // Temporarily set FD to non-blocking
            int flags = fcntl(pfd[0], F_GETFL, 0);
            fcntl(pfd[0], F_SETFL, flags | O_NONBLOCK);

            NoteBytes::Reader reader(pfd[0], /*owns_fd=*/false);
            while (true) {
                try {
                    auto obj = reader.read_object();
                    // Expect QUERY_RESULT with ITEMS
                    auto* event_val = obj.get(NoteMessaging::Keys::EVENT);
                    if (event_val &&
                        *event_val == NoteMessaging::ProtocolMessages::QUERY_RESULT) {
                        auto* items_val = obj.get(NoteMessaging::Keys::ITEMS);
                        if (items_val && items_val->type() == NoteBytes::Type::ARRAY) {
                            auto arr = NoteBytes::as_array(*items_val);
                            for (const auto& elem : arr.values()) {
                                merged_items.add(elem);
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    // No more objects or read error
                    break;
                }
            }

            if (flags >= 0) {
                fcntl(pfd[0], F_SETFL, flags);
            }
        }

        close(pfd[0]);
        close(pfd[1]);

        // Build merged QUERY_RESULT
        NoteBytes::Object merged_response;
        merged_response.add(NoteMessaging::Keys::EVENT,
                            NoteMessaging::ProtocolMessages::QUERY_RESULT);
        merged_response.add(NoteMessaging::Keys::ITEMS,
                            merged_items.as_value());
        write_to_fd(reply_fd, merged_response);

        syslog(LOG_INFO,
               "QUERY_DEVICES: merged %zu items from %zu modules",
               merged_items.size(),
               target_modules.size());
    }

    void handle_test_message(int reply_fd, const NoteBytes::Object& msg,
                             pid_t client_pid) {
        (void)msg;  // unused
        (void)client_pid;  // unused

        // Return a deterministic test payload so Java/C++ serialization can be
        // compared without any module-specific runtime dependencies.
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT,
                     NoteMessaging::ProtocolMessages::TEST_MESSAGE);

        NoteBytes::Array items;
        auto add_test_item = [&](const char* device_id,
                                 const char* device_type,
                                 int vendor_id) {
            NoteBytes::Object obj;
            obj.add(NoteMessaging::Keys::DEVICE_ID, NoteBytes::Value(device_id));
            obj.add(NoteMessaging::Keys::DEVICE_TYPE, NoteBytes::Value(device_type));
            obj.add(NoteMessaging::Keys::VENDOR_ID, NoteBytes::Value(vendor_id));
            items.add(obj.as_value());
        };

        add_test_item("test_device_1", "test_type", 0x1234);
        add_test_item("test_device_2", "test_type", 0x5678);
        add_test_item("test_device_3", "test_type", 0xABCD);

        response.add(NoteMessaging::Keys::ITEMS, items.as_value());
        write_to_fd(reply_fd, response);

        syslog(LOG_INFO, "Sent TEST_MESSAGE payload (%zu items)", items.size());
    }

  // ── WebRTC signaling handler ──────────────────────────────────────────────
  void handle_webrtc_offer(int reply_fd, const NoteBytes::Object& msg, pid_t client_pid) {
    (void)client_pid;
    auto* sdp_val = msg.get(NoteBytes::Value("sdp"));
    std::string sdp = sdp_val ? sdp_val->as_string() : "";
    auto* mid_val = msg.get(NoteBytes::Value("target_module"));
    std::string module_id = mid_val ? mid_val->as_string() : "note_agent";
    if (sdp.empty()) {
      syslog(LOG_WARNING, "[Core] webrtc_offer: missing SDP");
      send_error(reply_fd, NoteDaemon::ErrorCodes::INVALID_MESSAGE, "Missing SDP offer");
      return;
    }
    IModule* module = module_registry_.get(module_id);
    if (!module) {
      syslog(LOG_WARNING, "[Core] webrtc_offer: module '%s' not found", module_id.c_str());
      send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN, "Module not found: " + module_id);
      return;
    }
    syslog(LOG_INFO, "[Core] webrtc_offer: module=%s sdp_size=%zu", module_id.c_str(), sdp.size());
    // Set up the channel callback: when the data channel opens, route it to module
    webrtc_manager_.set_channel_callback([this, module_id](Channel* channel, const std::string& device_id) {
      IModule* mod = module_registry_.get(module_id);
      if (!mod) {
        syslog(LOG_WARNING, "[Core] WebRTC channel callback: module '%s' gone", module_id.c_str());
        return;
      }
      syslog(LOG_INFO, "[Core] WebRTC data channel open -> routing to module=%s", module_id.c_str());
      Error err = mod->handle_channel(channel, device_id);
      if (err.failed()) {
        syslog(LOG_ERR, "[Core] handle_channel() failed for module=%s: %s",
          module_id.c_str(), err.message().data());
      }
    });
    std::string answer_sdp = webrtc_manager_.handle_offer(sdp, module_id, module);
    if (answer_sdp.empty()) {
      syslog(LOG_ERR, "[Core] webrtc_offer: failed to get SDP answer");
      send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN, "Failed to create WebRTC answer");
      return;
    }
    NoteBytes::Object response;
    response.add(NoteMessaging::Keys::CMD, NoteBytes::Value("webrtc_answer"));
    response.add(NoteMessaging::Keys::STATUS, NoteMessaging::Status::OK);
    response.add(NoteBytes::Value("sdp"), NoteBytes::Value(answer_sdp));
    response.add(NoteBytes::Value("type"), NoteBytes::Value("answer"));
    write_to_fd(reply_fd, response);
    syslog(LOG_INFO, "[Core] webrtc_offer: answer sent (%zu bytes SDP)", answer_sdp.size());
  }

    // ── NoteFile / Auth management handlers ──────────────────────────────────

    void handle_note_file_auth(int reply_fd, const NoteBytes::Object& msg,
                                pid_t client_pid) {
        auto* pass_val = msg.get(NoteBytes::Value("password"));
        if (!pass_val) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::INVALID_MESSAGE,
                      "Missing password field");
            return;
        }
        auto* svc = get_file_service();
        if (!svc) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                      "File service not initialized");
            return;
        }
        auto token = svc->authenticate_admin(pass_val->as_string(), client_pid);
        if (!token) {
            send_error(reply_fd, NoteMessaging::ErrorCodes::UNAUTHORIZED,
                      "Authentication failed");
            return;
        }
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT, NoteBytes::Value("auth_result"));
        response.add(NoteMessaging::Keys::STATUS, NoteMessaging::Status::OK);
        response.add(NoteBytes::Value("session_id"), token->session_id);
        response.add(NoteBytes::Value("has_password"),
                     NoteBytes::Value(svc->has_admin_api_key()));
        write_to_fd(reply_fd, response);
        syslog(LOG_INFO, "[Auth] Client pid=%d authenticated, session=%s",
               client_pid, token->session_id.c_str());
    }

    void handle_note_file_set_password(int reply_fd, const NoteBytes::Object& msg,
                                        pid_t client_pid) {
        auto* pass_val = msg.get(NoteBytes::Value("password"));
        if (!pass_val) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::INVALID_MESSAGE,
                      "Missing password");
            return;
        }
        auto* svc = get_file_service();
        if (!svc) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                      "Service not available");
            return;
        }
        if (!svc->set_admin_api_key(pass_val->as_string())) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                      "Failed to set password (may already be set)");
            return;
        }
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT, NoteBytes::Value("password_set"));
        response.add(NoteMessaging::Keys::STATUS, NoteMessaging::Status::OK);
        write_to_fd(reply_fd, response);
        syslog(LOG_INFO, "[Auth] Initial password set by pid=%d", client_pid);
    }

    void handle_note_file_change_password(int reply_fd, const NoteBytes::Object& msg,
                                           pid_t client_pid) {
        auto* old_val = msg.get(NoteBytes::Value("old_password"));
        auto* new_val = msg.get(NoteBytes::Value("new_password"));
        if (!old_val || !new_val) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::INVALID_MESSAGE,
                      "Missing old_password or new_password");
            return;
        }
        auto* svc = get_file_service();
        if (!svc) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                      "Service not available");
            return;
        }
        if (!false /* removed */) {
            send_error(reply_fd, NoteMessaging::ErrorCodes::UNAUTHORIZED,
                      "Password change failed (wrong old password?)");
            return;
        }
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT, NoteBytes::Value("password_changed"));
        response.add(NoteMessaging::Keys::STATUS, NoteMessaging::Status::OK);
        write_to_fd(reply_fd, response);
        syslog(LOG_INFO, "[Auth] Password changed by pid=%d", client_pid);
    }

    void handle_note_file_query_files(int reply_fd, const NoteBytes::Object& msg,
                                       pid_t client_pid) {
        (void)msg; (void)client_pid;
        auto* svc = get_file_service();
        if (!svc) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                      "Service not available");
            return;
        }
        auto files = svc->list_client_files(std::string());
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT, NoteBytes::Value("file_list"));
        NoteBytes::Array arr;
        for (const auto& f : files) {
            arr.add(NoteBytes::Value(f));
        }
        response.add(NoteBytes::Value("files"), arr.as_value());
        write_to_fd(reply_fd, response);
    }

    void handle_note_file_get(int reply_fd, const NoteBytes::Object& msg,
                               pid_t client_pid) {
        (void)client_pid;
        auto* path_val = msg.get(NoteBytes::Value("path"));
        if (!path_val) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::INVALID_MESSAGE,
                      "Missing path");
            return;
        }
        auto* svc = get_file_service();
        if (!svc) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                      "Service not available");
            return;
        }
        // Parse path string into segments
        std::string path_str = path_val->as_string();
        std::vector<std::string> segments;
        size_t start = 0, end;
        while ((end = path_str.find('/', start)) != std::string::npos) {
            if (end > start)
                segments.push_back(path_str.substr(start, end - start));
            start = end + 1;
        }
        if (start < path_str.size())
            segments.push_back(path_str.substr(start));

        auto handle = svc->get_file("", segments);
        if (!handle) {
            send_error(reply_fd, NoteMessaging::ErrorCodes::DEVICE_NOT_FOUND,
                      "File not found: " + path_str);
            return;
        }
        auto obj = handle->read_object();
        auto serialized = obj.serialize();
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT, NoteBytes::Value("file_content"));
        response.add(NoteBytes::Value("path"), NoteBytes::Value(path_str));
        response.add(NoteBytes::Value("data"),
                     NoteBytes::Value(serialized, NoteBytes::Type::OBJECT));
        write_to_fd(reply_fd, response);
    }

    void handle_note_file_put(int reply_fd, const NoteBytes::Object& msg,
                               pid_t client_pid) {
        (void)client_pid;
        auto* path_val = msg.get(NoteBytes::Value("path"));
        auto* data_val = msg.get(NoteBytes::Value("data"));
        if (!path_val || !data_val) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::INVALID_MESSAGE,
                      "Missing path or data");
            return;
        }
        auto* svc = get_file_service();
        if (!svc) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                      "Service not available");
            return;
        }
        std::string path_str = path_val->as_string();
        std::vector<std::string> segments;
        size_t start = 0, end;
        while ((end = path_str.find('/', start)) != std::string::npos) {
            if (end > start)
                segments.push_back(path_str.substr(start, end - start));
            start = end + 1;
        }
        if (start < path_str.size())
            segments.push_back(path_str.substr(start));

        auto handle = svc->get_file("", segments);
        if (!handle) {
            send_error(reply_fd, NoteMessaging::ErrorCodes::DEVICE_NOT_FOUND,
                      "Cannot create file: " + path_str);
            return;
        }
        try {
            auto obj = NoteBytes::Object::deserialize(data_val->data().data(),
                                                       data_val->data().size());
            if (!handle->write_object(obj)) {
                send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                          "Failed to write file");
                return;
            }
        } catch (const std::exception& e) {
            send_error(reply_fd, NoteMessaging::ErrorCodes::PARSE_ERROR,
                      std::string("Data parse error: ") + e.what());
            return;
        }
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT, NoteBytes::Value("file_written"));
        response.add(NoteMessaging::Keys::STATUS, NoteMessaging::Status::OK);
        response.add(NoteBytes::Value("path"), NoteBytes::Value(path_str));
        write_to_fd(reply_fd, response);
    }

    void handle_note_file_delete(int reply_fd, const NoteBytes::Object& msg,
                                  pid_t client_pid) {
        (void)client_pid;
        auto* path_val = msg.get(NoteBytes::Value("path"));
        auto* recurse_val = msg.get(NoteBytes::Value("recursive"));
        if (!path_val) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::INVALID_MESSAGE,
                      "Missing path");
            return;
        }
        auto* svc = get_file_service();
        if (!svc) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                      "Service not available");
            return;
        }
        std::string path_str = path_val->as_string();
        std::vector<std::string> segments;
        size_t start = 0, end;
        while ((end = path_str.find('/', start)) != std::string::npos) {
            if (end > start)
                segments.push_back(path_str.substr(start, end - start));
            start = end + 1;
        }
        if (start < path_str.size())
            segments.push_back(path_str.substr(start));

        bool recursive = recurse_val ? recurse_val->as_bool() : false;
        std::vector<NoteBytes::Value> nb_segments;
        for (const auto& s : segments) nb_segments.emplace_back(s);

        if (!svc->delete_file("", nb_segments, recursive)) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                      "Failed to delete: " + path_str);
            return;
        }
        NoteBytes::Object response;
        response.add(NoteMessaging::Keys::EVENT, NoteBytes::Value("file_deleted"));
        response.add(NoteMessaging::Keys::STATUS, NoteMessaging::Status::OK);
        response.add(NoteBytes::Value("path"), NoteBytes::Value(path_str));
        write_to_fd(reply_fd, response);
    }

    // ── File stream handlers ─────────────────────────────────────────────────

    void handle_open_file_stream(int reply_fd, const NoteBytes::Object& msg,
                                  pid_t) {
        auto* cid = msg.get(NoteBytes::Value("client_id"));
        auto* path_val = msg.get(NoteBytes::Value("path"));
        auto* mode_val = msg.get(NoteBytes::Value("mode"));
        if (!cid || !path_val || !mode_val) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::INVALID_MESSAGE,
                      "Missing client_id, path, or mode");
            return;
        }
        auto* svc = get_file_service();
        if (!svc) { send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                              "Service not available"); return; }

        std::string mode_str = mode_val->as_string();
        StreamMode mode = (mode_str == "write") ? StreamMode::WRITE : StreamMode::READ;

        std::vector<std::string> segs;
        std::string ps = path_val->as_string();
        size_t s = 0, e;
        while ((e = ps.find('/', s)) != std::string::npos) {
            if (e > s) segs.push_back(ps.substr(s, e - s));
            s = e + 1;
        }
        if (s < ps.size()) segs.push_back(ps.substr(s));

        std::vector<NoteBytes::Value> nb_segs;
        for (auto& seg : segs) nb_segs.emplace_back(seg);

        auto session = svc->open_stream(cid->as_string(), nb_segs, mode);
        if (!session) {
            send_error(reply_fd, NoteMessaging::ErrorCodes::DEVICE_NOT_FOUND,
                      "Failed to open stream");
            return;
        }

        // Return the client-prefixed stream_id for data channel routing
        std::string routed_id = session->client_id + ":" + session->stream_id;

        NoteBytes::Object resp;
        resp.add(NoteMessaging::Keys::EVENT, NoteBytes::Value("stream_opened"));
        resp.add(NoteBytes::Value("stream_id"), routed_id);
        resp.add(NoteBytes::Value("mode"), *mode_val);
        resp.add(NoteBytes::Value("size"),
                 NoteBytes::Value(static_cast<int64_t>(session->handle->size())));
        write_to_fd(reply_fd, resp);
    }

    void handle_close_stream(int reply_fd, const NoteBytes::Object& msg,
                              pid_t) {
        auto* sid = msg.get(NoteBytes::Value("stream_id"));
        if (!sid) {
            send_error(reply_fd, NoteDaemon::ErrorCodes::INVALID_MESSAGE,
                      "Missing stream_id");
            return;
        }
        auto* svc = get_file_service();
        if (!svc) { send_error(reply_fd, NoteDaemon::ErrorCodes::UNKNOWN,
                              "Service not available"); return; }
        std::string raw = sid->as_string();
        // Strip client prefix if present: "client:uuid" → "uuid"
        size_t c = raw.find(':');
        if (c != std::string::npos && c > 0) raw = raw.substr(c + 1);
        svc->close_stream(raw);
        NoteBytes::Object resp;
        resp.add(NoteMessaging::Keys::EVENT, NoteBytes::Value("stream_closed"));
        resp.add(NoteMessaging::Keys::STATUS, NoteMessaging::Status::OK);
        write_to_fd(reply_fd, resp);
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
        if (!config_.security_require_group) {
            return true;
        }

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

    __attribute__((used)) static std::string get_binary_directory() {
        // Prefer /proc/self/exe on Linux
        char exe_path[4096] = {0};
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = '\0';
        } else {
            // Fallback to argv[0]-style or current dir
            exe_path[0] = '.';
            exe_path[1] = '/';
            exe_path[2] = 'n';
            exe_path[3] = 'o';
            exe_path[4] = 't';
            exe_path[5] = 'e';
            exe_path[6] = '-';
            exe_path[7] = 'd';
            exe_path[8] = 'a';
            exe_path[9] = 'e';
            exe_path[10] = 'm';
            exe_path[11] = 'o';
            exe_path[12] = 'n';
            exe_path[13] = '\0';
        }

        std::string path(exe_path);
        auto pos = path.find_last_of('/');
        if (pos != std::string::npos) {
            path = path.substr(0, pos);
        }
        // Normalize empty to "."
        if (path.empty() || path == "/") path = ".";
        return path;
    }

    __attribute__((used)) static std::string get_config_path(const std::string& binary_dir) {
        // Config file: same directory as the binary
        std::string path = join_path(binary_dir, "note-daemon-config");
        struct stat buf;
        if (stat(path.c_str(), &buf) == 0) {
            return path;
        }
        return std::string{};
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────

    void cleanup() {
        try {
            AsyncLogger::Logger::log_info("SHUTDOWN-04: cleanup() started", "NoteDaemon");

        // 0) Close shutdown pipe so no further wakeups can occur
        if (g_shutdown_pipe[0] >= 0) { safe_close(g_shutdown_pipe[0]); g_shutdown_pipe[0] = -1; }
        if (g_shutdown_pipe[1] >= 0) { safe_close(g_shutdown_pipe[1]); g_shutdown_pipe[1] = -1; }
        AsyncLogger::Logger::log_info("SHUTDOWN-05: shutdown pipe closed", "NoteDaemon");

        // 1) Close all client fds to unblock read loops in connection threads
        AsyncLogger::Logger::log_info("SHUTDOWN-06: closing client file descriptors", "NoteDaemon");
        {
            std::lock_guard<std::mutex> lock(client_fds_mutex_);
            for (int fd : client_fds_) {
                safe_close(fd);
            }
            client_fds_.clear();
        }
        AsyncLogger::Logger::log_info("SHUTDOWN-07: client file descriptors closed", "NoteDaemon");

        // 2) Shut down modules (e.g., NoteUSB will stop sessions, release devices)
        AsyncLogger::Logger::log_info("SHUTDOWN-08: shutting down modules", "NoteDaemon");
        for (auto* mod : module_registry_.get_all_modules()) {
            AsyncLogger::Logger::log_info(
                "SHUTDOWN-09: shutting down module: " + std::string(mod->name()), "NoteDaemon");
            mod->shutdown();
            AsyncLogger::Logger::log_info(
                "SHUTDOWN-10: module " + std::string(mod->name()) + " shutdown complete", "NoteDaemon");
        }

        // 3) Clean up core registries and unload modules
        AsyncLogger::Logger::log_info("SHUTDOWN-11: cleaning up core registries", "NoteDaemon");
        error_collector_.clear();
  webrtc_manager_.shutdown();
        
        // Shutdown file service (clears auth tokens, saves state)
        set_file_service(nullptr);
        file_service_.reset();
        
        module_registry_.clear();
        ownership_registry_.clear();
        module_loader_.unload_all();
        AsyncLogger::Logger::log_info("SHUTDOWN-12: core registries cleaned up", "NoteDaemon");

        // 4) Close server socket
        AsyncLogger::Logger::log_info("SHUTDOWN-13: closing server socket", "NoteDaemon");
        if (server_socket_ >= 0) {
            safe_close(server_socket_);
            // Only unlink for Unix sockets (TCP has no file to clean up)
            if (config_.socket_type != "tcp") {
                unlink(config_.socket_path.c_str());
            }
        }

        // 5) Detach tracked worker threads (non-blocking teardown)
        AsyncLogger::Logger::log_info("SHUTDOWN-14: detaching worker threads", "NoteDaemon");
        thread_manager_.shutdown_all(std::chrono::milliseconds(1000));
        AsyncLogger::Logger::log_info("SHUTDOWN-15: worker thread detach complete", "NoteDaemon");

        #ifdef WITH_LIBUSB

        // 6) Exit libusb
        AsyncLogger::Logger::log_info("SHUTDOWN-16: exiting libusb", "NoteDaemon");
        if (usb_ctx_) {
            libusb_exit(usb_ctx_);
            usb_ctx_ = nullptr;
        }

        #endif

        // 7) Stop async logger last (other components may still log during shutdown)
        // This is the last AsyncLogger call; after this, we fall back to syslog if needed.
        AsyncLogger::Logger::log_info("SHUTDOWN-17: stopping async logger", "NoteDaemon");
        AsyncLogger::Logger::stop();
        syslog(LOG_INFO, "SHUTDOWN-18: cleanup complete");
        } catch (const std::exception& e) {
            // Best-effort log; logger may already be stopped
            syslog(LOG_ERR, "SHUTDOWN-ERR: exception during cleanup: %s", e.what());
        } catch (...) {
            syslog(LOG_ERR, "SHUTDOWN-ERR: unknown exception during cleanup");
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// main()
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    bool show_help   = false;
    bool check_only  = false;
    std::string cli_root;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--help" || arg == "-h") show_help  = true;
        if (arg == "--check"|| arg == "-c") check_only = true;
        if (arg == "--root") {
            if (i + 1 < argc) {
                ++i;
                cli_root = argv[i];
            } else {
                fprintf(stderr, "--root requires a path argument\n");
                return 1;
            }
        }
    }

    if (show_help) {
        fprintf(stderr,
            "NetNotes IO Daemon (two-socket modular architecture)\n"
            "Usage: %s [OPTIONS]\n\n"
            "Options:\n"
            "  -h, --help          Show this help\n"
            "  -c, --check         Check requirements and exit\n"
            "      --root PATH     Set Netnotes root directory\n\n"
            "Root resolution (first match wins):\n"
            "  1) --root PATH\n"
            "  2) $NETNOTES_ROOT\n"
            "  3) config root.path\n"
            "  4) default: ~/.netnotes\n",
            argv[0]);
        return 0;
    }

    if (check_only) {
        openlog("notedaemon-check", LOG_PERROR | LOG_PID, LOG_DAEMON);
        #ifdef WITH_LIBUSB
        libusb_context* ctx = nullptr;
        bool ok = (libusb_init(&ctx) == 0);
        if (ok) libusb_exit(ctx);
        #else
        bool ok = true; // No libusb
        #endif
        closelog();
        return ok ? 0 : 1;
    }

    NoteDaemonApp daemon;
    daemon.set_cli_root(cli_root);
    return daemon.run();
}
