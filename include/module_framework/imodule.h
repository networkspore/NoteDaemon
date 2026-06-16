// include/module_framework/imodule.h
// IModule interface - base interface for all loadable modules.
//
// handle_channel() takes a raw Channel* (non-owning) because some channel
// types (WebRTC) have their lifecycle managed by the core's WebRTCManager,
// not the module. The module must NOT delete the channel pointer.
// For Unix/TCP fd channels, the module can call channel->close() when done.

#ifndef IMODULE_H
#define IMODULE_H

#include <string_view>
#include <memory>
#include <vector>
#include "error.h"
#include "channel.h"
#include "capability_registry.h"
#include "device_ownership_registry.h"
#include "json.hpp" // nlohmann/json

namespace NoteDaemon {

class HandlerRegistry;

class IModule {
public:
  virtual ~IModule() = default;

  // ── Identity ──────────────────────────────────────────────────────────────

  virtual std::string_view name() const = 0;
  virtual std::string_view version() const = 0;
  virtual std::string_view description() const = 0;

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  virtual Error init(const nlohmann::json& config) = 0;
  virtual void set_ownership_registry(DeviceOwnershipRegistry* /*registry*/) {}
  virtual Error start() = 0;
  virtual Error stop() = 0;
  virtual void shutdown() = 0;

  // ── Connection handling ───────────────────────────────────────────────────

  virtual Error handle_management_message(const NoteBytes::Object& message,
    int reply_fd, pid_t client_pid) {
    (void)message; (void)reply_fd; (void)client_pid;
    return Error::from_code(ErrorCodes::UNKNOWN, "handle_management_message not implemented");
  }

  /**
   * handle_client() – DEVICE socket entry point (fd-based).
   * Module takes full ownership of client_fd lifecycle.
   */
  virtual Error handle_client(int client_fd, pid_t client_pid,
    const std::string& device_id) = 0;

  /**
   * handle_channel() – channel-based data connection entry point.
   *
   * Called when a data connection arrives on any channel type.
   * The module gets a non-owning Channel* — it can read/write but
   * must NOT delete it. For WebRTC channels, the WebRTCManager owns
   * the lifecycle. For Unix channels, the module can call close().
   *
   * Default: unwraps fd and delegates to handle_client().
   */
  virtual Error handle_channel(Channel* channel, const std::string& device_id) {
    int fd = channel->fd();
    pid_t pid = channel->peer_pid();
    return handle_client(fd, pid, device_id);
  }

  /**
   * Return the module's preferred data channel type.
   * "unix" (default), "tcp", "webrtc", "pipe".
   */
  virtual std::string_view channel_type() const { return "unix"; }

  virtual void cleanup_client(pid_t client_pid) = 0;

  // ── Health ───────────────────────────────────────────────────────────────

  virtual Error check_health(const std::string& core_api_version) = 0;

  // ── Capabilities & routing ───────────────────────────────────────────────

  virtual cpp_int capabilities() const = 0;
  virtual std::vector<std::string> get_handled_message_types() = 0;
  virtual HandlerRegistry& get_handler_registry() = 0;
  virtual void collect_errors(std::vector<Error>& errors) = 0;
  virtual void cleanup() = 0;
};

using ModuleFactory = IModule*(*)();

inline std::string get_module_factory_symbol(const std::string& module_name) {
  return "create_" + module_name + "_module";
}

} // namespace NoteDaemon
#endif // IMODULE_H
