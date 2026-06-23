// include/module_framework/channel.h
// Channel abstraction — wraps different transports for module data communication.
//
// The management socket (Unix/TCP) is always the control plane.
// Each module can optionally declare a "channel" type in its config
// for its data plane — how clients exchange live data with the module.
//
// Channel types:
// "unix" (default) — Same fd-based path as today.
// "tcp" — Module listens on its own TCP port.
// "webrtc"— Module uses WebRTC data channels. Signaling via management socket.
// "pipe" — Internal pipe pair (for core-internal module-to-module routing).
//
// WebRTCChannel uses pimpl to hide libdatachannel from this header.
// The .cpp includes <rtc/rtc.hpp> only when WITH_WEBRTC is defined.
// Callers pass a void* to the rtc::DataChannel; the pimpl wraps it.

#ifndef CHANNEL_H
#define CHANNEL_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <atomic>
#include <sys/types.h>
#include "json.hpp" // nlohmann/json

namespace NoteDaemon {

// ═══════════════════════════════════════════════════════════════════════════
// Channel — bidirectional byte stream abstraction
// ═══════════════════════════════════════════════════════════════════════════

class Channel {
public:
  virtual ~Channel() = default;

  virtual std::string channel_type() const = 0;
  virtual std::string peer_id() const = 0;
  virtual pid_t peer_pid() const = 0;

  // Write raw bytes. Thread-safe.
  virtual ssize_t write(const uint8_t* data, size_t len) = 0;
  virtual ssize_t write(const std::vector<uint8_t>& data) {
    return write(data.data(), data.size());
  }

  // Read raw bytes. Blocking. Returns bytes read, 0 on EOF, -1 on error.
  virtual ssize_t read(uint8_t* buf, size_t len) = 0;

  virtual bool is_open() const = 0;
  virtual void close() = 0;

  // Underlying fd for backward compat. -1 for non-fd channels.
  virtual int fd() const = 0;

  // Send as binary on data channel (WebRTC-specific, no-op otherwise).
  virtual void send_arraybuffer(const uint8_t* data, size_t len) {
    write(data, len);
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// UnixChannel — wraps a Unix domain socket fd
// ═══════════════════════════════════════════════════════════════════════════

class UnixChannel : public Channel {
public:
  explicit UnixChannel(int fd, pid_t peer_pid = 0, const std::string& peer_id = "");
  ~UnixChannel() override;

  std::string channel_type() const override { return "unix"; }
  std::string peer_id() const override { return peer_id_; }
  pid_t peer_pid() const override { return peer_pid_; }
  ssize_t write(const uint8_t* data, size_t len) override;
  ssize_t read(uint8_t* buf, size_t len) override;
  bool is_open() const override { return fd_ >= 0; }
  void close() override;
  int fd() const override { return fd_; }

private:
  int fd_;
  pid_t peer_pid_;
  std::string peer_id_;
};

// ═══════════════════════════════════════════════════════════════════════════
// TcpChannel — wraps a TCP socket fd
// ═══════════════════════════════════════════════════════════════════════════

class TcpChannel : public Channel {
public:
  explicit TcpChannel(int fd, const std::string& peer_addr = "", const std::string& peer_id = "");
  ~TcpChannel() override;

  std::string channel_type() const override { return "tcp"; }
  std::string peer_id() const override { return peer_id_; }
  pid_t peer_pid() const override { return 0; }
  ssize_t write(const uint8_t* data, size_t len) override;
  ssize_t read(uint8_t* buf, size_t len) override;
  bool is_open() const override { return fd_ >= 0; }
  void close() override;
  int fd() const override { return fd_; }

private:
  int fd_;
  std::string peer_addr_;
  std::string peer_id_;
};

// ═══════════════════════════════════════════════════════════════════════════
// WebRTCChannel — wraps a WebRTC data channel (pimpl for libdatachannel)
//
// Pipe bridge design:
//   data channel onmessage → write_pipe_ → [pipe] → read_pipe_
//     → NoteBytes::Reader reads from read_pipe_ (a real fd)
//   Module writes → send_arraybuffer() → data channel send()
//
// The pimpl (WebRTCChannelImpl) holds the shared_ptr<rtc::DataChannel>.
// This header never includes libdatachannel — the .cpp does that.
// Callers pass a void* pointer to the rtc::DataChannel.
// ═══════════════════════════════════════════════════════════════════════════

struct WebRTCChannelImpl; // Opaque — defined in channel.cpp

class WebRTCChannel : public Channel, public std::enable_shared_from_this<WebRTCChannel> {
public:
  // Factory: create a WebRTC channel from a data channel pointer.
  // dc_ptr is a pointer to rtc::DataChannel. Returns nullptr if
  // WebRTC support is not compiled in.
  static std::unique_ptr<WebRTCChannel> create(void* dc_ptr, const std::string& peer_id);
  ~WebRTCChannel() override;

  std::string channel_type() const override { return "webrtc"; }
  std::string peer_id() const override { return peer_id_; }
  pid_t peer_pid() const override { return 0; }

  ssize_t write(const uint8_t* data, size_t len) override;
  void send_arraybuffer(const uint8_t* data, size_t len) override;
  ssize_t read(uint8_t* buf, size_t len) override;

  bool is_open() const override;
  void close() override;

  // Pipe read fd — for NoteBytes::Reader compatibility
  int fd() const override { return read_pipe_; }

  // Data channel callbacks (called by the core's WebRTC event loop)
  void on_data_channel_message(const uint8_t* data, size_t len);
  void on_data_channel_open();
  void on_data_channel_close();

  // Access pimpl for WebRTC management code
  WebRTCChannelImpl* impl() { return impl_.get(); }

private:
  explicit WebRTCChannel(const std::string& peer_id);
  std::unique_ptr<WebRTCChannelImpl> impl_;
  std::string peer_id_;
  int read_pipe_ = -1;
  int write_pipe_ = -1;
  std::atomic<bool> open_{false};
};

// ═══════════════════════════════════════════════════════════════════════════
// PipeChannel — internal pipe pair for module-to-module routing
// ═══════════════════════════════════════════════════════════════════════════

class PipeChannel : public Channel {
public:
  PipeChannel(int read_fd, int write_fd, const std::string& peer_id = "internal");
  ~PipeChannel() override;

  std::string channel_type() const override { return "pipe"; }
  std::string peer_id() const override { return peer_id_; }
  pid_t peer_pid() const override { return 0; }
  ssize_t write(const uint8_t* data, size_t len) override;
  ssize_t read(uint8_t* buf, size_t len) override;
  bool is_open() const override { return read_fd_ >= 0; }
  void close() override;
  int fd() const override { return read_fd_; }

private:
  int read_fd_;
  int write_fd_;
  std::string peer_id_;
};

// ═══════════════════════════════════════════════════════════════════════════
// ChannelFactory
// ═══════════════════════════════════════════════════════════════════════════

class ChannelFactory {
public:
  // Read channel type from module config. Defaults to "unix".
  static std::string get_channel_type(const nlohmann::json& module_config);

  // Create a Unix/TcpChannel from an existing fd
  static std::unique_ptr<Channel> from_fd(int fd, pid_t peer_pid = 0,
    const std::string& channel_type = "unix", const std::string& peer_id = "");

  // Create a WebRTCChannel from a data channel pointer.
  // dc_ptr is a raw pointer to rtc::DataChannel. Returns nullptr if
  // WebRTC is not compiled in.
  static std::unique_ptr<Channel> from_webrtc(void* dc_ptr, const std::string& peer_id = "");
};

} // namespace NoteDaemon
#endif // CHANNEL_H
