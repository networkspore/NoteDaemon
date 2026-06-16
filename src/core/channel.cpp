// src/core/channel.cpp
// Channel implementation — wraps different transports for module data communication.

#include "module_framework/channel.h"
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>
#include <sys/syslog.h>

// libdatachannel is only needed for WebRTCChannel impl
#ifdef WITH_WEBRTC
#include <rtc/rtc.hpp>
#endif

namespace NoteDaemon {

// ═══════════════════════════════════════════════════════════════════════════
// UnixChannel
// ═══════════════════════════════════════════════════════════════════════════

UnixChannel::UnixChannel(int fd, pid_t peer_pid, const std::string& peer_id)
  : fd_(fd), peer_pid_(peer_pid),
    peer_id_(peer_id.empty() ? ("unix:" + std::to_string(fd)) : peer_id) {}

UnixChannel::~UnixChannel() {
  // Don't auto-close — module or core owns the fd lifecycle
}

ssize_t UnixChannel::write(const uint8_t* data, size_t len) {
  if (fd_ < 0) return -1;
  return ::write(fd_, data, len);
}

ssize_t UnixChannel::read(uint8_t* buf, size_t len) {
  if (fd_ < 0) return -1;
  return ::read(fd_, buf, len);
}

void UnixChannel::close() {
  if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
}

// ═══════════════════════════════════════════════════════════════════════════
// TcpChannel
// ═══════════════════════════════════════════════════════════════════════════

TcpChannel::TcpChannel(int fd, const std::string& peer_addr, const std::string& peer_id)
  : fd_(fd), peer_addr_(peer_addr),
    peer_id_(peer_id.empty() ? ("tcp:" + peer_addr) : peer_id) {}

TcpChannel::~TcpChannel() {}

ssize_t TcpChannel::write(const uint8_t* data, size_t len) {
  if (fd_ < 0) return -1;
  return ::write(fd_, data, len);
}

ssize_t TcpChannel::read(uint8_t* buf, size_t len) {
  if (fd_ < 0) return -1;
  return ::read(fd_, buf, len);
}

void TcpChannel::close() {
  if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
}

// ═══════════════════════════════════════════════════════════════════════════
// WebRTCChannel — pimpl implementation
//
// WebRTCChannelImpl is only defined when WITH_WEBRTC is compiled.
// It holds the shared_ptr<rtc::DataChannel> that we use for writes.
// The header never sees rtc::DataChannel — only a void* factory arg.
//
// Pipe bridge:
//   data channel onmessage → write_pipe_ → [pipe] → read_pipe_
//     → NoteBytes::Reader reads from read_pipe_ (real fd)
//   Module writes → send_arraybuffer() → dc->send(binary)
// ═══════════════════════════════════════════════════════════════════════════

#ifdef WITH_WEBRTC
struct WebRTCChannelImpl {
  // Non-owning shared_ptr: PeerConnection owns the DataChannel.
  // Null deleter so shared_ptr doesn't free it.
  std::shared_ptr<rtc::DataChannel> dc;

  explicit WebRTCChannelImpl(rtc::DataChannel* raw_dc)
    : dc(raw_dc, [](rtc::DataChannel*) {}) {}
};
#else
// Stub pimpl so unique_ptr<WebRTCChannelImpl> can destruct
struct WebRTCChannelImpl {};
#endif

WebRTCChannel::WebRTCChannel(const std::string& peer_id)
  : peer_id_(peer_id.empty() ? "webrtc:unknown" : peer_id)
{
  // Create pipe for read-side fd compatibility
  int pipefd[2];
  if (pipe(pipefd) < 0) {
    syslog(LOG_ERR, "[WebRTCChannel] pipe() failed: %s", strerror(errno));
    return;
  }
  read_pipe_ = pipefd[0];
  write_pipe_ = pipefd[1];
}

std::unique_ptr<WebRTCChannel> WebRTCChannel::create(void* dc_ptr, const std::string& peer_id) {
#ifdef WITH_WEBRTC
  if (!dc_ptr) return nullptr;
  auto ch = std::unique_ptr<WebRTCChannel>(new WebRTCChannel(peer_id));
  ch->impl_ = std::make_unique<WebRTCChannelImpl>(
    static_cast<rtc::DataChannel*>(dc_ptr)
  );
  return ch;
#else
  (void)dc_ptr; (void)peer_id;
  syslog(LOG_WARNING, "[WebRTCChannel] WebRTC not compiled in");
  return nullptr;
#endif
}

WebRTCChannel::~WebRTCChannel() { close(); }

ssize_t WebRTCChannel::write(const uint8_t* data, size_t len) {
  send_arraybuffer(data, len);
  return static_cast<ssize_t>(len);
}

void WebRTCChannel::send_arraybuffer(const uint8_t* data, size_t len) {
#ifdef WITH_WEBRTC
  if (!impl_ || !impl_->dc || !open_.load()) return;
  try {
    // libdatachannel v0.21: send(const std::byte* data, size_t size)
    impl_->dc->send(reinterpret_cast<const std::byte*>(data), len);
  } catch (const std::exception& e) {
    syslog(LOG_WARNING, "[WebRTCChannel] send failed: %s", e.what());
  }
#else
  (void)data; (void)len;
#endif
}

ssize_t WebRTCChannel::read(uint8_t* buf, size_t len) {
  if (read_pipe_ < 0) return -1;
  return ::read(read_pipe_, buf, len);
}

bool WebRTCChannel::is_open() const {
  return open_.load() && read_pipe_ >= 0;
}

void WebRTCChannel::close() {
  open_.store(false);
  if (read_pipe_ >= 0) { ::close(read_pipe_); read_pipe_ = -1; }
  if (write_pipe_ >= 0) { ::close(write_pipe_); write_pipe_ = -1; }
#ifdef WITH_WEBRTC
  impl_.reset();
#endif
}

void WebRTCChannel::on_data_channel_message(const uint8_t* data, size_t len) {
  if (write_pipe_ < 0) return;
  size_t written = 0;
  while (written < len) {
    ssize_t n = ::write(write_pipe_, data + written, len - written);
    if (n <= 0) {
      syslog(LOG_WARNING, "[WebRTCChannel] pipe write failed: %s", strerror(errno));
      break;
    }
    written += n;
  }
}

void WebRTCChannel::on_data_channel_open() {
  open_.store(true);
  syslog(LOG_INFO, "[WebRTCChannel] Data channel open: %s", peer_id_.c_str());
}

void WebRTCChannel::on_data_channel_close() {
  open_.store(false);
  if (write_pipe_ >= 0) { ::close(write_pipe_); write_pipe_ = -1; }
  syslog(LOG_INFO, "[WebRTCChannel] Data channel closed: %s", peer_id_.c_str());
}

// ═══════════════════════════════════════════════════════════════════════════
// PipeChannel
// ═══════════════════════════════════════════════════════════════════════════

PipeChannel::PipeChannel(int read_fd, int write_fd, const std::string& peer_id)
  : read_fd_(read_fd), write_fd_(write_fd), peer_id_(peer_id) {}

PipeChannel::~PipeChannel() { close(); }

ssize_t PipeChannel::write(const uint8_t* data, size_t len) {
  if (write_fd_ < 0) return -1;
  return ::write(write_fd_, data, len);
}

ssize_t PipeChannel::read(uint8_t* buf, size_t len) {
  if (read_fd_ < 0) return -1;
  return ::read(read_fd_, buf, len);
}

void PipeChannel::close() {
  if (read_fd_ >= 0) { ::close(read_fd_); read_fd_ = -1; }
  if (write_fd_ >= 0) { ::close(write_fd_); write_fd_ = -1; }
}

// ═══════════════════════════════════════════════════════════════════════════
// ChannelFactory
// ═══════════════════════════════════════════════════════════════════════════

std::string ChannelFactory::get_channel_type(const nlohmann::json& module_config) {
  if (module_config.contains("settings")) {
    const auto& settings = module_config["settings"];
    if (settings.contains("channel")) {
      return settings["channel"].get<std::string>();
    }
  }
  if (module_config.contains("channel")) {
    return module_config["channel"].get<std::string>();
  }
  return "unix";
}

std::unique_ptr<Channel> ChannelFactory::from_fd(int fd, pid_t peer_pid,
    const std::string& channel_type, const std::string& peer_id) {
  if (channel_type == "tcp") {
    return std::make_unique<TcpChannel>(fd, peer_id, peer_id);
  }
  return std::make_unique<UnixChannel>(fd, peer_pid, peer_id);
}

std::unique_ptr<Channel> ChannelFactory::from_webrtc(void* dc_ptr, const std::string& peer_id) {
  return WebRTCChannel::create(dc_ptr, peer_id);
}

} // namespace NoteDaemon
