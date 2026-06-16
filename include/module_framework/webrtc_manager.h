// include/module_framework/webrtc_manager.h
// WebRTC PeerConnection manager for the NoteDaemon core.
//
// When a module declares channel_type = "webrtc", signaling comes
// through the management socket as a "webrtc_offer" command.
// The core intercepts this, creates a PeerConnection via this manager,
// and when the data channel opens, wraps it in a WebRTCChannel and
// routes it to the module's handle_channel().
//
// Flow:
//   1. Browser → POST /api/webrtc/offer → Flask → management socket
//   2. Core sees "webrtc_offer", calls webrtc_manager_.handle_offer()
//   3. Manager creates PeerConnection, sets remote description, creates answer
//   4. Answer written back on management reply_fd
//   5. Data channel opens → manager creates WebRTCChannel
//   6. Core routes WebRTCChannel to module's handle_channel()

#ifndef WEBRTC_MANAGER_H
#define WEBRTC_MANAGER_H

#include <string>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>

#ifdef WITH_WEBRTC
#include <rtc/rtc.hpp>
#endif

#include "module_framework/channel.h"

namespace NoteDaemon {

class IModule; // Forward

// Callback type: when a WebRTC data channel opens and is ready
// to be routed to a module. The channel is owned by WebRTCManager
// (PeerState), so the module gets a non-owning pointer.
using WebrtcChannelCallback =
  std::function<void(Channel* channel, const std::string& device_id)>;

class WebRTCManager {
public:
  WebRTCManager();
  ~WebRTCManager();

  // Set the callback that fires when a data channel opens
  // and is ready to be routed to a module.
  void set_channel_callback(WebrtcChannelCallback cb);

  // Handle an incoming SDP offer for a specific module.
  // Creates a PeerConnection, sets the remote description,
  // and returns the SDP answer as a string.
  //
  // Returns empty string on failure.
  std::string handle_offer(const std::string& sdp_offer,
    const std::string& module_id,
    IModule* target_module);

  // Clean up all PeerConnections
  void shutdown();

  // Get number of active connections (for status)
  size_t active_connections() const;

private:
#ifdef WITH_WEBRTC
  // Internal PeerConnection state
  struct PeerState {
    std::shared_ptr<rtc::PeerConnection> pc;
    std::shared_ptr<rtc::DataChannel> dc;
    std::string module_id;
    IModule* target_module;
    std::unique_ptr<WebRTCChannel> channel;
    std::string answer_sdp; // Filled when answer is ready
  };

  std::unordered_map<std::string, std::shared_ptr<PeerState>> peers_;
  mutable std::mutex peers_mutex_;
  uint64_t next_peer_id_ = 1;
#endif

  WebrtcChannelCallback channel_callback_;
  bool initialized_ = false;

  void init();
};

} // namespace NoteDaemon
#endif // WEBRTC_MANAGER_H
