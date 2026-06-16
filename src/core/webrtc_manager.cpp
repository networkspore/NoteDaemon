// src/core/webrtc_manager.cpp
// WebRTC PeerConnection manager implementation.
//
// Uses libdatachannel (rtc::PeerConnection, rtc::DataChannel) to create
// WebRTC connections. The signaling comes through the management socket,
// and once a data channel is open, we wrap it in a WebRTCChannel and
// route it to the target module via the channel_callback_.

#include "module_framework/webrtc_manager.h"
#include "module_framework/imodule.h"
#include <sys/syslog.h>
#include <chrono>
#include <thread>

namespace NoteDaemon {

WebRTCManager::WebRTCManager() {}

WebRTCManager::~WebRTCManager() { shutdown(); }

void WebRTCManager::init() {
#ifdef WITH_WEBRTC
  rtc::InitLogger(rtc::LogLevel::Warning);
  rtc::Preload();
  initialized_ = true;
  syslog(LOG_INFO, "[WebRTCManager] Initialized (libdatachannel v0.21)");
#else
  initialized_ = false;
  syslog(LOG_INFO, "[WebRTCManager] Not available (compiled without WITH_WEBRTC)");
#endif
}

void WebRTCManager::set_channel_callback(WebrtcChannelCallback cb) {
  channel_callback_ = std::move(cb);
}

std::string WebRTCManager::handle_offer(const std::string& sdp_offer,
    const std::string& module_id, IModule* target_module) {
#ifdef WITH_WEBRTC
  if (!initialized_) init();
  if (!initialized_) {
    syslog(LOG_ERR, "[WebRTCManager] Cannot handle offer: not initialized");
    return "";
  }

  syslog(LOG_INFO, "[WebRTCManager] Handling SDP offer for module=%s (%zu bytes)",
    module_id.c_str(), sdp_offer.size());

  // Create a unique peer ID for tracking
  std::string peer_id = module_id + ":" + std::to_string(next_peer_id_++);

  try {
    // ── PeerConnection config ──
    rtc::Configuration config;
    // STUN server for NAT traversal (Google's public STUN)
    config.iceServers.emplace_back("stun:stun.l.google.com:19302");
    // For LAN-only, we can also use mDNS candidates

    // ── Create PeerConnection ──
    auto pc = std::make_shared<rtc::PeerConnection>(config);

    auto state = std::make_shared<PeerState>();
    state->pc = pc;
    state->module_id = module_id;
    state->target_module = target_module;

    std::weak_ptr<PeerState> weak_state = state;

    // ── Listen for incoming DataChannel from the browser ──
    // The browser creates the data channel (offerer-initiated).
    // We register callbacks on the incoming channel.
    pc->onDataChannel([weak_state, this](std::shared_ptr<rtc::DataChannel> dc) {
      auto s = weak_state.lock();
      if (!s) return;
      
      syslog(LOG_INFO, "[WebRTCManager] Incoming data channel '%s' from %s",
             dc->label().c_str(), s->module_id.c_str());
      
      s->dc = dc;

      // ── DataChannel callbacks ──
      dc->onOpen([weak_state, this]() {
        auto s = weak_state.lock();
        if (!s) return;
        syslog(LOG_INFO, "[WebRTCManager] Data channel open for %s", s->module_id.c_str());

        // Create WebRTCChannel wrapping this data channel.
        s->channel = WebRTCChannel::create(static_cast<void*>(s->dc.get()),
          "webrtc:" + s->module_id);
        if (s->channel) {
          s->channel->on_data_channel_open();
          // Route to module via callback — the module gets a Channel*
          if (channel_callback_) {
            channel_callback_(s->channel.get(), "webrtc:" + s->module_id);
          }
        }
      });

      dc->onClosed([weak_state]() {
        auto s = weak_state.lock();
        if (!s) return;
        syslog(LOG_INFO, "[WebRTCManager] Data channel closed for %s", s->module_id.c_str());
        if (s->channel) {
          s->channel->on_data_channel_close();
          s->channel.reset();
        }
      });

      dc->onMessage([weak_state](auto data) {
        auto s = weak_state.lock();
        if (!s || !s->channel) return;

        if (std::holds_alternative<std::vector<std::byte>>(data)) {
          auto& bytes = std::get<std::vector<std::byte>>(data);
          s->channel->on_data_channel_message(
            reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
        } else if (std::holds_alternative<std::string>(data)) {
          auto& str = std::get<std::string>(data);
          s->channel->on_data_channel_message(
            reinterpret_cast<const uint8_t*>(str.data()), str.size());
        }
      });
    });

    // ── Wait for the answer to be ready ──
    // libdatachannel generates the answer asynchronously.
    // We poll for it with a timeout.
    // NOTE: Register the callback BEFORE setRemoteDescription to avoid
    // a race condition where the answer is generated before the callback
    // is registered (libdatachannel may generate synchronously).
    std::string answer_sdp;
    bool got_answer = false;

    pc->onLocalDescription([&answer_sdp, &got_answer](rtc::Description desc) {
      answer_sdp = std::string(desc);
      got_answer = true;
    });

    // ── Set remote description (the offer) ──
    rtc::Description offer(sdp_offer, rtc::Description::Type::Offer);
    pc->setRemoteDescription(offer);

    // Wait for ICE gathering + answer generation (up to 5 seconds)
    for (int i = 0; i < 50 && !got_answer; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (!got_answer) {
      syslog(LOG_WARNING, "[WebRTCManager] Timed out waiting for SDP answer");
      return "";
    }

    // Store the peer state
    {
      std::lock_guard<std::mutex> lock(peers_mutex_);
      peers_[peer_id] = state;
    }

    syslog(LOG_INFO, "[WebRTCManager] SDP answer ready for %s (%zu bytes)",
      module_id.c_str(), answer_sdp.size());

    return answer_sdp;

  } catch (const std::exception& e) {
    syslog(LOG_ERR, "[WebRTCManager] Error handling offer: %s", e.what());
    return "";
  }
#else
  (void)sdp_offer; (void)module_id; (void)target_module;
  syslog(LOG_WARNING, "[WebRTCManager] WebRTC not compiled in");
  return "";
#endif
}

void WebRTCManager::shutdown() {
#ifdef WITH_WEBRTC
  std::lock_guard<std::mutex> lock(peers_mutex_);
  for (auto& [id, state] : peers_) {
    if (state->channel) state->channel->close();
    if (state->dc) state->dc->close();
    if (state->pc) state->pc->close();
  }
  peers_.clear();
  syslog(LOG_INFO, "[WebRTCManager] Shutdown complete");
#endif
}

size_t WebRTCManager::active_connections() const {
#ifdef WITH_WEBRTC
  std::lock_guard<std::mutex> lock(peers_mutex_);
  return peers_.size();
#else
  return 0;
#endif
}

} // namespace NoteDaemon
