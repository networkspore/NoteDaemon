// src/core/webrtc_manager.cpp
// WebRTC PeerConnection manager implementation.
//
// Uses libdatachannel (rtc::PeerConnection, rtc::DataChannel) to create
// WebRTC connections. All libdatachannel operations run on a single
// worker thread via the internal work queue. Modules use post_offer()
// which is safe from any thread and returns a std::future.

#include "module_framework/webrtc_manager.h"
#include "module_framework/imodule.h"
#include "module_framework/module_registry.h"
#include <sys/syslog.h>
#include <chrono>
#include <thread>

namespace NoteDaemon {

WebRTCManager::WebRTCManager() {
    worker_running_ = true;
    worker_thread_ = std::thread(&WebRTCManager::worker_loop, this);
    syslog(LOG_DEBUG, "[WebRTCManager] Worker thread started");
}

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

// ── Work queue ──────────────────────────────────────────────────────────────

void WebRTCManager::enqueue(std::function<void()> task, std::promise<void> promise) {
  std::lock_guard<std::mutex> lock(queue_mutex_);
  work_queue_.push({std::move(task), std::move(promise)});
  queue_cv_.notify_one();
}

void WebRTCManager::worker_loop() {
  syslog(LOG_DEBUG, "[WebRTCManager] Worker thread started");
  while (worker_running_) {
    WorkItem item;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      queue_cv_.wait(lock, [this]() {
        return !work_queue_.empty() || !worker_running_;
      });
      if (!worker_running_ && work_queue_.empty()) break;
      item = std::move(work_queue_.front());
      work_queue_.pop();
    }
    // Execute the task
    item.task();
    item.promise.set_value();
  }
  syslog(LOG_DEBUG, "[WebRTCManager] Worker thread stopped");
}

void WebRTCManager::stop_worker() {
  worker_running_ = false;
  queue_cv_.notify_one();
  if (worker_thread_.joinable()) worker_thread_.join();
}

// ── Thread-safe post_offer ──────────────────────────────────────────────────

std::future<std::string> WebRTCManager::post_offer(
    const std::string& sdp_offer,
    const std::string& module_id,
    IModule* target_module)
{
  // Create a packaged_task that wraps handle_offer
  auto result = std::make_shared<std::promise<std::string>>();
  std::future<std::string> future = result->get_future();

  // Capture copies of sdp/module_id for the async call
  std::string sdp = sdp_offer;
  std::string mod = module_id;

  enqueue(
    [this, sdp = std::move(sdp), mod = std::move(mod), target_module, result]() {
      std::string answer = this->handle_offer(sdp, mod, target_module);
      result->set_value(answer);
    },
    std::promise<void>()  // fire-and-forget inner promise
  );

  return future;
}

// ── Direct handle_offer (called from worker thread or management socket) ────

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

  std::string peer_id = module_id + ":" + std::to_string(next_peer_id_++);

  try {
    rtc::Configuration config;
    // config.iceServers.emplace_back("stun:stun.l.google.com:19302");  // disabled for same-machine testing

    auto pc = std::make_shared<rtc::PeerConnection>(config);
    auto state = std::make_shared<PeerState>();
    state->pc = pc;
    state->module_id = module_id;
    state->target_module = target_module;

    std::weak_ptr<PeerState> weak_state = state;

    pc->onDataChannel([weak_state, this](std::shared_ptr<rtc::DataChannel> dc) {
      auto s = weak_state.lock();
      if (!s) return;
      syslog(LOG_INFO, "[WebRTCManager] Incoming data channel %s for %s",
             dc->label().c_str(), s->module_id.c_str());
      s->dc = dc;

      dc->onOpen([weak_state, this]() {
        auto s = weak_state.lock();
        if (!s) return;
        syslog(LOG_INFO, "[WebRTCManager] Data channel open for %s", s->module_id.c_str());
        s->channel = WebRTCChannel::create(static_cast<void*>(s->dc.get()),
          "webrtc:" + s->module_id);
        if (s->channel) {
          s->channel->on_data_channel_open();
          // Route directly to the target module if no external callback
          if (channel_callback_) {
            channel_callback_(s->channel.get(), "webrtc:" + s->module_id);
          } else if (s->target_module) {
            syslog(LOG_INFO, "[WebRTCManager] Direct routing to module=%s", s->module_id.c_str());
            s->target_module->handle_channel(s->channel.get(), "webrtc:" + s->module_id);
          } else if (module_registry_) {
            // Look up module by name from registry
            auto* mod = module_registry_->get(s->module_id);
            if (mod) {
              syslog(LOG_INFO, "[WebRTCManager] Registry routing to module=%s", s->module_id.c_str());
              mod->handle_channel(s->channel.get(), "webrtc:" + s->module_id);
            } else {
              syslog(LOG_WARNING, "[WebRTCManager] Module %s not found in registry", s->module_id.c_str());
            }
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

    std::string answer_sdp;
    bool got_answer = false;
    pc->onLocalDescription([&answer_sdp, &got_answer](rtc::Description desc) {
      answer_sdp = std::string(desc);
      got_answer = true;
    });

    // Collect ICE candidates as they arrive
    std::vector<std::string> ans_cands;
    pc->onLocalCandidate([&ans_cands](rtc::Candidate c) {
        ans_cands.push_back(std::string(c));
    });

    rtc::Description offer(sdp_offer, rtc::Description::Type::Offer);
    pc->setRemoteDescription(offer);

    for (int i = 0; i < 50 && !got_answer; ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (!got_answer) {
      syslog(LOG_WARNING, "[WebRTCManager] Timed out waiting for SDP answer");
      return "";
    }

    // Wait for gathering (up to 3s)
    bool gathered = false;
    pc->onGatheringStateChange([&gathered](rtc::PeerConnection::GatheringState s) {
        if (s == rtc::PeerConnection::GatheringState::Complete) gathered = true;
    });
    for (int i = 0; i < 30 && !gathered; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Append candidates to answer SDP
    if (!ans_cands.empty()) {
        // Remove the final \r\n if present
        if (answer_sdp.size() >= 2 && answer_sdp.substr(answer_sdp.size() - 2) == "\r\n")
            answer_sdp.erase(answer_sdp.size() - 2);
        // Add srflx candidates from onLocalCandidate
        for (const auto& c : ans_cands)
            answer_sdp += "\r\n" + c;
        // Also add a host candidate for the local IP (may not arrive via onLocalCandidate)
        // libjuice should provide this, but just in case:
        answer_sdp += "\r\n";
        syslog(LOG_DEBUG, "[WebRTCManager] Added %zu candidates to answer (srflx)", ans_cands.size());
    } else {
        // No candidates from onLocalCandidate — add a minimal host candidate
        if (answer_sdp.size() >= 2 && answer_sdp.substr(answer_sdp.size() - 2) == "\r\n")
            answer_sdp.erase(answer_sdp.size() - 2);
        answer_sdp += "\r\na=candidate:1 1 UDP 2130706431 127.0.0.1 9 typ host\r\n";
        syslog(LOG_DEBUG, "[WebRTCManager] Added fallback host candidate to answer");
    }

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
  // Stop the worker thread first (no more new work)
  stop_worker();

  // Then clean up all peer connections (on the current thread)
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
