// include/module_framework/webrtc_manager.h
// WebRTC PeerConnection manager for the NoteDaemon core.
//
// All libdatachannel operations (handle_offer, shutdown) run on a
// dedicated worker thread via an internal work queue. This ensures
// thread-safe serialization — no direct libdatachannel calls from
// arbitrary module threads.
//
// Modules access the manager via set_webrtc_manager() on IModule.
// They call post_offer() instead of handle_offer() — it's safe from
// any thread and returns a std::future for the SDP answer.
//
// Flow:
//   1. Browser → POST /api/webrtc/offer → http.so → post_offer()
//   2. Worker thread dequeues → handle_offer_internal()
//   3. Creates PeerConnection, sets remote description, creates answer
//   4. Answer returned via future
//   5. Data channel opens → manager creates WebRTCChannel
//   6. Core routes WebRTCChannel to module's handle_channel()

#ifndef WEBRTC_MANAGER_H
#define WEBRTC_MANAGER_H

#include <string>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <queue>
#include <thread>
#include <atomic>
#include <future>
#include <condition_variable>

#ifdef WITH_WEBRTC
#include <rtc/rtc.hpp>
#endif

#include "module_framework/channel.h"

namespace NoteDaemon {

class IModule; // Forward
class ModuleRegistry; // Forward

// Callback type: when a WebRTC data channel opens and is ready
// to be routed to a module.
using WebrtcChannelCallback =
  std::function<void(Channel* channel, const std::string& device_id)>;

class WebRTCManager {
public:
  WebRTCManager();
  ~WebRTCManager();

  // Set the callback that fires when a data channel opens.
  void set_channel_callback(WebrtcChannelCallback cb);
  void set_module_registry(ModuleRegistry* reg) { module_registry_ = reg; }

  // ── Direct call (core use only — called from management socket thread) ────
  // Creates a PeerConnection and returns the SDP answer.
  // NOT thread-safe with libdatachannel internals — only call from
  // the management socket handler or the work queue thread.
  std::string handle_offer(const std::string& sdp_offer,
    const std::string& module_id,
    IModule* target_module);

  // ── Thread-safe post (module use — safe from any thread) ─────────────────
  // Posts a handle_offer request to the internal work queue.
  // Returns a future that resolves with the SDP answer (empty on failure).
  // The work is processed sequentially on a single worker thread.
  std::future<std::string> post_offer(const std::string& sdp_offer,
                                       const std::string& module_id,
                                       IModule* target_module);

  // Clean up all PeerConnections and stop the worker thread.
  void shutdown();

  // Get number of active connections (for status).
  size_t active_connections() const;

private:
#ifdef WITH_WEBRTC
  struct PeerState {
    std::shared_ptr<rtc::PeerConnection> pc;
    std::shared_ptr<rtc::DataChannel> dc;
    std::string module_id;
    IModule* target_module;
    std::shared_ptr<WebRTCChannel> channel;
    std::string answer_sdp;
  };

  std::unordered_map<std::string, std::shared_ptr<PeerState>> peers_;
  mutable std::mutex peers_mutex_;
  uint64_t next_peer_id_ = 1;
#endif

  WebrtcChannelCallback channel_callback_;
  ModuleRegistry* module_registry_ = nullptr;
  bool initialized_ = false;

  void init();

  // ── Work queue for thread-safe module access ──────────────────────────────
  struct WorkItem {
    std::function<void()> task;
    std::promise<void> promise;
  };
  std::queue<WorkItem> work_queue_;
  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;
  std::thread worker_thread_;
  std::atomic<bool> worker_running_{false};

  void worker_loop();
  void enqueue(std::function<void()> task, std::promise<void> promise);
  void stop_worker();
};

} // namespace NoteDaemon
#endif // WEBRTC_MANAGER_H
