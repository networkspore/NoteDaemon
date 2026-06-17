// include/note_file_service.h
// NoteFileService – filesystem-backed auth + zone-isolated storage
//
// Architecture:
//
//   /var/netnotes/data/
//     clients/
//       <client_id>/          ← zone existence = directory exists
//         .auth               ← API key hash (SHA-256 with salt)
//         .ledger             ← NoteBytes path ledger
//         <uuid>.dat          ← actual data files
//
//   No central registry. The filesystem IS the database.
//   Client exists iff `data/clients/<client_id>/` exists.
//
// Management socket handlers:
//   set_admin_api_key  {api_key}        first-boot admin setup
//   admin_auth         {api_key}        admin login
//   add_client         {client_id, api_key}
//   remove_client      {client_id}
//   list_clients
//   client_auth        {client_id, api_key}
//   get_file           {client_id, path}
//   put_file           {client_id, path, data}
//   delete_file        {client_id, path}
//   open_file_stream   {client_id, path, mode}
//   close_stream       {stream_id}

#ifndef NOTE_FILE_SERVICE_H
#define NOTE_FILE_SERVICE_H

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "note_messaging.h"
#include "notebytes.h"
#include "module_framework/channel.h"

class NoteFileHandle;
class NoteFilePath;

// ── Stream session ───────────────────────────────────────────────────────

enum class StreamMode { READ, WRITE };

struct StreamSession {
    std::string stream_id;
    std::string client_id;
    std::shared_ptr<NoteFileHandle> handle;
    StreamMode mode;
    bool active = false;
};

// ── Auth tokens ──────────────────────────────────────────────────────────

struct AdminToken {
    std::string session_id;
    pid_t client_pid = 0;
    uint64_t created_at_ms = 0;
    bool valid = true;
};

struct ClientToken {
    std::string session_id;
    std::string client_id;
    pid_t client_pid = 0;
    uint64_t created_at_ms = 0;
    bool valid = true;
};

// ── Configuration ────────────────────────────────────────────────────────

struct NoteFileConfig {
    std::string data_directory;       // /var/netnotes/data
    std::string admin_key_path;       // /etc/netnotes/admin.key
};

// ── NoteFileService ──────────────────────────────────────────────────────

class NoteFileService : public std::enable_shared_from_this<NoteFileService> {
public:
    explicit NoteFileService(const NoteFileConfig& config);
    ~NoteFileService();
    NoteFileService(const NoteFileService&) = delete;
    NoteFileService& operator=(const NoteFileService&) = delete;

    bool init();
    bool is_initialized() const { return initialized_.load(); }

    // ── Admin ───────────────────────────────────────────────────────────
    bool set_admin_api_key(const std::string& api_key);
    bool verify_admin_api_key(const std::string& api_key) const;
    bool has_admin_api_key() const;
    std::unique_ptr<AdminToken> authenticate_admin(const std::string& api_key,
                                                    pid_t client_pid);
    void invalidate_admin_token(const std::string& sid);

    // ── Clients (filesystem-backed, no registry) ────────────────────────
    bool add_client(const std::string& client_id,
                     const std::string& api_key);
    bool remove_client(const std::string& client_id);
    std::vector<std::string> list_clients() const;
    bool client_exists(const std::string& client_id) const;

    std::unique_ptr<ClientToken> authenticate_client(
        const std::string& client_id,
        const std::string& api_key,
        pid_t client_pid);
    void invalidate_client_token(const std::string& sid);

    // ── File operations ────────────────────────────────────────────────
    std::shared_ptr<NoteFileHandle> get_file(
        const std::string& client_id,
        const std::vector<NoteBytes::Value>& path_segments);
    std::shared_ptr<NoteFileHandle> get_file(
        const std::string& client_id,
        const std::vector<std::string>& segments);

    bool delete_file(const std::string& client_id,
                     const std::vector<NoteBytes::Value>& path,
                     bool recursive = false);

    std::vector<std::string> list_client_files(const std::string& client_id);

    // ── Stream management ──────────────────────────────────────────────
    std::unique_ptr<StreamSession> open_stream(
        const std::string& client_id,
        const std::vector<NoteBytes::Value>& path_segments,
        StreamMode mode);
    StreamSession* get_stream(const std::string& stream_id);
    void close_stream(const std::string& stream_id);
    bool route_channel(const std::string& stream_id,
                       NoteDaemon::Channel* channel);

    // ── Internal ───────────────────────────────────────────────────────
    std::string resolve_or_create_path(
        const std::string& client_id,
        const std::vector<NoteBytes::Value>& path_segments);

    /** Ensure a file path exists in the ledger (for WriteStream recovery). */
    bool ensure_ledger_entry(const std::string& client_id,
                              const std::vector<NoteBytes::Value>& path_segments,
                              const std::string& file_path);
    std::vector<uint8_t> read_file_to_buffer(const std::string& file_path);
    bool write_buffer_to_file(const std::string& file_path,
                               const std::vector<uint8_t>& data);
    std::string client_data_dir(const std::string& client_id) const;
    bool create_pipe(int& r, int& w);
    void register_handle(NoteFileHandle* h);
    void unregister_handle(NoteFileHandle* h);
    size_t active_handle_count() const;

private:
    // Helpers
    std::vector<uint8_t> hash_key(const std::string& key) const;
    bool verify_key(const std::string& key,
                     const std::vector<uint8_t>& hash) const;
    std::string auth_file(const std::string& client_id) const;
    std::string client_ledger_path(const std::string& client_id) const;
    std::string generate_data_file_path(const std::string& client_id) const;
    std::vector<uint8_t> random_bytes(size_t len) const;

    NoteFileConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_{false};

    // Admin
    mutable std::mutex admin_mutex_;
    std::vector<uint8_t> admin_key_hash_;
    std::unordered_map<std::string, std::unique_ptr<AdminToken>> admin_tokens_;

    // Client tokens (in-memory only, .auth is on disk)
    mutable std::mutex client_mutex_;
    std::unordered_map<std::string, std::unique_ptr<ClientToken>> client_tokens_;

    // Stream sessions
    mutable std::mutex streams_mutex_;
    std::unordered_map<std::string, std::unique_ptr<StreamSession>> streams_;

    // Handle registry
    mutable std::mutex handles_mutex_;
    std::unordered_map<std::string, std::weak_ptr<NoteFileHandle>> handles_;

    // Per-client ledger locks (striped, 64 buckets)
    mutable std::mutex ledger_locks_mutex_;
    mutable std::unordered_map<std::string, std::unique_ptr<std::mutex>> ledger_locks_;
    std::mutex& get_ledger_lock(const std::string& client_id) const;
};

// ── Global accessor ──────────────────────────────────────────────────────

NoteFileService* get_file_service();
void set_file_service(NoteFileService* s);

#endif
