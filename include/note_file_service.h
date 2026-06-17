// include/note_file_service.h
// NoteFileService – auth + zone-isolated file registry
//
// Architecture:
//
//   ┌────────────────────────────────────────────────────────────┐
//   │  TLS Server Key  (for SSL transport encryption)            │
//   │  /etc/netnotes/server.key  (perm 0600, daemon-owned)       │
//   ├────────────────────────────────────────────────────────────┤
//   │  Admin API Key  (bcrypt-hashed)                           │
//   │  /etc/netnotes/admin.key  (perm 0600)                     │
//   │  Admin manages clients: add/remove/list/change API keys   │
//   ├────────────────────────────────────────────────────────────┤
//   │  Client Registry  (bcrypt-hashed API keys per client)     │
//   │  /etc/netnotes/clients.dat  (perm 0600, plain NoteBytes)  │
//   │  client_id → { api_key_hash, created_at }                 │
//   ├────────────────────────────────────────────────────────────┤
//   │  NoteBytes Zones  (plaintext at rest, permission-protected)│
//   │  /var/netnotes/data/<client_id>/...  (per-client dirs)    │
//   └────────────────────────────────────────────────────────────┘
//
// Management socket handlers:
//   admin_auth           {api_key} → admin session
//   set_admin_api_key    {api_key}  (first boot only)
//   add_client           {api_key, client_id, client_api_key}
//   remove_client        {api_key, client_id}
//   list_clients         {api_key} → client list
//   client_auth          {client_id, api_key} → client session
//   get_file             {client_id, path}
//   put_file             {client_id, path, data}
//   delete_file          {client_id, path}
//
// Data channel (Unix/TCP/WebRTC):
//   Stream NoteBytes for claimed files (plaintext transport,
//   pipe should be over TLS or Unix socket with peer cred)

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

// ── Client entry ─────────────────────────────────────────────────────────

struct ClientEntry {
    std::vector<uint8_t> api_key_hash;  // bcrypt-style hash of client's API key
    uint64_t created_at_ms = 0;
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
    std::string data_directory;       // /var/netnotes/data (per-client subdirs)
    std::string server_key_path;      // /etc/netnotes/server.key (TLS)
    std::string admin_key_path;       // /etc/netnotes/admin.key
    std::string clients_registry;     // /etc/netnotes/clients.dat
};

// ── NoteFileService ──────────────────────────────────────────────────────

class NoteFileService : public std::enable_shared_from_this<NoteFileService> {
public:
    explicit NoteFileService(const NoteFileConfig& config);
    ~NoteFileService();

    NoteFileService(const NoteFileService&) = delete;
    NoteFileService& operator=(const NoteFileService&) = delete;

    // ── Init ────────────────────────────────────────────────────────────

    bool init();
    bool is_initialized() const { return initialized_.load(); }

    // ── Admin API key ───────────────────────────────────────────────────

    bool set_admin_api_key(const std::string& api_key);
    bool verify_admin_api_key(const std::string& api_key) const;
    bool has_admin_api_key() const;

    std::unique_ptr<AdminToken> authenticate_admin(const std::string& api_key,
                                                    pid_t client_pid);
    void invalidate_admin_token(const std::string& session_id);

    // ── Client management (admin only) ──────────────────────────────────

    bool add_client(const std::string& client_id,
                     const std::string& client_api_key);
    bool remove_client(const std::string& client_id);
    std::vector<std::string> list_clients() const;

    // ── Client authentication ───────────────────────────────────────────

    std::unique_ptr<ClientToken> authenticate_client(
        const std::string& client_id,
        const std::string& api_key,
        pid_t client_pid);
    void invalidate_client_token(const std::string& session_id);

    // ── File operations (per-client zone) ───────────────────────────────

    std::shared_ptr<NoteFileHandle> get_file(
        const std::string& client_id,
        const std::vector<NoteBytes::Value>& path_segments);

    std::shared_ptr<NoteFileHandle> get_file(
        const std::string& client_id,
        const std::vector<std::string>& path_segments);

    bool delete_file(const std::string& client_id,
                     const std::vector<NoteBytes::Value>& path,
                     bool recursive = false);

    std::vector<std::string> list_client_files(const std::string& client_id);

    // ── Internal (for NoteFileHandle) ───────────────────────────────────

    std::string resolve_or_create_path(
        const std::string& client_id,
        const std::vector<NoteBytes::Value>& path_segments);

    std::vector<uint8_t> read_file_to_buffer(const std::string& file_path);
    bool write_buffer_to_file(const std::string& file_path,
                               const std::vector<uint8_t>& data);

    std::string client_data_dir(const std::string& client_id) const;
    bool create_pipe(int& read_fd, int& write_fd);

    // ── Handle registry ────────────────────────────────────────────────

    void register_handle(NoteFileHandle* handle);
    void unregister_handle(NoteFileHandle* handle);
    size_t active_handle_count() const;

private:
    // Password hashing
    std::vector<uint8_t> hash_api_key(const std::string& api_key) const;
    bool verify_api_key(const std::string& api_key,
                         const std::vector<uint8_t>& hash) const;

    // Client registry I/O
    bool save_clients_registry();
    bool load_clients_registry();

    // Mics
    std::vector<uint8_t> random_bytes(size_t length) const;
    std::string generate_data_file_path(const std::string& client_id) const;
    std::string client_ledger_path(const std::string& client_id) const;

    NoteFileConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_{false};

    // Admin
    mutable std::mutex admin_mutex_;
    std::vector<uint8_t> admin_api_key_hash_;
    std::unordered_map<std::string, std::unique_ptr<AdminToken>> admin_tokens_;
    uint64_t next_session_ = 1;

    // Clients
    mutable std::mutex clients_mutex_;
    std::unordered_map<std::string, ClientEntry> clients_;
    std::unordered_map<std::string, std::unique_ptr<ClientToken>> client_tokens_;

    // Ledger access
    mutable std::mutex ledger_mutex_;

    // Handle registry
    mutable std::mutex handles_mutex_;
    std::unordered_map<std::string, std::weak_ptr<NoteFileHandle>> handles_;
};

// ── Global accessor ──────────────────────────────────────────────────────

NoteFileService* get_file_service();
void set_file_service(NoteFileService* service);

#endif // NOTE_FILE_SERVICE_H
