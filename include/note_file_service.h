// include/note_file_service.h
// NoteFileService – encrypted file registry + three-layer auth
//
// Architecture:
//
//   ┌──────────────────────────────────────────────────────────┐
//   │  1. Server Key Pair  (Ed25519, on disk, perm 0600)       │
//   │     Root of trust – only this daemon instance            │
//   │     /etc/netnotes/server.key                             │
//   ├──────────────────────────────────────────────────────────┤
//   │  2. Admin API Key   (bcrypt-hashed)                      │
//   │     Admin "solves" it to authenticate                    │
//   │     Can: SET_LOCKER_PASSWORD, ADD/REMOVE/LIST_CLIENTS    │
//   │     Can: CHANGE_CLIENT_PASSWORD (triggers re-encrypt)    │
//   ├──────────────────────────────────────────────────────────┤
//   │  3. Key Locker      (encrypted with locker key)          │
//   │     Locker key = HKDF( server_sk , locker_password )     │
//   │     Stores per-client { bcrypt, salt, encrypt_key }      │
//   │     Client encryption is OPTIONAL – opt-in per client    │
//   └──────────────────────────────────────────────────────────┘
//
// Management socket handlers:
//   ADMIN_AUTH      {api_key} → admin session
//   SET_LOCKER_PW   {api_key, password} → sets locker password
//   CHANGE_LOCKER_PW {api_key, old_pw, new_pw}
//   ADD_CLIENT      {api_key, client_id, password?}
//   REMOVE_CLIENT   {api_key, client_id}
//   LIST_CLIENTS    {api_key} → client list
//   CHANGE_CLIENT_PW {api_key, client_id, old_pw, new_pw}
//   GET_FILE        {client_id, path}
//   PUT_FILE        {client_id, path, data}
//   DELETE_FILE     {client_id, path}
//   QUERY_FILES     {client_id} → file list
//
// Data channel (Unix/TCP/WebRTC):
//   Stream NoteBytes for claimed files, encrypted with client's key

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
#include "notebytes_reader.h"
#include "notebytes_writer.h"
#include "module_framework/channel.h"
#include "module_framework/encryption_api.h"

class NoteFileHandle;
class NoteFilePath;

// ── Server key pair ──────────────────────────────────────────────────────

struct ServerKeyPair {
    std::vector<uint8_t> private_key;   // Ed25519 seed (32 bytes)
    std::vector<uint8_t> public_key;    // Ed25519 public (32 bytes)
};

// ── Per-client auth data stored inside the key locker ────────────────────

struct ClientEntry {
    std::vector<uint8_t> bcrypt_hash;         // bcrypt of client's password
    std::vector<uint8_t> salt;                // salt for key derivation
    std::vector<uint8_t> encryption_key;      // 32-byte AES key
    std::vector<uint8_t> old_bcrypt_hash;     // during password change
    std::vector<uint8_t> old_salt;
    std::vector<uint8_t> old_encryption_key;
    bool has_encryption = false;              // opt-in

    bool has_old() const {
        return !old_bcrypt_hash.empty() && !old_salt.empty();
    }
};

// ── Auth token (returned on admin auth) ──────────────────────────────────

struct AdminToken {
    std::string session_id;
    pid_t client_pid = 0;
    uint64_t created_at_ms = 0;
    bool valid = true;
};

// ── Key locker (in-memory representation) ────────────────────────────────

struct KeyLocker {
    std::vector<uint8_t> salt;                   // random salt for locker key derivation
    std::vector<uint8_t> wrapped_locker_key;     // locker_key encrypted with server key
    std::vector<uint8_t> auth_tag;               // GCM auth tag for locker integrity
    std::unordered_map<std::string, ClientEntry> clients;
};

// ── Configuration ────────────────────────────────────────────────────────

struct NoteFileConfig {
    std::string data_directory;          // where .dat files live
    std::string ledger_path;             // path ledger
    std::string server_key_path;         // /etc/netnotes/server.key
    std::string key_locker_path;         // /etc/netnotes/key_locker.dat
    std::string admin_api_key_path;      // /etc/netnotes/admin_api_key
    size_t pipe_buffer_size = 65536;
};

// ── NoteFileService ──────────────────────────────────────────────────────

class NoteFileService : public std::enable_shared_from_this<NoteFileService> {
public:
    explicit NoteFileService(const NoteFileConfig& config);
    ~NoteFileService();

    NoteFileService(const NoteFileService&) = delete;
    NoteFileService& operator=(const NoteFileService&) = delete;

    // ── Initialization ──────────────────────────────────────────────────

    bool init();
    bool is_initialized() const { return initialized_.load(); }

    // ── Server key ──────────────────────────────────────────────────────

    const ServerKeyPair& server_key() const { return server_key_; }

    // ── Admin API key ───────────────────────────────────────────────────

    bool set_admin_api_key(const std::string& api_key);
    bool verify_admin_api_key(const std::string& api_key) const;
    bool has_admin_api_key() const;

    // ── Admin authentication ────────────────────────────────────────────

    std::unique_ptr<AdminToken> authenticate_admin(const std::string& api_key,
                                                    pid_t client_pid);
    void invalidate_admin_token(const std::string& session_id);

    // ── Key locker ──────────────────────────────────────────────────────

    bool set_locker_password(const std::string& password);
    bool change_locker_password(const std::string& old_pw,
                                 const std::string& new_pw);
    bool has_locker_password() const { return !locker_key_.empty(); }

    // ── Client management (requires authenticated admin session) ────────

    bool add_client(const std::string& client_id,
                    const std::string& password = "");
    bool remove_client(const std::string& client_id);
    std::vector<std::string> list_clients() const;

    bool change_client_password(const std::string& client_id,
                                 const std::string& old_password,
                                 const std::string& new_password);

    bool client_has_encryption(const std::string& client_id) const;

    // ── Per-client encryption key access ────────────────────────────────

    /** Get the client's current encryption key (empty if no encryption). */
    std::vector<uint8_t> get_client_key(const std::string& client_id) const;

    /** Get the client's key and authenticate them. */
    struct ClientAuthResult {
        std::vector<uint8_t> key;
        bool authenticated = false;
    };
    ClientAuthResult authenticate_client(const std::string& client_id,
                                          const std::string& password);

    // ── File operations (per-client) ────────────────────────────────────

    std::shared_ptr<NoteFileHandle> get_file(
        const std::string& client_id,
        const std::vector<NoteBytes::Value>& path_segments);

    std::shared_ptr<NoteFileHandle> get_file(
        const std::string& client_id,
        const std::vector<std::string>& path_segments);

    bool delete_file(const std::string& client_id,
                     const std::vector<NoteBytes::Value>& path_segments,
                     bool recursive = false);

    std::vector<std::string> list_files(const std::string& client_id);

    // ── Internal (for NoteFileHandle / NoteFilePath) ────────────────────

    std::string resolve_or_create_path(
        const std::string& client_id,
        const std::vector<NoteBytes::Value>& path_segments);

    /** Decrypt file using a specific key. */
    std::vector<uint8_t> read_file_to_buffer(const std::string& file_path,
                                              const std::vector<uint8_t>& key);

    /** Encrypt buffer to file using a specific key. */
    bool encrypt_buffer_to_file(const std::string& file_path,
                                 const std::vector<uint8_t>& data,
                                 const std::vector<uint8_t>& key);

    /** Create a pipe pair. */
    bool create_pipe(int& read_fd, int& write_fd);

    const std::string& data_directory() const { return config_.data_directory; }

    // ── Handle registry ────────────────────────────────────────────────

    void register_handle(NoteFileHandle* handle);
    void unregister_handle(NoteFileHandle* handle);
    size_t active_handle_count() const;

private:
    // Server key
    bool load_or_generate_server_key();
    bool save_server_key();
    std::vector<uint8_t> wrap_with_server_key(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> unwrap_with_server_key(const std::vector<uint8_t>& wrapped) const;

    // Key locker I/O
    bool save_key_locker();
    bool load_key_locker();

    // Derive locker key from password + server key
    std::vector<uint8_t> derive_locker_key(const std::string& password) const;

    // Password utility
    std::vector<uint8_t> hash_password(const std::string& password) const;
    bool verify_password(const std::string& password,
                         const std::vector<uint8_t>& hash) const;
    std::vector<uint8_t> derive_key(const std::string& password,
                                     const std::vector<uint8_t>& salt) const;
    std::vector<uint8_t> generate_salt(size_t length = 16) const;
    std::vector<uint8_t> random_bytes(size_t length) const;

    // File path per client (each client gets a subdirectory)
    std::string client_data_dir(const std::string& client_id) const;
    std::string client_ledger_path(const std::string& client_id) const;
    std::string generate_data_file_path(const std::string& client_id) const;

    NoteFileConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_{false};

    // Server key pair
    ServerKeyPair server_key_;

    // Admin API key
    mutable std::mutex admin_mutex_;
    std::vector<uint8_t> admin_api_key_hash_;
    std::unordered_map<std::string, std::unique_ptr<AdminToken>> admin_tokens_;
    uint64_t next_session_id_ = 1;

    // Key locker
    mutable std::mutex locker_mutex_;
    KeyLocker locker_;
    std::vector<uint8_t> locker_key_;   // derived from password + server key

    // Ledger access serialization
    mutable std::mutex ledger_mutex_;

    // Handle registry
    mutable std::mutex handles_mutex_;
    std::unordered_map<std::string, std::weak_ptr<NoteFileHandle>> handles_;
};

// ── Global accessor ──────────────────────────────────────────────────────

NoteFileService* get_file_service();
void set_file_service(NoteFileService* service);

#endif // NOTE_FILE_SERVICE_H
