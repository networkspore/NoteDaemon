// include/note_file_service.h
// NoteFileService - encrypted file registry + auth provider
//
// Architecture:
//   Two-socket model with integrated authentication:
//
//   Management socket:
//     - Auth: AUTH (password proof) → session token + derived key
//     - CRUD: QUERY_FILES, CLAIM_FILE, RELEASE_FILE, DELETE_FILE
//     - Key management: CHANGE_PASSWORD
//
//   Data channel (Unix/TCP/WebRTC via Channel abstraction):
//     - Stream NoteBytes reads and writes for claimed files
//
//   The service is initialized in main.cpp alongside WebRTCManager.
//   Modules can access it via NoteDaemon::get_file_service().
//
// Auth flow:
//   1. Client sends AUTH with password-derived proof (bcrypt)
//   2. Service validates against stored bcrypt hash
//   3. On success, derives AES key from password + salt (PBKDF2)
//   4. AES key is used for transparent file encryption
//   5. Client gets a session and access to files

#ifndef NOTE_FILE_SERVICE_H
#define NOTE_FILE_SERVICE_H

#include <atomic>
#include <functional>
#include <map>
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

/**
 * AuthToken - session token for authenticated clients.
 */
struct AuthToken {
    std::string session_id;        // Unique session identifier
    pid_t client_pid;               // Client process ID
    std::vector<uint8_t> derived_key; // 32-byte AES key for file ops
    uint64_t created_at_ms;         // Creation timestamp
    bool valid = true;
};

/**
 * NoteFileConfig - Configuration for the file service.
 */
struct NoteFileConfig {
    std::string data_directory;     // Where .dat files live
    std::string ledger_path;        // Path to the encrypted path ledger
    std::string settings_path;      // Path to settings.dat (auth data)
    std::vector<uint8_t> default_encryption_key; // Fallback key (256-bit)
    size_t pipe_buffer_size = 65536;
};

/**
 * NoteFileService - manages encrypted files, path ledger, and auth.
 *
 * Core service initialised in main.cpp. Provides:
 * - Password-based authentication
 * - Encrypted file storage with path-based ledger
 * - Stream-based file access over any Channel transport
 * - Key management (password change, re-encryption)
 */
class NoteFileService : public std::enable_shared_from_this<NoteFileService> {
public:
    explicit NoteFileService(const NoteFileConfig& config);
    ~NoteFileService();

    NoteFileService(const NoteFileService&) = delete;
    NoteFileService& operator=(const NoteFileService&) = delete;

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /**
     * Initialise the service.
     * Creates data directory, initialises ledger.
     * Must be called before any other method.
     */
    bool init();

    bool is_initialized() const { return initialized_.load(); }

    // =========================================================================
    // AUTHENTICATION
    // =========================================================================

    /**
     * Stored auth data (from settings.dat with empty password on first boot).
     */
    struct AuthData {
        std::vector<uint8_t> bcrypt_hash;  // Stored bcrypt hash
        std::vector<uint8_t> salt;         // Salt for key derivation
        bool has_password = false;          // Whether a password is set
    };

    /**
     * Authenticate a client.
     *
     * @param password Proof string (the password) to verify
     * @param client_pid Client process ID
     * @return AuthToken on success, nullptr on failure
     */
    std::unique_ptr<AuthToken> authenticate(const std::string& password,
                                            pid_t client_pid);

    /**
     * Set initial password (first-time setup).
     * Creates bcrypt hash, salt, and derives the encryption key.
     */
    bool set_initial_password(const std::string& password);

    /**
     * Change password (requires old password verification).
     * Derives new key, re-encrypts ledger + all files.
     */
    bool change_password(const std::string& old_password,
                         const std::string& new_password);

    /**
     * Check if a password has been set.
     */
    bool has_password() const;

    /**
     * Invalidate a session token.
     */
    void invalidate_token(const std::string& session_id);

    /**
     * Get current encryption key (derived from password).
     */
    const std::vector<uint8_t>& encryption_key() const { return current_key_; }

    // =========================================================================
    // FILE OPERATIONS
    // =========================================================================

    /**
     * Get or create a file handle for the given path.
     *
     * @param path_segments e.g. {"apps", "config", "settings"}
     * @return Shared handle, or nullptr on error
     */
    std::shared_ptr<NoteFileHandle> get_file(
        const std::vector<NoteBytes::Value>& path_segments);

    /** Convenience: string-based path. */
    std::shared_ptr<NoteFileHandle> get_file(
        const std::vector<std::string>& path_segments);

    /**
     * Delete a file at the given path.
     *
     * @param path_segments Path to delete
     * @param recursive If true, delete all children
     * @return true on success
     */
    bool delete_file(const std::vector<NoteBytes::Value>& path_segments,
                     bool recursive = false);

    /**
     * List all file paths in the ledger.
     */
    std::vector<std::string> list_files();

    /**
     * Check if a file exists.
     */
    bool file_exists(const std::vector<NoteBytes::Value>& path_segments);

    // =========================================================================
    // KEY MANAGEMENT
    // =========================================================================

    /**
     * Re-encrypt all files with a new key.
     */
    bool re_encrypt_all(const std::vector<uint8_t>& new_key);

    // =========================================================================
    // INTERNAL (for NoteFileHandle / NoteFilePath)
    // =========================================================================

    /**
     * Resolve a path to an actual file on disk (creates if needed).
     */
    std::string resolve_or_create_path(
        const std::vector<NoteBytes::Value>& path_segments);

    /**
     * Decrypt a file, return a pipe fd for reading plaintext.
     */
    int decrypt_file(const std::string& file_path);

    /**
     * Read from pipe, encrypt, atomically swap with original file.
     */
    bool encrypt_file_swap(const std::string& file_path, int pipe_fd);

    /**
     * Encrypt and write a new file.
     */
    bool encrypt_new_file(const std::string& file_path, int pipe_fd);

    /**
     * Encrypt a data buffer directly to a file (avoids pipe overhead).
     */
    bool encrypt_buffer_to_file(const std::string& file_path,
                                const std::vector<uint8_t>& data);

    /**
     * Decrypt a file directly into a byte buffer.
     */
    std::vector<uint8_t> read_file_to_buffer(const std::string& file_path);

    /** Data directory path. */
    const std::string& data_directory() const { return config_.data_directory; }

private:
    // Load/save auth data from settings file
    bool load_auth_data();
    bool save_auth_data();

    // Derive AES key from password + salt (PBKDF2-compatible)
    std::vector<uint8_t> derive_key(const std::string& password,
                                    const std::vector<uint8_t>& salt) const;

    // Generate bcrypt hash
    std::vector<uint8_t> hash_password(const std::string& password) const;

    // Verify password against bcrypt hash
    bool verify_password(const std::string& password,
                         const std::vector<uint8_t>& hash) const;

    // Generate random salt
    std::vector<uint8_t> generate_salt(size_t length = 16) const;

    // Create a pipe pair
    // NoteFileHandle is a friend and accesses this
    friend class NoteFileHandle;
    bool create_pipe(int& read_fd, int& write_fd);

    // Generate unique file path
    std::string generate_data_file_path();

    NoteFileConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_{false};

    // Auth state
    mutable std::mutex auth_mutex_;
    AuthData auth_data_;
    std::vector<uint8_t> current_key_;     // Current derived AES key
    std::vector<uint8_t> old_key_;          // Previous key (during password change)
    std::unordered_map<std::string, std::unique_ptr<AuthToken>> active_tokens_;
    uint64_t next_session_id_ = 1;

    // Ledger access serialization
    mutable std::mutex ledger_mutex_;

    // Handle registry
    mutable std::mutex handles_mutex_;
    std::unordered_map<std::string, std::weak_ptr<NoteFileHandle>> handles_;

public:
    // Handle registration (called by NoteFileHandle)
    void register_handle(NoteFileHandle* handle);
    void unregister_handle(NoteFileHandle* handle);
    size_t active_handle_count() const;

private:
};

// =========================================================================
// Global accessor (initialized in main.cpp)
// =========================================================================

/**
 * Get the global NoteFileService instance.
 * Set by NoteDaemonApp during startup.
 * Returns nullptr if not initialized.
 */
NoteFileService* get_file_service();

/**
 * Set the global NoteFileService pointer.
 * Called once during daemon startup.
 */
void set_file_service(NoteFileService* service);

#endif // NOTE_FILE_SERVICE_H
