// include/note_file_service.h
// NoteFileService - manages encrypted file handles with path-based ledger
//
// Architecture:
// - Files are identified by path segments (like Java NotePath)
// - An encrypted ledger maps paths to actual file locations on disk
// - All ledger operations are serialized via an internal executor
// - Each file handle provides stream-based access (read/write)
// - Encryption is transparent using the existing IEncryptionProvider
//
// Thread safety:
// - Ledger access is serialized (only one operation at a time)
// - File handle operations are serialized per-file
// - Multiple files can be accessed concurrently

#ifndef NOTE_FILE_SERVICE_H
#define NOTE_FILE_SERVICE_H

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <unordered_map>

#include "note_messaging.h"
#include "notebytes.h"
#include "notebytes_reader.h"
#include "notebytes_writer.h"

#include "module_framework/encryption_api.h"

class NoteFileHandle;
class NoteFilePath;

/**
 * NoteFileConfig - Configuration for the NoteFile service.
 * Mirrors Java NoteFileConfig interface.
 */
struct NoteFileConfig {
    std::string data_directory;   // Directory for .dat files
    std::string ledger_path;      // Path to the encrypted ledger file
    std::vector<uint8_t> encryption_key; // 32-byte AES-256 key
    std::vector<uint8_t> old_key;        // Previous key (for re-encryption)
    
    // Buffer sizes
    size_t pipe_buffer_size = 65536;      // 64KB pipe buffer
    size_t temp_buffer_limit = 8388608;   // 8MB before using temp files
};

/**
 * NoteFileService - Registry and manager for encrypted files.
 *
 * Usage:
 *   auto config = NoteFileConfig{"/path/to/data", "/path/to/ledger", key};
 *   NoteFileService service(config);
 *   
 *   // Get or create a file at path ["my", "settings"]
 *   auto handle = service.get_file({"my", "settings"});
 *   
 *   // Read the file
 *   auto obj = handle->read_object();
 *   
 *   // Write to the file
 *   handle->write_object(my_data);
 */
class NoteFileService : public std::enable_shared_from_this<NoteFileService> {
public:
    /**
     * Create the service with the given configuration.
     * Does NOT initialize the ledger — call init() to set up.
     */
    explicit NoteFileService(const NoteFileConfig& config);

    /**
     * Destructor — cleans up all handles and resources.
     */
    ~NoteFileService();

    // Non-copyable
    NoteFileService(const NoteFileService&) = delete;
    NoteFileService& operator=(const NoteFileService&) = delete;

    // Movable
    NoteFileService(NoteFileService&&) = default;
    NoteFileService& operator=(NoteFileService&&) = default;

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /**
     * Initialize the service.
     * Creates the data directory and ledger if needed.
     * Call once before using the service.
     */
    bool init();

    /**
     * Check if the service is initialized.
     */
    bool is_initialized() const { return initialized_.load(); }

    // =========================================================================
    // FILE OPERATIONS
    // =========================================================================

    /**
     * Get or create a file handle for the given path.
     *
     * The path is an array of NoteBytes::Value segments (strings).
     * If the file exists, returns a handle to it.
     * If the file doesn't exist, it is created when first written to.
     *
     * @param path_segments Path segments (e.g., {"apps", "config", "settings"})
     * @return Shared handle to the file, or nullptr on error
     */
    std::shared_ptr<NoteFileHandle> get_file(
        const std::vector<NoteBytes::Value>& path_segments);

    /**
     * Convenience: get file from string path segments.
     */
    std::shared_ptr<NoteFileHandle> get_file(
        const std::vector<std::string>& path_segments);

    /**
     * Delete a file at the given path.
     *
     * @param path_segments Path to the file to delete
     * @param recursive If true, delete all children as well
     * @return true if successful
     */
    bool delete_file(const std::vector<NoteBytes::Value>& path_segments,
                     bool recursive = false);

    /**
     * Check if a file exists at the given path.
     */
    bool file_exists(const std::vector<NoteBytes::Value>& path_segments);

    // =========================================================================
    // ENCRYPTION & KEY MANAGEMENT
    // =========================================================================

    /**
     * Update the encryption key for all files.
     * Re-encrypts the ledger and all files with the new key.
     */
    bool update_encryption_key(const std::vector<uint8_t>& new_key);

    /**
     * Verify that a password-derived key is correct.
     */
    bool verify_key(const std::vector<uint8_t>& key);

    /**
     * Get the current encryption key.
     */
    const std::vector<uint8_t>& encryption_key() const { return config_.encryption_key; }

    /**
     * Get the data directory path.
     */
    const std::string& data_directory() const { return config_.data_directory; }

    // =========================================================================
    // FILE PATH LEDGER (internal + friend access)
    // =========================================================================

    /**
     * Resolve a note path to the actual file path on disk.
     * Creates the file entry in the ledger if it doesn't exist.
     */
    std::string resolve_or_create_path(
        const std::vector<NoteBytes::Value>& path_segments);

    /**
     * Perform decryption of a file to a pipe.
     * Returns a file descriptor for reading decrypted content.
     */
    int decrypt_file(const std::string& file_path);

    /**
     * Perform encryption of a file from a pipe.
     * Reads from the pipe, encrypts, and writes to a temp file,
     * then atomically swaps with the original.
     */
    bool encrypt_file_swap(const std::string& file_path, int pipe_fd);

    /**
     * Encrypt data to a new file (for creation).
     */
    bool encrypt_new_file(const std::string& file_path, int pipe_fd);

    // =========================================================================
    // HANDLE REGISTRY
    // =========================================================================

    /**
     * Register a handle (called by NoteFileHandle constructor).
     */
    void register_handle(NoteFileHandle* handle);

    /**
     * Unregister a handle (called by NoteFileHandle destructor).
     */
    void unregister_handle(NoteFileHandle* handle);

    /**
     * Get number of active handles.
     */
    size_t active_handle_count() const;

private:
    // =========================================================================
    // INTERNAL
    // =========================================================================

    /**
     * Generate a new unique data file path.
     */
    std::string generate_data_file_path();

    /**
     * Initialize the ledger file.
     */
    bool init_ledger();

    /**
     * Serialize ledger access operations.
     * Uses a dedicated thread for serialized ledger operations.
     */
    template<typename F>
    auto execute_ledger_op(F&& func) -> decltype(func()) {
        std::lock_guard<std::mutex> lock(ledger_mutex_);
        return func();
    }

    /**
     * Create a pipe pair for streaming.
     */
    bool create_pipe(int& read_fd, int& write_fd);

    NoteFileConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_{false};

    // Ledger access serialization
    mutable std::mutex ledger_mutex_;

    // Handle registry
    mutable std::mutex handles_mutex_;
    std::unordered_map<std::string, std::weak_ptr<NoteFileHandle>> handles_;

    // Encryption provider reference
    NoteDaemon::IEncryptionProvider& encryption_;
};

#endif // NOTE_FILE_SERVICE_H
