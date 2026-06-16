// include/note_file_path.h
// NoteFilePath - Encrypted ledger path traversal for NoteFile system
//
// Mirrors Java NotePath + NotePathFactory + NotePathGet functionality:
// - Parses the encrypted ledger to find/create file path entries
// - Handles nested path traversal (buckets within buckets)
// - Manages file creation and deletion within the ledger
//
// The ledger is an encrypted NoteBytes::Object that maps path segments
// to actual file paths on disk, forming a tree structure:
//
//   root = {
//     "apps": {
//       "config": {
//         "settings": FILE_PATH -> "/data/uuid1.dat"
//       },
//       "data": FILE_PATH -> "/data/uuid2.dat"
//     },
//     "system": {
//       "state": FILE_PATH -> "/data/uuid3.dat"
//     }
//   }

#ifndef NOTE_FILE_PATH_H
#define NOTE_FILE_PATH_H

#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "note_messaging.h"
#include "notebytes.h"
#include "notebytes_reader.h"
#include "notebytes_writer.h"
#include "module_framework/encryption_api.h"

/**
 * Constants matching Java NotePath
 */
namespace NoteFileConstants {
    // Special FILE_PATH marker (0x01 in Java)
    inline const NoteBytes::Value FILE_PATH(std::vector<uint8_t>{0x01});

    // Maximum path segment length before warning
    constexpr size_t PATH_LENGTH_WARNING = 512;
}

/**
 * NoteFilePath - Path traversal state for ledger operations.
 *
 * Tracks traversal state when navigating the encrypted ledger
 * to find or create file path entries.
 */
class NoteFilePath {
public:
    /**
     * Create a path traversal state.
     *
     * @param ledger_path Path to the encrypted ledger file
     * @param target_path Path segments to find/create
     * @param data_dir Directory for new .dat files
     * @param recursive Whether to recursively delete children
     */
    NoteFilePath(const std::string& ledger_path,
                 const std::vector<NoteBytes::Value>& target_path,
                 const std::string& data_dir,
                 bool recursive = false);

    /**
     * Get the target path segments.
     */
    const std::vector<NoteBytes::Value>& target_path() const { return target_path_; }

    /**
     * Get the current path segment being searched.
     */
    const NoteBytes::Value& current_path_key() const;

    /**
     * Get the current depth level in the path.
     */
    int current_level() const { return current_level_; }

    /**
     * Get the total depth (number of path segments).
     */
    int depth() const { return static_cast<int>(target_path_.size()); }

    /**
     * Check if we've reached the target depth.
     */
    bool at_target_depth() const { return current_level_ >= depth(); }

    /**
     * Get the resolved file path (if found/created).
     */
    const std::string& resolved_file_path() const { return resolved_path_; }

    /**
     * Set the resolved file path.
     */
    void set_resolved_file_path(const std::string& path) { resolved_path_ = path; }

    /**
     * Get the ledger path.
     */
    const std::string& ledger_path() const { return ledger_path_; }

    /**
     * Get the data directory.
     */
    const std::string& data_dir() const { return data_dir_; }

    /**
     * Check if recursive deletion is enabled.
     */
    bool is_recursive() const { return recursive_; }

    /**
     * Generate a new unique data file path in the data directory.
     */
    std::string generate_data_file_path() const;

    /**
     * Create a FILE_PATH pair for insertion into the ledger.
     *
     * @param path_index Current index in the target path
     * @param result_file_path The actual file path to store
     * @return NoteBytes::Pair representing the path entry
     */
    NoteBytes::Pair create_file_path_pair(int path_index,
                                          const std::string& result_file_path) const;

    // =========================================================================
    // TRAVERSAL HELPERS
    // =========================================================================

    /**
     * Increment the current level (entering a nested bucket).
     */
    void push_level() { current_level_++; }

    /**
     * Decrement the current level (leaving a nested bucket).
     */
    void pop_level() { current_level_--; }

    /**
     * Reset traversal to initial state.
     */
    void reset() {
        current_level_ = 0;
        resolved_path_.clear();
        byte_counter_ = 0;
        deleted_length_ = 0;
    }

    /**
     * Get the byte counter for tracking position in the ledger.
     */
    int64_t byte_counter() const { return byte_counter_; }

    /**
     * Add bytes to the counter.
     */
    void add_bytes(int64_t n) { byte_counter_ += n; }

    /**
     * Set the byte counter.
     */
    void set_byte_counter(int64_t n) { byte_counter_ = n; }

    /**
     * Get the total deleted bytes length (for size adjustment).
     */
    int64_t deleted_length() const { return deleted_length_; }

    /**
     * Add to deleted length.
     */
    void add_deleted_length(int64_t n) { deleted_length_ += n; }

private:
    std::string ledger_path_;
    std::vector<NoteBytes::Value> target_path_;
    std::string data_dir_;
    bool recursive_;

    int current_level_ = 0;
    std::string resolved_path_;
    int64_t byte_counter_ = 0;
    int64_t deleted_length_ = 0;
};

// =========================================================================
// LEDGER OPERATIONS
// =========================================================================

/**
 * Namespace for ledger read/write operations.
 * Mirrors Java NotePathGet, NotePathDelete, NotePathReEncryption.
 */
namespace NoteFileLedger {

    /**
     * Find or create a file path in the ledger.
     *
     * If the path exists, returns the associated file path.
     * If not, creates the path structure and returns a new file path.
     *
     * @param path The NoteFilePath state
     * @param encryption_key 32-byte AES key for decrypting/encrypting the ledger
     * @return The resolved file path, or empty on error
     */
    std::string find_or_create_path(NoteFilePath& path,
                                    const std::vector<uint8_t>& encryption_key);

    /**
     * Delete a file path from the ledger.
     *
     * @param path The NoteFilePath state
     * @param encryption_key 32-byte AES key
     * @return true if successful
     */
    bool delete_from_path(NoteFilePath& path,
                          const std::vector<uint8_t>& encryption_key);

    /**
     * Re-encrypt the ledger with a new key.
     * Also re-encrypts all referenced data files.
     *
     * @param ledger_path Path to the ledger file
     * @param old_key Current encryption key
     * @param new_key New encryption key
     * @param callback Progress callback (optional)
     * @return true if successful
     */
    bool re_encrypt_ledger(const std::string& ledger_path,
                           const std::vector<uint8_t>& old_key,
                           const std::vector<uint8_t>& new_key,
                           std::function<void(int64_t, int64_t)> callback = nullptr);

    /**
     * Parse the ledger to collect all referenced file paths.
     *
     * @param ledger_path Path to the ledger file
     * @param encryption_key Current encryption key
     * @return List of file paths referenced in the ledger
     */
    std::vector<std::string> collect_file_paths(
        const std::string& ledger_path,
        const std::vector<uint8_t>& encryption_key);

} // namespace NoteFileLedger

#endif // NOTE_FILE_PATH_H
