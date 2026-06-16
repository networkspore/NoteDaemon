// include/note_file_path.h
// NoteFilePath - Encrypted ledger for path-to-file mapping
//
// Mirrors Java NotePath + NotePathFactory:
// The ledger is an encrypted NoteBytes::Object that maps path segments
// to actual file paths on disk, forming a tree:
//
//   {
//     "apps": {
//       "config": { "settings": [0x01 → "/data/uuid1.dat"] },
//       "data":   [0x01 → "/data/uuid2.dat"]
//     }
//   }
//
// Where 0x01 (NoteFileConstants::FILE_PATH) marks a terminal file entry.

#ifndef NOTE_FILE_PATH_H
#define NOTE_FILE_PATH_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "note_messaging.h"
#include "notebytes.h"
#include "notebytes_reader.h"
#include "notebytes_writer.h"

namespace NoteFileConstants {
    // FILE_PATH marker (matches Java NotePath.FILE_PATH = byte[]{0x01})
    inline const NoteBytes::Value FILE_PATH(std::vector<uint8_t>{0x01});

    // Metadata size for NoteBytes values (1 type + 4 length)
    constexpr size_t METADATA_SIZE = 5;
}

/**
 * NoteFilePath - Traversal state for navigating the encrypted ledger.
 *
 * Tracks current position and depth when searching for or creating
 * path entries in the hierarchical ledger structure.
 */
class NoteFilePath {
public:
    NoteFilePath(const std::string& ledger_path,
                 const std::vector<NoteBytes::Value>& target_path,
                 const std::string& data_dir,
                 bool recursive = false);

    const std::vector<NoteBytes::Value>& target_path() const { return target_path_; }
    const NoteBytes::Value& current_path_key() const;
    int current_level() const { return current_level_; }
    int depth() const { return static_cast<int>(target_path_.size()); }
    bool at_target_depth() const { return current_level_ >= depth(); }

    const std::string& resolved_file_path() const { return resolved_path_; }
    void set_resolved_file_path(const std::string& p) { resolved_path_ = p; }

    const std::string& ledger_path() const { return ledger_path_; }
    const std::string& data_dir() const { return data_dir_; }
    bool is_recursive() const { return recursive_; }

    std::string generate_data_file_path() const;
    NoteBytes::Pair create_file_path_pair(int path_index,
                                          const std::string& result_path) const;

    void push_level() { current_level_++; }
    void pop_level() { current_level_--; }
    void reset() {
        current_level_ = 0;
        resolved_path_.clear();
        byte_counter_ = 0;
        deleted_length_ = 0;
    }

    int64_t byte_counter() const { return byte_counter_; }
    void add_bytes(int64_t n) { byte_counter_ += n; }
    void set_byte_counter(int64_t n) { byte_counter_ = n; }

    int64_t deleted_length() const { return deleted_length_; }
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

namespace NoteFileLedger {

    /**
     * Find or create a file path in the encrypted ledger.
     *
     * If the path exists, returns the associated file path on disk.
     * If not, creates the path hierarchy and returns a new UUID file path.
     *
     * @param path Traversal state
     * @param encryption_key 32-byte AES key for ledger
     * @return Resolved file path, or empty on error
     */
    std::string find_or_create_path(NoteFilePath& path,
                                    const std::vector<uint8_t>& encryption_key);

    /**
     * Delete a file path from the ledger.
     *
     * @param path Traversal state
     * @param encryption_key 32-byte AES key
     * @return true on success
     */
    bool delete_from_path(NoteFilePath& path,
                          const std::vector<uint8_t>& encryption_key);

    /**
     * Re-encrypt the ledger and all referenced data files with a new key.
     *
     * @param ledger_path Path to the ledger file
     * @param old_key Current encryption key
     * @param new_key New encryption key
     * @param callback Optional progress callback (processed, total)
     * @return true on success
     */
    bool re_encrypt_ledger(const std::string& ledger_path,
                           const std::vector<uint8_t>& old_key,
                           const std::vector<uint8_t>& new_key,
                           std::function<void(int64_t, int64_t)> callback = nullptr);

    /**
     * Collect all file paths referenced in the ledger.
     */
    std::vector<std::string> collect_file_paths(
        const std::string& ledger_path,
        const std::vector<uint8_t>& encryption_key);

    /**
     * AES-256-GCM encrypt a plaintext file to ciphertext output.
     * Format: [12-byte IV][ciphertext][16-byte tag]
     */
    bool aes_encrypt_file(const std::string& input_path,
                          const std::string& output_path,
                          const std::vector<uint8_t>& key);

    /**
     * AES-256-GCM decrypt a ciphertext file to plaintext output.
     */
    bool aes_decrypt_file(const std::string& input_path,
                          const std::string& output_path,
                          const std::vector<uint8_t>& key);

    /**
     * AES-256-GCM encrypt a byte buffer directly to a file.
     */
    bool aes_encrypt_buffer_to_file(const std::vector<uint8_t>& plaintext,
                                    const std::string& output_path,
                                    const std::vector<uint8_t>& key);

    /**
     * AES-256-GCM decrypt a file directly into a byte vector.
     */
    std::vector<uint8_t> aes_decrypt_to_buffer(const std::string& file_path,
                                                const std::vector<uint8_t>& key);

} // namespace NoteFileLedger

#endif // NOTE_FILE_PATH_H
