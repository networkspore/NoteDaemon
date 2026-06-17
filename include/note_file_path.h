// include/note_file_path.h
// NoteFilePath – Java-style hierarchical ledger (no encryption)
//
// The ledger is a plain NoteBytes::Object that maps path segments to
// actual file paths on disk, forming a tree:
//
//   {
//     "apps": {
//       "config": { "settings": [0x01 → "/data/uuid1.dat"] },
//       "data":   [0x01 → "/data/uuid2.dat"]
//     }
//   }
//
// Where 0x01 (FILE_PATH) marks a terminal file entry.
// This mirrors Java NotePath / NotePathGet / NotePathDelete exactly.

#ifndef NOTE_FILE_PATH_H
#define NOTE_FILE_PATH_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "notebytes.h"
#include "notebytes_reader.h"
#include "notebytes_writer.h"

namespace NoteFileConstants {
    // FILE_PATH marker (matches Java NotePath.FILE_PATH = byte[]{0x01})
    inline const NoteBytes::Value FILE_PATH(std::vector<uint8_t>{0x01});
}

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

// ── Ledger operations (plaintext NoteBytes, no encryption) ───────────────

namespace NoteFileLedger {

    /**
     * Find or create a file path in the ledger.
     * Mirrors Java NotePathGet.
     */
    std::string find_or_create_path(NoteFilePath& path);

    /**
     * Delete a file path from the ledger.
     * Mirrors Java NotePathDelete.
     */
    bool delete_from_path(NoteFilePath& path);

    /**
     * Read ledger file into a NoteBytes::Object.
     */
    NoteBytes::Object read_ledger(const std::string& ledger_path);

    /**
     * Write a NoteBytes::Object as the ledger file.
     */
    bool write_ledger(const std::string& ledger_path,
                      const NoteBytes::Object& obj);

} // namespace NoteFileLedger

#endif
