// include/note_file_handle.h
// NoteFileHandle – streamable NoteBytes for a client zone file
// Plaintext at rest, protected by API key auth + OS file permissions

#ifndef NOTE_FILE_HANDLE_H
#define NOTE_FILE_HANDLE_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "note_messaging.h"
#include "notebytes.h"
#include "notebytes_reader.h"
#include "notebytes_writer.h"

class NoteFileService;

class NoteFileHandle : public std::enable_shared_from_this<NoteFileHandle> {
public:
    const std::string& id() const { return path_string_; }
    const std::vector<NoteBytes::Value>& path() const { return path_segments_; }
    const std::string& client_id() const { return client_id_; }

    NoteBytes::Object read_object();
    bool write_object(const NoteBytes::Object& obj);
    std::vector<uint8_t> read_bytes();
    bool write_bytes(const uint8_t* data, size_t length);
    bool write_bytes(const std::vector<uint8_t>& d) {
        return write_bytes(d.data(), d.size());
    }

    uint64_t size() const;
    bool exists() const;
    bool is_open() const { return !closed_.load(); }
    void close();
    void force_close();

    NoteFileHandle(std::string file_path,
                   std::vector<NoteBytes::Value> path_segments,
                   std::string path_string,
                   std::string client_id,
                   std::vector<uint8_t> encryption_key,
                   std::shared_ptr<NoteFileService> service);

private:
    friend class NoteFileService;
    const std::string& file_path() const { return file_path_; }

    std::string file_path_;
    std::vector<NoteBytes::Value> path_segments_;
    std::string path_string_;
    std::string client_id_;
    std::vector<uint8_t> encryption_key_;  // unused (cleartext disk I/O)
    std::weak_ptr<NoteFileService> service_;
    std::atomic<bool> closed_{false};
    std::mutex operation_mutex_;
};

#endif
