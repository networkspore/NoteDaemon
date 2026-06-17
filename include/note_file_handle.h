// include/note_file_handle.h
// NoteFileHandle – streamable NoteBytes with zero-buffering Channel I/O

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

class NoteFileService;
namespace NoteDaemon { class Channel; }

class NoteFileHandle : public std::enable_shared_from_this<NoteFileHandle> {
public:
    // ── Read stream – file chunks → Channel ────────────────────────────
    class ReadStream {
    public:
        ReadStream(std::string file_path,
                   std::shared_ptr<NoteFileHandle> handle);
        ~ReadStream();

        /**
         * Stream file content directly into `channel` in 64KB chunks.
         * No buffering — reads from disk, writes to channel.
         */
        void transfer_to(NoteDaemon::Channel* channel);

        void cancel();
        bool is_open() const { return !closed_; }
    private:
        std::string file_path_;
        std::shared_ptr<NoteFileHandle> handle_;
        std::atomic<bool> closed_{false};
    };

    // ── Write stream – Channel chunks → file ───────────────────────────
    class WriteStream {
    public:
        WriteStream(std::string file_path,
                    std::shared_ptr<NoteFileHandle> handle);
        ~WriteStream();

        /**
         * Read chunks from `channel` and write directly to a temp file.
         * On channel close, atomically renames temp → target.
         * No buffering — reads from channel, writes to disk.
         */
        void receive_from(NoteDaemon::Channel* channel);

        void cancel();
        bool is_open() const { return !closed_; }
    private:
        std::string file_path_;
        std::shared_ptr<NoteFileHandle> handle_;
        std::atomic<bool> closed_{false};
    };

    // ── Public API ─────────────────────────────────────────────────────
    const std::string& id() const { return path_string_; }
    const std::vector<NoteBytes::Value>& path() const { return path_segments_; }
    const std::string& client_id() const { return client_id_; }

    // Inline operations (entire file in memory)
    NoteBytes::Object read_object();
    bool write_object(const NoteBytes::Object& obj);
    std::vector<uint8_t> read_bytes();
    bool write_bytes(const uint8_t* data, size_t length);
    bool write_bytes(const std::vector<uint8_t>& d) {
        return write_bytes(d.data(), d.size());
    }

    // Stream operations (zero-buffer, chunked)
    std::unique_ptr<ReadStream> open_read_stream();
    std::unique_ptr<WriteStream> open_write_stream();

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
                   NoteFileService* service);

private:
    friend class NoteFileService;
    const std::string& file_path() const { return file_path_; }

    std::string file_path_;
    std::vector<NoteBytes::Value> path_segments_;
    std::string path_string_;
    std::string client_id_;
    std::vector<uint8_t> encryption_key_;
    NoteFileService* service_;
    std::atomic<bool> closed_{false};
    std::mutex operation_mutex_;
};

#endif
