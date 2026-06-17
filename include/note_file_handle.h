// include/note_file_handle.h
// NoteFileHandle - streamable NoteBytes with an ID
//
// Like a LibUSB USB drive: claim it by ID, then stream data in/out
// through any Channel transport (Unix socket, TCP, WebRTC).
// All operations are serialized per-handle and transparently encrypted.

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

namespace NoteDaemon { class Channel; }

class NoteFileHandle : public std::enable_shared_from_this<NoteFileHandle> {
public:
    class ReadStream {
    public:
        ReadStream(std::unique_ptr<NoteDaemon::Channel> channel,
                   std::shared_ptr<NoteFileHandle> handle);
        NoteBytes::Value read_value();
        NoteBytes::Object read_object();
        std::vector<uint8_t> read_all();
        void close();
        bool is_open() const { return !closed_; }
        ~ReadStream() { close(); }
    private:
        friend class NoteFileHandle;
        std::unique_ptr<NoteBytes::Reader> reader_;
        std::unique_ptr<NoteDaemon::Channel> channel_;
        std::shared_ptr<NoteFileHandle> handle_;
        std::atomic<bool> closed_{false};
    };

    class WriteStream {
    public:
        WriteStream(std::unique_ptr<NoteDaemon::Channel> channel,
                    std::shared_ptr<NoteFileHandle> handle);
        void write_value(const NoteBytes::Value& value);
        void write_object(const NoteBytes::Object& obj);
        void write_raw(const uint8_t* data, size_t length);
        void write_raw(const std::vector<uint8_t>& data) {
            write_raw(data.data(), data.size());
        }
        void flush();
        void close();
        bool is_open() const { return !closed_; }
        ~WriteStream() { close(); }
    private:
        friend class NoteFileHandle;
        std::unique_ptr<NoteBytes::Writer> writer_;
        std::unique_ptr<NoteDaemon::Channel> channel_;
        std::shared_ptr<NoteFileHandle> handle_;
        std::atomic<bool> closed_{false};
    };

    // Public API
    const std::string& id() const { return path_string_; }
    const std::vector<NoteBytes::Value>& path() const { return path_segments_; }

    std::unique_ptr<ReadStream> read_stream(NoteDaemon::Channel* channel);
    std::unique_ptr<WriteStream> write_stream(NoteDaemon::Channel* channel);

    NoteBytes::Object read_object();
    bool write_object(const NoteBytes::Object& obj);
    std::vector<uint8_t> read_bytes();
    bool write_bytes(const uint8_t* data, size_t length);
    bool write_bytes(const std::vector<uint8_t>& data) {
        return write_bytes(data.data(), data.size());
    }

    uint64_t size() const;
    bool exists() const;
    bool is_open() const { return !closed_.load(); }
    void close();
    void force_close();

    /** Client ID for per-client encryption. */
    const std::string& client_id() const { return client_id_; }

    /** Get the encryption key used by this handle (empty = no encryption). */
    const std::vector<uint8_t>& encryption_key() const { return encryption_key_; }

    /** Whether this handle uses encryption. */
    bool has_encryption() const { return !encryption_key_.empty(); }

    // Public so std::make_shared can access it
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
    std::vector<uint8_t> encryption_key_;
    std::weak_ptr<NoteFileService> service_;
    std::atomic<bool> closed_{false};
    std::mutex operation_mutex_;
};

#endif // NOTE_FILE_HANDLE_H
