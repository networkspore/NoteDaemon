// include/note_file_handle.h
// NoteFileHandle - streamable NoteBytes with an ID
// Like a LibUSB USB drive: you claim it by ID, then stream data in/out
// All operations are serialized per-handle for thread safety

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

/**
 * Forward declarations
 */
class NoteFileService;

/**
 * NoteFileHandle - Handle to an encrypted file with stream-based access.
 *
 * Architecture:
 * - Identified by a unique path (array of NoteBytes::Value segments)
 * - Provides read() and write() streams for NoteBytes
 * - All operations are automatically serialized per handle
 * - Encryption is transparent via the service
 * - Like claiming a LibUSB interface, then doing bulk transfers
 *
 * Thread safety:
 * - read() and write() are mutually exclusive per handle
 * - Multiple concurrent reads are allowed
 * - Only one write at a time
 */
class NoteFileHandle : public std::enable_shared_from_this<NoteFileHandle> {
public:
    /**
     * Stream handle for reading file contents.
     * Wraps a NoteBytes::Reader with automatic cleanup.
     */
    class ReadStream {
    public:
        /**
         * Read the next NoteBytes::Value from the stream.
         * Returns empty Value on end of file.
         */
        NoteBytes::Value read_value();

        /**
         * Read the next NoteBytes::Object from the stream.
         * Returns empty Object on end of file.
         */
        NoteBytes::Object read_object();

        /**
         * Read all remaining bytes as raw data.
         */
        std::vector<uint8_t> read_all();

        /**
         * Close the read stream.
         */
        void close();

        /**
         * Check if the stream is open.
         */
        bool is_open() const { return !closed_; }

        ~ReadStream() { close(); }

    private:
        friend class NoteFileHandle;
        ReadStream(int fd, std::shared_ptr<NoteFileHandle> handle);

        std::unique_ptr<NoteBytes::Reader> reader_;
        std::shared_ptr<NoteFileHandle> handle_;
        std::atomic<bool> closed_{false};
        int temp_fd_ = -1;
    };

    /**
     * Stream handle for writing file contents.
     * Wraps a NoteBytes::Writer with automatic cleanup.
     */
    class WriteStream {
    public:
        /**
         * Write a NoteBytes::Value to the stream.
         */
        void write_value(const NoteBytes::Value& value);

        /**
         * Write a NoteBytes::Object to the stream.
         */
        void write_object(const NoteBytes::Object& obj);

        /**
         * Write raw bytes to the stream.
         */
        void write_raw(const uint8_t* data, size_t length);

        void write_raw(const std::vector<uint8_t>& data) {
            write_raw(data.data(), data.size());
        }

        /**
         * Flush any buffered data.
         */
        void flush();

        /**
         * Close the write stream.
         * This commits the data to the encrypted file.
         */
        void close();

        /**
         * Check if the stream is open.
         */
        bool is_open() const { return !closed_; }

        ~WriteStream() { close(); }

    private:
        friend class NoteFileHandle;
        WriteStream(int fd, std::shared_ptr<NoteFileHandle> handle);

        std::unique_ptr<NoteBytes::Writer> writer_;
        std::shared_ptr<NoteFileHandle> handle_;
        std::atomic<bool> closed_{false};
        int temp_fd_ = -1;
    };

    // =========================================================================
    // PUBLIC API
    // =========================================================================

    /**
     * Get the unique identifier for this file handle (the path string).
     */
    const std::string& id() const { return path_string_; }

    /**
     * Get the path segments that identify this file.
     */
    const std::vector<NoteBytes::Value>& path() const { return path_segments_; }

    /**
     * Open a read stream to read the decrypted file contents.
     *
     * Like claiming a USB interface and starting a read transfer.
     * The file is decrypted on-the-fly as you read.
     *
     * @return ReadStream handle, or nullptr if file doesn't exist
     */
    std::unique_ptr<ReadStream> read();

    /**
     * Open a write stream to write encrypted file contents.
     *
     * Like claiming a USB interface and starting a write transfer.
     * The file is encrypted on-the-fly as you write.
     *
     * @return WriteStream handle, or nullptr on error
     */
    std::unique_ptr<WriteStream> write();

    /**
     * Convenience: read the entire file as a NoteBytes::Object.
     * Returns empty Object if file doesn't exist or is empty.
     */
    NoteBytes::Object read_object();

    /**
     * Convenience: write a NoteBytes::Object to the file.
     * Replaces the entire file contents.
     */
    bool write_object(const NoteBytes::Object& obj);

    /**
     * Convenience: read the entire file as raw bytes.
     */
    std::vector<uint8_t> read_bytes();

    /**
     * Convenience: write raw bytes to the file.
     * Replaces the entire file contents.
     */
    bool write_bytes(const uint8_t* data, size_t length);

    bool write_bytes(const std::vector<uint8_t>& data) {
        return write_bytes(data.data(), data.size());
    }

    /**
     * Get the file size in bytes.
     * Returns 0 if the file doesn't exist.
     */
    uint64_t size() const;

    /**
     * Check if the underlying file exists on disk.
     */
    bool exists() const;

    /**
     * Check if the handle is still open (not closed).
     */
    bool is_open() const { return !closed_.load(); }

    /**
     * Close the handle and release resources.
     * After closing, the handle cannot be used for further operations.
     */
    void close();

    /**
     * Force close without waiting for pending operations.
     */
    void force_close();

private:
    friend class NoteFileService;

    // Only created by NoteFileService
    NoteFileHandle(std::string file_path,
                   std::vector<NoteBytes::Value> path_segments,
                   std::string path_string,
                   std::shared_ptr<NoteFileService> service);

    // Internal: get the actual file path on disk
    const std::string& file_path() const { return file_path_; }

    // Internal: execute a read-only operation (decrypt, stream, re-encrypt)
    // Returns a pipe fd for reading decrypted content
    int begin_read();

    // Internal: execute a write-only operation (stream, encrypt, save)
    // Returns a pipe fd for writing plaintext content
    int begin_write();

    // Internal: commit a write (finalize encryption and save)
    bool commit_write(int pipe_fd);

    std::string file_path_;                       // Actual path on disk
    std::vector<NoteBytes::Value> path_segments_; // Path segments
    std::string path_string_;                     // String representation
    std::weak_ptr<NoteFileService> service_;      // Parent service

    std::atomic<bool> closed_{false};
    std::mutex operation_mutex_;                  // Serializes read/write
    
    // Current operation tracking
    std::atomic<bool> read_in_progress_{false};
    std::atomic<bool> write_in_progress_{false};
};

#endif // NOTE_FILE_HANDLE_H
