// include/notebytes_writer.h
// C++ NoteBytes Writer - standardized serialization with predictable metadata
// Matches Java NoteBytesWriter behavior

#ifndef NOTEBYTES_WRITER_H
#define NOTEBYTES_WRITER_H

#include "notebytes.h"
#include <sys/socket.h>
#include <sys/syslog.h>
#include <unistd.h>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace NoteBytes {

/**
 * Metadata structure - always 5 bytes
 * [1-byte type][4-byte length in big-endian]
 */
struct MetaData {
    uint8_t type;
    uint32_t length;
    
    MetaData(uint8_t t, uint32_t len) : type(t), length(len) {}
    
    static constexpr size_t SIZE = 5;
    
    /**
     * Write metadata to buffer
     */
    size_t write_to(uint8_t* buffer, size_t offset = 0) const {
        buffer[offset++] = type;
        buffer[offset++] = (length >> 24) & 0xFF;
        buffer[offset++] = (length >> 16) & 0xFF;
        buffer[offset++] = (length >> 8) & 0xFF;
        buffer[offset++] = length & 0xFF;
        return offset;
    }
    
    /**
     * Read metadata from buffer
     */
    static MetaData read_from(const uint8_t* buffer, size_t& offset) {
        uint8_t type = buffer[offset++];
        uint32_t length = (static_cast<uint32_t>(buffer[offset]) << 24) |
                         (static_cast<uint32_t>(buffer[offset + 1]) << 16) |
                         (static_cast<uint32_t>(buffer[offset + 2]) << 8) |
                         static_cast<uint32_t>(buffer[offset + 3]);
        offset += 4;
        return MetaData(type, length);
    }
};

/**
 * NoteBytesWriter - standardized writer for NoteBytes protocol
 * Ensures all writes follow the [type][length][data] format
 * 
 * Usage:
 *   NoteBytesWriter writer(socket_fd);
 *   writer.write(value);
 *   writer.flush();
 */
class Writer {
private:
    int fd_;
    std::vector<uint8_t> buffer_;
    bool owns_fd_;
    
public:
    /**
     * Create writer for file descriptor
     * @param fd File descriptor (socket, file, etc.)
     * @param owns_fd If true, closes fd on destruction
     */
    explicit Writer(int fd, bool owns_fd = false) 
        : fd_(fd), owns_fd_(owns_fd) {
        buffer_.reserve(8192);  // Pre-allocate reasonable size
    }
    
    ~Writer() {
        try {
            flush();
            if (owns_fd_ && fd_ >= 0) {
                close(fd_);
            }
        } catch (...) {
            // Suppress exceptions in destructor
        }
    }
    
    // Non-copyable
    Writer(const Writer&) = delete;
    Writer& operator=(const Writer&) = delete;
    
    // Movable
    Writer(Writer&& other) noexcept 
        : fd_(other.fd_), buffer_(std::move(other.buffer_)), 
          owns_fd_(other.owns_fd_) {
        other.fd_ = -1;
        other.owns_fd_ = false;
    }
    
    /**
     * Write a NoteBytes Value with full metadata
     * Format: [1-byte type][4-byte length][data]
     * @return Number of bytes written to buffer
     */
    size_t write(const Value& value) {
        MetaData meta(value.type(), value.size());
        
        size_t old_size = buffer_.size();
        buffer_.resize(old_size + MetaData::SIZE + value.size());
        
        size_t offset = old_size;
        offset = meta.write_to(buffer_.data(), offset);
        
        if (value.size() > 0) {
            memcpy(buffer_.data() + offset, value.data().data(), value.size());
        }
        
        return MetaData::SIZE + value.size();
    }
    
    /**
     * Write just metadata (useful for custom protocols)
     * @return Number of bytes written (always 5)
     */
    size_t write_metadata(const MetaData& meta) {
        size_t old_size = buffer_.size();
        buffer_.resize(old_size + MetaData::SIZE);
        meta.write_to(buffer_.data(), old_size);
        return MetaData::SIZE;
    }
    
    /**
     * Write raw data without metadata (for custom use)
     * @return Number of bytes written
     */
    size_t write_raw(const uint8_t* data, size_t length) {
        buffer_.insert(buffer_.end(), data, data + length);
        return length;
    }
    
    size_t write_raw(const std::vector<uint8_t>& data) {
        return write_raw(data.data(), data.size());
    }
    
    /**
     * Write a key-value pair
     * @return Number of bytes written
     */
    size_t write(const Pair& pair) {
        return write(pair.key()) + write(pair.value());
    }
    
    /**
     * Write two values as a pair
     * @return Number of bytes written
     */
    size_t write_pair(const Value& key, const Value& value) {
        return write(key) + write(value);
    }
    
    /**
     * Write an Object with full metadata
     * Format: [0x0C][length][pairs...]
     * @return Number of bytes written
     */
    size_t write(const Object& obj) {
        auto body = obj.serialize();
        MetaData meta(Type::OBJECT, body.size());
        
        size_t written = write_metadata(meta);
        written += write_raw(body);
        return written;
    }
    
    /**
     * Write an Array with full metadata
     * Format: [0x0D][length][values...]
     * @return Number of bytes written
     */
    size_t write(const Array& arr) {
        auto body = arr.serialize();
        MetaData meta(Type::ARRAY, body.size());
        
        size_t written = write_metadata(meta);
        written += write_raw(body);
        return written;
    }
    
    /**
     * Write all values from an array
     * @return Number of bytes written
     */
    size_t write_array_values(const Array& arr) {
        size_t total = 0;
        for (const auto& val : arr.values()) {
            total += write(val);
        }
        return total;
    }
    
    /**
     * Flush buffered data to file descriptor
     * @return Number of bytes flushed
     */
    size_t flush() {
        if (buffer_.empty()) {
            return 0;
        }
        
        ssize_t written = ::write(fd_, buffer_.data(), buffer_.size());
        if (written < 0) {
            throw std::runtime_error("Failed to write to fd: " + 
                                   std::string(strerror(errno)));
        }
        
        if (static_cast<size_t>(written) != buffer_.size()) {
            throw std::runtime_error("Incomplete write to fd");
        }
        
        size_t count = buffer_.size();
        buffer_.clear();
        return count;
    }
    
    /**
     * Get current buffer size (unflushed bytes)
     */
    size_t buffered_size() const {
        return buffer_.size();
    }
    
    /**
     * Clear buffer without flushing
     */
    void clear() {
        buffer_.clear();
    }
    
    /**
     * Get underlying file descriptor
     */
    int fd() const {
        return fd_;
    }
};

} // namespace NoteBytes

#endif // NOTEBYTES_WRITER_H