// include/notebytes_reader.h
// C++ NoteBytes Reader - standardized deserialization with predictable metadata
// Matches Java NoteBytesReader behavior

#ifndef NOTEBYTES_READER_H
#define NOTEBYTES_READER_H

#include "notebytes.h"
#include "notebytes_writer.h"
#include <sys/socket.h>
#include <unistd.h>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <sys/syslog.h>

namespace NoteBytes {

/**
 * NoteBytesReader - standardized reader for NoteBytes protocol
 * Ensures all reads follow the [type][length][data] format
 * 
 * Usage:
 *   Reader reader(socket_fd);
 *   Value val = reader.read_value();
 *   Object obj = reader.read_object();
 */
class Reader {
private:
    int fd_;
    std::vector<uint8_t> buffer_;
    size_t buffer_pos_;
    bool owns_fd_;
    
public:
    /**
     * Create reader for file descriptor
     * @param fd File descriptor (socket, file, etc.)
     * @param owns_fd If true, closes fd on destruction
     */
    explicit Reader(int fd, bool owns_fd = false)
        : fd_(fd), buffer_pos_(0), owns_fd_(owns_fd) {
        buffer_.reserve(8192);
    }
    
    ~Reader() {
        if (owns_fd_ && fd_ >= 0) {
            close(fd_);
        }
    }
    
    // Non-copyable
    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;
    
    // Movable
    Reader(Reader&& other) noexcept
        : fd_(other.fd_), buffer_(std::move(other.buffer_)),
          buffer_pos_(other.buffer_pos_), owns_fd_(other.owns_fd_) {
        other.fd_ = -1;
        other.owns_fd_ = false;
    }
    
    /**
     * Read exactly n bytes from fd into internal buffer
     * Blocks until all bytes are read or error occurs
     */
    bool read_exact(size_t n) {
        size_t start_pos = buffer_.size();
        buffer_.resize(start_pos + n);
        
        size_t total_read = 0;
        while (total_read < n) {
            ssize_t r = ::read(fd_, buffer_.data() + start_pos + total_read, 
                             n - total_read);
            if (r <= 0) {
                if (r == 0) {
                    syslog(LOG_INFO, "Socket closed during read");
                } else {
                    syslog(LOG_ERR, "Read error: %s", strerror(errno));
                }
                buffer_.resize(start_pos);  // Restore original size
                return false;
            }
            total_read += r;
        }
        
        return true;
    }
    
    /**
     * Read metadata (5 bytes: type + length)
     * @return MetaData structure
     */
    MetaData read_metadata() {
        if (!read_exact(MetaData::SIZE)) {
            throw std::runtime_error("Failed to read metadata");
        }
        
        size_t offset = buffer_pos_;
        buffer_pos_ += MetaData::SIZE;
        
        return MetaData::read_from(buffer_.data(), offset);
    }
    
    /**
     * Peek at next metadata without consuming it
     */
    MetaData peek_metadata() {
        if (buffer_.size() - buffer_pos_ < MetaData::SIZE) {
            if (!read_exact(MetaData::SIZE)) {
                throw std::runtime_error("Failed to peek metadata");
            }
        }
        
        size_t temp_offset = buffer_pos_;
        return MetaData::read_from(buffer_.data(), temp_offset);
    }
    
    /**
     * Read a complete Value (metadata + data)
     * @return NoteBytes Value
     */
    Value read_value() {
        // Read metadata
        MetaData meta = read_metadata();
        
        // Read data
        if (!read_exact(meta.length)) {
            throw std::runtime_error("Failed to read value data");
        }
        
        Value val(buffer_.data() + buffer_pos_, meta.length, meta.type);
        buffer_pos_ += meta.length;
        
        // Compact buffer if we've read everything
        if (buffer_pos_ == buffer_.size()) {
            buffer_.clear();
            buffer_pos_ = 0;
        }
        
        return val;
    }
    
    /**
     * Read a key-value pair
     * @return Pair
     */
    Pair read_pair() {
        Value key = read_value();
        Value val = read_value();
        return Pair(key, val);
    }
    
    /**
     * Read an Object
     * First reads metadata, then deserializes pairs
     */
    Object read_object() {
        MetaData meta = read_metadata();
        
        if (meta.type != Type::OBJECT) {
            throw std::runtime_error("Expected OBJECT type, got " + 
                                   std::to_string(meta.type));
        }
        
        if (!read_exact(meta.length)) {
            throw std::runtime_error("Failed to read object body");
        }
        
        Object obj = Object::deserialize(buffer_.data() + buffer_pos_, meta.length);
        buffer_pos_ += meta.length;
        
        // Compact buffer
        if (buffer_pos_ == buffer_.size()) {
            buffer_.clear();
            buffer_pos_ = 0;
        }
        
        return obj;
    }
    
    /**
     * Read an Array
     * First reads metadata, then reads all values
     */
    Array read_array() {
        MetaData meta = read_metadata();
        
        if (meta.type != Type::ARRAY) {
            throw std::runtime_error("Expected ARRAY type, got " + 
                                   std::to_string(meta.type));
        }
        
        if (!read_exact(meta.length)) {
            throw std::runtime_error("Failed to read array body");
        }
        
        Array arr;
        size_t end_pos = buffer_pos_ + meta.length;
        
        while (buffer_pos_ < end_pos) {
            size_t temp_offset = buffer_pos_;
            Value val = Value::read_from(buffer_.data(), temp_offset);
            arr.add(val);
            buffer_pos_ = temp_offset;
        }
        
        // Compact buffer
        if (buffer_pos_ == buffer_.size()) {
            buffer_.clear();
            buffer_pos_ = 0;
        }
        
        return arr;
    }
    
    /**
     * Read raw bytes without metadata
     * Used for custom protocols
     */
    std::vector<uint8_t> read_raw(size_t length) {
        if (!read_exact(length)) {
            throw std::runtime_error("Failed to read raw bytes");
        }
        
        std::vector<uint8_t> data(buffer_.data() + buffer_pos_, 
                                 buffer_.data() + buffer_pos_ + length);
        buffer_pos_ += length;
        
        return data;
    }
    
    /**
     * Check if more data is available in buffer
     */
    bool has_buffered_data() const {
        return buffer_pos_ < buffer_.size();
    }
    
    /**
     * Get number of buffered bytes
     */
    size_t buffered_size() const {
        return buffer_.size() - buffer_pos_;
    }
    
    /**
     * Clear internal buffer
     */
    void clear() {
        buffer_.clear();
        buffer_pos_ = 0;
    }
    
    /**
     * Get underlying file descriptor
     */
    int fd() const {
        return fd_;
    }
};

/**
 * Helper function to read a complete packet from fd
 * Reads one complete Object
 */
inline Object read_packet(int fd) {
    Reader reader(fd, false);
    return reader.read_object();
}

/**
 * Helper to read a routed message with sourceId prefix
 * Format: [INTEGER type][0x00000004][sourceId][OBJECT/ENCRYPTED][length][data]
 * @return pair of (source_id, object)
 */
struct RoutedMessage {
    int32_t source_id;
    Object message;
    bool is_encrypted;
};

inline RoutedMessage read_routed_packet(int fd) {
    Reader reader(fd, false);
    
    // Read sourceId
    Value sid_val = reader.read_value();
    if (sid_val.type() != Type::INTEGER) {
        throw std::runtime_error("Expected INTEGER sourceId");
    }
    
    // Peek at next type to see if encrypted
    MetaData next_meta = reader.peek_metadata();
    bool encrypted = (next_meta.type == Type::ENCRYPTED);
    
    // Read the message object (or encrypted blob)
    if (encrypted) {
        // For encrypted messages, caller needs to decrypt
        Value encrypted_val = reader.read_value();
        Object dummy;  // Placeholder - caller must decrypt
        return RoutedMessage{sid_val.as_int(), dummy, true};
    } else {
        Object obj = reader.read_object();
        return RoutedMessage{sid_val.as_int(), obj, false};
    }
}

} // namespace NoteBytes

#endif // NOTEBYTES_READER_H