// src/core/note_file_handle.cpp – inline + stream-based I/O

#include "note_file_handle.h"
#include "note_file_service.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <cstring>

// ══════════════════════════════════════════════════════════════════════════
// NoteFileHandle
// ══════════════════════════════════════════════════════════════════════════

NoteFileHandle::NoteFileHandle(
    std::string file_path,
    std::vector<NoteBytes::Value> path_segments,
    std::string path_string,
    std::string client_id,
    std::vector<uint8_t> encryption_key,
    std::shared_ptr<NoteFileService> service)
    : file_path_(std::move(file_path))
    , path_segments_(std::move(path_segments))
    , path_string_(std::move(path_string))
    , client_id_(std::move(client_id))
    , encryption_key_(std::move(encryption_key))
    , service_(service)
{}

uint64_t NoteFileHandle::size() const {
    struct stat st;
    if (stat(file_path_.c_str(), &st) == 0 && S_ISREG(st.st_mode))
        return static_cast<uint64_t>(st.st_size);
    return 0;
}

bool NoteFileHandle::exists() const {
    struct stat st;
    return stat(file_path_.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

void NoteFileHandle::close() {
    if (closed_.exchange(true)) return;
    if (auto svc = service_.lock()) svc->unregister_handle(this);
}

void NoteFileHandle::force_close() {
    closed_.store(true);
    if (auto svc = service_.lock()) svc->unregister_handle(this);
}

// ══════════════════════════════════════════════════════════════════════════
// Inline I/O (buffer-based)
// ══════════════════════════════════════════════════════════════════════════

NoteBytes::Object NoteFileHandle::read_object() {
    if (closed_.load()) return {};
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto svc = service_.lock();
    if (!svc) return {};
    auto buf = svc->read_file_to_buffer(file_path_);
    if (buf.empty()) return {};
    try {
        return NoteBytes::Object::deserialize(buf.data(), buf.size());
    } catch (const std::exception& e) {
        syslog(LOG_WARNING, "[NoteFileHandle] parse: %s", e.what());
        return {};
    }
}

bool NoteFileHandle::write_object(const NoteBytes::Object& obj) {
    if (closed_.load()) return false;
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto svc = service_.lock();
    if (!svc) return false;
    return svc->write_buffer_to_file(file_path_, obj.serialize());
}

std::vector<uint8_t> NoteFileHandle::read_bytes() {
    if (closed_.load()) return {};
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto svc = service_.lock();
    if (!svc) return {};
    return svc->read_file_to_buffer(file_path_);
}

bool NoteFileHandle::write_bytes(const uint8_t* data, size_t length) {
    if (closed_.load()) return false;
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto svc = service_.lock();
    if (!svc) return false;
    std::vector<uint8_t> buf(data, data + length);
    return svc->write_buffer_to_file(file_path_, buf);
}

// ══════════════════════════════════════════════════════════════════════════
// Stream I/O (Channel-based)
// ══════════════════════════════════════════════════════════════════════════

// ── ReadStream ───────────────────────────────────────────────────────────

NoteFileHandle::ReadStream::ReadStream(
    std::vector<uint8_t> data,
    std::shared_ptr<NoteFileHandle> handle)
    : data_(std::move(data)), handle_(std::move(handle)) {}

NoteFileHandle::ReadStream::~ReadStream() { cancel(); }

void NoteFileHandle::ReadStream::transfer_to(NoteDaemon::Channel* channel) {
    if (closed_.exchange(true) || !channel || !channel->is_open()) return;

    // Write the serialized NoteBytes data to the channel
    // First send the size as a 4-byte big-endian header
    uint32_t sz = static_cast<uint32_t>(data_.size());
    uint8_t hdr[4];
    hdr[0] = (sz >> 24) & 0xFF;
    hdr[1] = (sz >> 16) & 0xFF;
    hdr[2] = (sz >> 8) & 0xFF;
    hdr[3] = sz & 0xFF;

    ssize_t written = channel->write(hdr, 4);
    if (written < 4) return;  // write failed

    size_t offset = 0;
    while (offset < data_.size()) {
        ssize_t n = channel->write(data_.data() + offset, data_.size() - offset);
        if (n <= 0) break;
        offset += n;
    }

    syslog(LOG_DEBUG, "[ReadStream] Transferred %zu bytes to channel", data_.size());
}

void NoteFileHandle::ReadStream::cancel() {
    closed_.store(true);
}

// ── WriteStream ──────────────────────────────────────────────────────────

NoteFileHandle::WriteStream::WriteStream(
    std::shared_ptr<NoteFileHandle> handle)
    : handle_(std::move(handle)) {}

NoteFileHandle::WriteStream::~WriteStream() { cancel(); }

void NoteFileHandle::WriteStream::receive_from(NoteDaemon::Channel* channel) {
    if (closed_.exchange(true) || !channel || !channel->is_open()) return;

    // Read the 4-byte size header
    uint8_t hdr[4];
    ssize_t n = channel->read(hdr, 4);
    if (n < 4) return;

    uint32_t sz = (static_cast<uint32_t>(hdr[0]) << 24) |
                  (static_cast<uint32_t>(hdr[1]) << 16) |
                  (static_cast<uint32_t>(hdr[2]) << 8) |
                  static_cast<uint32_t>(hdr[3]);

    if (sz > 100 * 1024 * 1024) {  // sanity cap: 100MB
        syslog(LOG_WARNING, "[WriteStream] Rejecting oversized write: %u bytes", sz);
        return;
    }

    buffer_.resize(sz);
    size_t offset = 0;
    while (offset < sz) {
        ssize_t r = channel->read(buffer_.data() + offset, sz - offset);
        if (r <= 0) break;
        offset += r;
    }
    buffer_.resize(offset);

    // Write to file (WriteStream is nested inside NoteFileHandle,
    // so it can access private members of the handle)
    if (auto svc = handle_ ? handle_->service_.lock() : nullptr) {
        svc->write_buffer_to_file(handle_->file_path_, buffer_);
    }

    syslog(LOG_DEBUG, "[WriteStream] Received %zu bytes from channel", buffer_.size());
}

void NoteFileHandle::WriteStream::cancel() {
    closed_.store(true);
}

// ══════════════════════════════════════════════════════════════════════════
// Factory methods
// ══════════════════════════════════════════════════════════════════════════

std::unique_ptr<NoteFileHandle::ReadStream> NoteFileHandle::open_read_stream() {
    if (closed_.load()) return nullptr;
    auto svc = service_.lock();
    if (!svc) return nullptr;
    auto data = svc->read_file_to_buffer(file_path_);
    if (data.empty() && !exists()) return nullptr;
    return std::make_unique<ReadStream>(std::move(data), shared_from_this());
}

std::unique_ptr<NoteFileHandle::WriteStream> NoteFileHandle::open_write_stream() {
    if (closed_.load()) return nullptr;
    return std::make_unique<WriteStream>(shared_from_this());
}
