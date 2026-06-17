// src/core/note_file_handle.cpp – inline + zero-buffer stream I/O

#include "note_file_handle.h"
#include "note_file_service.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <cstring>
#include <cstdio>

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
// Inline I/O (entire file in memory)
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
// Stream I/O – zero buffering, chunked transfer
// ══════════════════════════════════════════════════════════════════════════

// ── ReadStream ───────────────────────────────────────────────────────────

NoteFileHandle::ReadStream::ReadStream(
    std::string file_path,
    std::shared_ptr<NoteFileHandle> handle)
    : file_path_(std::move(file_path)), handle_(std::move(handle)) {}

NoteFileHandle::ReadStream::~ReadStream() { cancel(); }

void NoteFileHandle::ReadStream::transfer_to(NoteDaemon::Channel* channel) {
    if (closed_.exchange(true) || !channel || !channel->is_open()) return;

    int fd = ::open(file_path_.c_str(), O_RDONLY);
    if (fd < 0) {
        syslog(LOG_WARNING, "[ReadStream] Cannot open %s: %s",
               file_path_.c_str(), strerror(errno));
        return;
    }

    uint8_t buf[65536];  // 64KB chunks – no heap allocation per chunk
    ssize_t n;
    uint64_t total = 0;

    while ((n = ::read(fd, buf, sizeof(buf))) > 0) {
        if (closed_.load()) break;
        size_t offset = 0;
        while (offset < static_cast<size_t>(n)) {
            ssize_t written = channel->write(buf + offset, n - offset);
            if (written <= 0) {
                syslog(LOG_WARNING, "[ReadStream] channel write failed at %llu",
                       (unsigned long long)total);
                ::close(fd);
                return;
            }
            offset += written;
            total += written;
        }
    }

    ::close(fd);
    syslog(LOG_DEBUG, "[ReadStream] Streamed %llu bytes from %s",
           (unsigned long long)total, file_path_.c_str());
}

void NoteFileHandle::ReadStream::cancel() {
    closed_.store(true);
}

// ── WriteStream ──────────────────────────────────────────────────────────

NoteFileHandle::WriteStream::WriteStream(
    std::string file_path,
    std::shared_ptr<NoteFileHandle> handle)
    : file_path_(std::move(file_path)), handle_(std::move(handle)) {}

NoteFileHandle::WriteStream::~WriteStream() { cancel(); }

void NoteFileHandle::WriteStream::receive_from(NoteDaemon::Channel* channel) {
    if (closed_.exchange(true) || !channel || !channel->is_open()) return;

    // Write to temp file, atomically rename on completion
    std::string tmp_path = file_path_ + ".stream";
    int fd = ::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        syslog(LOG_WARNING, "[WriteStream] Cannot create %s: %s",
               tmp_path.c_str(), strerror(errno));
        return;
    }

    uint8_t buf[65536];  // 64KB chunks
    ssize_t n;
    uint64_t total = 0;

    while ((n = channel->read(buf, sizeof(buf))) > 0) {
        if (closed_.load()) break;
        size_t offset = 0;
        while (offset < static_cast<size_t>(n)) {
            ssize_t written = ::write(fd, buf + offset, n - offset);
            if (written <= 0) {
                syslog(LOG_WARNING, "[WriteStream] file write failed at %llu",
                       (unsigned long long)total);
                ::close(fd);
                unlink(tmp_path.c_str());
                return;
            }
            offset += written;
            total += written;
        }
    }

    ::close(fd);

    // Atomically replace target
    if (rename(tmp_path.c_str(), file_path_.c_str()) != 0) {
        syslog(LOG_ERR, "[WriteStream] rename failed: %s", strerror(errno));
        unlink(tmp_path.c_str());
        return;
    }

    syslog(LOG_DEBUG, "[WriteStream] Received %llu bytes to %s",
           (unsigned long long)total, file_path_.c_str());
}

void NoteFileHandle::WriteStream::cancel() {
    closed_.store(true);
}

// ══════════════════════════════════════════════════════════════════════════
// Factory methods
// ══════════════════════════════════════════════════════════════════════════

std::unique_ptr<NoteFileHandle::ReadStream> NoteFileHandle::open_read_stream() {
    if (closed_.load()) return nullptr;
    if (!exists()) return nullptr;  // nothing to stream
    return std::make_unique<ReadStream>(file_path_, shared_from_this());
}

std::unique_ptr<NoteFileHandle::WriteStream> NoteFileHandle::open_write_stream() {
    if (closed_.load()) return nullptr;
    return std::make_unique<WriteStream>(file_path_, shared_from_this());
}
