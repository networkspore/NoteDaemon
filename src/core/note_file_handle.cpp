// src/core/note_file_handle.cpp
// NoteFileHandle implementation

#include "note_file_handle.h"
#include "note_file_service.h"
#include "module_framework/channel.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <cstring>

using namespace NoteDaemon;

// =========================================================================
// ReadStream
// =========================================================================

NoteFileHandle::ReadStream::ReadStream(
    std::unique_ptr<Channel> channel,
    std::shared_ptr<NoteFileHandle> handle)
    : channel_(std::move(channel)), handle_(std::move(handle))
{
    if (channel_ && channel_->is_open() && channel_->fd() >= 0) {
        reader_ = std::make_unique<NoteBytes::Reader>(channel_->fd(), false);
    }
}

NoteBytes::Value NoteFileHandle::ReadStream::read_value() {
    if (closed_ || !reader_) return NoteBytes::Value();
    try {
        return reader_->read_value();
    } catch (const std::exception& e) {
        syslog(LOG_WARNING, "[ReadStream] read_value error: %s", e.what());
        close();
        return NoteBytes::Value();
    }
}

NoteBytes::Object NoteFileHandle::ReadStream::read_object() {
    if (closed_ || !reader_) return NoteBytes::Object();
    try {
        return reader_->read_object();
    } catch (const std::exception& e) {
        syslog(LOG_WARNING, "[ReadStream] read_object error: %s", e.what());
        close();
        return NoteBytes::Object();
    }
}

std::vector<uint8_t> NoteFileHandle::ReadStream::read_all() {
    std::vector<uint8_t> result;
    if (closed_ || !reader_) return result;
    try {
        while (true) {
            auto val = reader_->read_value();
            if (val.size() == 0 && val.type() == NoteBytes::Type::RAW_BYTES)
                break;
            auto& d = val.data();
            result.insert(result.end(), d.begin(), d.end());
        }
    } catch (const std::exception& e) {
        if (!result.empty())
            syslog(LOG_DEBUG, "[ReadStream] partial read: %zu bytes", result.size());
    }
    return result;
}

void NoteFileHandle::ReadStream::close() {
    if (closed_.exchange(true)) return;
    reader_.reset();
    if (channel_) { channel_->close(); channel_.reset(); }
}

// =========================================================================
// WriteStream
// =========================================================================

NoteFileHandle::WriteStream::WriteStream(
    std::unique_ptr<Channel> channel,
    std::shared_ptr<NoteFileHandle> handle)
    : channel_(std::move(channel)), handle_(std::move(handle))
{
    if (channel_ && channel_->is_open() && channel_->fd() >= 0) {
        writer_ = std::make_unique<NoteBytes::Writer>(channel_->fd(), false);
    }
}

void NoteFileHandle::WriteStream::write_value(const NoteBytes::Value& value) {
    if (closed_ || !writer_) return;
    try { writer_->write(value); }
    catch (const std::exception& e) {
        syslog(LOG_WARNING, "[WriteStream] write_value error: %s", e.what());
    }
}

void NoteFileHandle::WriteStream::write_object(const NoteBytes::Object& obj) {
    if (closed_ || !writer_) return;
    try { writer_->write(obj); }
    catch (const std::exception& e) {
        syslog(LOG_WARNING, "[WriteStream] write_object error: %s", e.what());
    }
}

void NoteFileHandle::WriteStream::write_raw(const uint8_t* data, size_t length) {
    if (closed_ || !writer_) return;
    try { writer_->write_raw(data, length); }
    catch (const std::exception& e) {
        syslog(LOG_WARNING, "[WriteStream] write_raw error: %s", e.what());
    }
}

void NoteFileHandle::WriteStream::flush() {
    if (closed_ || !writer_) return;
    try { writer_->flush(); }
    catch (const std::exception& e) {
        syslog(LOG_WARNING, "[WriteStream] flush error: %s", e.what());
    }
}

void NoteFileHandle::WriteStream::close() {
    if (closed_.exchange(true)) return;
    if (writer_) { try { writer_->flush(); } catch (...) {} writer_.reset(); }
    if (channel_) { channel_->close(); channel_.reset(); }
}

// =========================================================================
// NoteFileHandle
// =========================================================================

NoteFileHandle::NoteFileHandle(
    std::string file_path,
    std::vector<NoteBytes::Value> path_segments,
    std::string path_string,
    std::shared_ptr<NoteFileService> service)
    : file_path_(std::move(file_path))
    , path_segments_(std::move(path_segments))
    , path_string_(std::move(path_string))
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

// =========================================================================
// Stream-based access
// =========================================================================

std::unique_ptr<NoteFileHandle::ReadStream>
NoteFileHandle::read_stream(Channel* /*channel*/) {
    if (closed_.load()) return nullptr;
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto svc = service_.lock();
    if (!svc) return nullptr;
    int pipe_fd = svc->decrypt_file(file_path_);
    if (pipe_fd < 0) return nullptr;
    auto pipe_ch = std::make_unique<PipeChannel>(pipe_fd, -1,
        "pipe:read:" + path_string_);
    return std::make_unique<ReadStream>(std::move(pipe_ch), shared_from_this());
}

std::unique_ptr<NoteFileHandle::WriteStream>
NoteFileHandle::write_stream(Channel* /*channel*/) {
    if (closed_.load()) return nullptr;
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto svc = service_.lock();
    if (!svc) return nullptr;
    int rfd=-1, wfd=-1;
    if (!svc->create_pipe(rfd, wfd)) return nullptr;
    if (!svc->encrypt_file_swap(file_path_, rfd)) {
        ::close(rfd); ::close(wfd); return nullptr;
    }
    auto pipe_ch = std::make_unique<PipeChannel>(-1, wfd,
        "pipe:write:" + path_string_);
    return std::make_unique<WriteStream>(std::move(pipe_ch), shared_from_this());
}

// =========================================================================
// Convenience methods
// =========================================================================

NoteBytes::Object NoteFileHandle::read_object() {
    if (closed_.load()) return NoteBytes::Object();
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto svc = service_.lock();
    if (!svc) return NoteBytes::Object();
    int pipe_fd = svc->decrypt_file(file_path_);
    if (pipe_fd < 0) return NoteBytes::Object();
    NoteBytes::Object result;
    try {
        NoteBytes::Reader reader(pipe_fd, true);
        result = reader.read_object();
    } catch (const std::exception& e) {
        syslog(LOG_WARNING, "[NoteFileHandle] read_object: %s", e.what());
        ::close(pipe_fd);
    }
    return result;
}

bool NoteFileHandle::write_object(const NoteBytes::Object& obj) {
    if (closed_.load()) return false;
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto svc = service_.lock();
    if (!svc) return false;
    int rfd=-1, wfd=-1;
    if (!svc->create_pipe(rfd, wfd)) return false;
    {
        NoteBytes::Writer writer(wfd, true);
        writer.write(obj);
        writer.flush();
    }
    if (!svc->encrypt_file_swap(file_path_, rfd)) {
        ::close(rfd); return false;
    }
    return true;
}

std::vector<uint8_t> NoteFileHandle::read_bytes() {
    if (closed_.load()) return {};
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto svc = service_.lock();
    if (!svc) return {};
    int pipe_fd = svc->decrypt_file(file_path_);
    if (pipe_fd < 0) return {};
    std::vector<uint8_t> result;
    uint8_t buf[65536];
    ssize_t n;
    while ((n = ::read(pipe_fd, buf, sizeof(buf))) > 0)
        result.insert(result.end(), buf, buf + n);
    ::close(pipe_fd);
    return result;
}

bool NoteFileHandle::write_bytes(const uint8_t* data, size_t length) {
    if (closed_.load()) return false;
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto svc = service_.lock();
    if (!svc) return false;
    int rfd=-1, wfd=-1;
    if (!svc->create_pipe(rfd, wfd)) return false;
    size_t written = 0;
    while (written < length) {
        ssize_t n = ::write(wfd, data + written, length - written);
        if (n <= 0) break;
        written += n;
    }
    ::close(wfd);
    if (!svc->encrypt_file_swap(file_path_, rfd)) {
        ::close(rfd); return false;
    }
    return true;
}

// =========================================================================
// Internal pipe methods
// =========================================================================

int NoteFileHandle::begin_read_pipe() {
    auto svc = service_.lock();
    return svc ? svc->decrypt_file(file_path_) : -1;
}

int NoteFileHandle::begin_write_pipe() {
    auto svc = service_.lock();
    if (!svc) return -1;
    int rfd=-1, wfd=-1;
    if (!svc->create_pipe(rfd, wfd)) return -1;
    if (!svc->encrypt_file_swap(file_path_, rfd)) {
        ::close(rfd); ::close(wfd); return -1;
    }
    return wfd;
}

bool NoteFileHandle::commit_write(int) { return true; }
