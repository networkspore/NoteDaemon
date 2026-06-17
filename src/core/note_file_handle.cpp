// src/core/note_file_handle.cpp – plaintext at rest, API-key protected

#include "note_file_handle.h"
#include "note_file_service.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <cstring>

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

NoteBytes::Object NoteFileHandle::read_object() {
    if (closed_.load()) return NoteBytes::Object();
    std::lock_guard<std::mutex> lock(operation_mutex_);
    auto svc = service_.lock();
    if (!svc) return NoteBytes::Object();
    auto buf = svc->read_file_to_buffer(file_path_);
    if (buf.empty()) return NoteBytes::Object();
    try {
        return NoteBytes::Object::deserialize(buf.data(), buf.size());
    } catch (const std::exception& e) {
        syslog(LOG_WARNING, "[NoteFileHandle] parse: %s", e.what());
        return NoteBytes::Object();
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
