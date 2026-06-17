// src/core/note_file_service.cpp – filesystem-backed auth, no central registry

#include "note_file_service.h"
#include "note_file_handle.h"
#include "note_file_path.h"
#include "module_framework/channel.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>

namespace fs = std::filesystem;

// ── Helpers ──────────────────────────────────────────────────────────────

namespace {
    std::vector<uint8_t> rand_bytes(size_t len) {
        std::vector<uint8_t> buf(len);
        if (RAND_bytes(buf.data(), (int)len) != 1) {
            FILE* f = fopen("/dev/urandom", "rb");
            if (f) { size_t r = fread(buf.data(), 1, len, f); (void)r; fclose(f); }
        }
        return buf;
    }
    bool const_cmp(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        uint8_t x = 0;
        for (size_t i = 0; i < a.size(); i++) x |= a[i] ^ b[i];
        return x == 0;
    }
    std::string uuid() {
        auto b = rand_bytes(16);
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 16; i++) {
            if (i == 4 || i == 6 || i == 8 || i == 10) ss << "-";
            ss << std::setw(2) << (int)b[i];
        }
        return ss.str();
    }
    uint64_t now() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
}

std::vector<uint8_t> NoteFileService::random_bytes(size_t len) const {
    return rand_bytes(len);
}

// ══════════════════════════════════════════════════════════════════════════
// Init
// ══════════════════════════════════════════════════════════════════════════

NoteFileService::NoteFileService(const NoteFileConfig& config) : config_(config) {}

NoteFileService::~NoteFileService() {
    shutdown_.store(true);
    admin_tokens_.clear();
    client_tokens_.clear();
}

bool NoteFileService::init() {
    if (initialized_.load()) return true;
    syslog(LOG_INFO, "[NoteFileService] Init — filesystem-backed auth");

    try { fs::create_directories(config_.data_directory + "/clients"); }
    catch (const std::exception& e) {
        syslog(LOG_ERR, "[NoteFileService] mkdir: %s", e.what());
        return false;
    }

    std::ifstream ak(config_.admin_key_path, std::ios::binary);
    if (ak) {
        ak.seekg(0, std::ios::end);
        admin_key_hash_.resize(ak.tellg());
        ak.seekg(0, std::ios::beg);
        ak.read((char*)admin_key_hash_.data(), admin_key_hash_.size());
        syslog(LOG_INFO, "[NoteFileService] Admin key loaded");
    }

    initialized_.store(true);
    syslog(LOG_INFO, "[NoteFileService] Ready. admin=%s clients=%s",
           admin_key_hash_.empty() ? "NOT SET" : "SET",
           fs::is_directory(config_.data_directory + "/clients") ? "OK" : "MISSING");
    return true;
}

// ══════════════════════════════════════════════════════════════════════════
// Key hashing
// ══════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> NoteFileService::hash_key(const std::string& key) const {
    auto salt = rand_bytes(16);
    std::vector<uint8_t> hash(32);
    unsigned int n = 0;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md, salt.data(), salt.size());
    EVP_DigestUpdate(md, key.data(), key.size());
    EVP_DigestFinal_ex(md, hash.data(), &n);
    EVP_MD_CTX_free(md);
    std::vector<uint8_t> out;
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), hash.begin(), hash.begin() + n);
    return out;
}

bool NoteFileService::verify_key(const std::string& key,
                                  const std::vector<uint8_t>& stored) const {
    if (stored.size() < 16) return false;
    auto salt = std::vector<uint8_t>(stored.begin(), stored.begin() + 16);
    auto expected = std::vector<uint8_t>(stored.begin() + 16, stored.end());
    std::vector<uint8_t> computed(32);
    unsigned int n = 0;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md, salt.data(), salt.size());
    EVP_DigestUpdate(md, key.data(), key.size());
    EVP_DigestFinal_ex(md, computed.data(), &n);
    EVP_MD_CTX_free(md);
    return const_cmp(computed, expected);
}

// ══════════════════════════════════════════════════════════════════════════
// Admin
// ══════════════════════════════════════════════════════════════════════════

bool NoteFileService::set_admin_api_key(const std::string& key) {
    std::lock_guard<std::mutex> l(admin_mutex_);
    if (!admin_key_hash_.empty()) return false;
    admin_key_hash_ = hash_key(key);
    std::ofstream out(config_.admin_key_path, std::ios::binary);
    if (!out) return false;
    out.write((const char*)admin_key_hash_.data(), admin_key_hash_.size());
    out.close();
    chmod(config_.admin_key_path.c_str(), 0600);
    return true;
}

bool NoteFileService::verify_admin_api_key(const std::string& key) const {
    std::lock_guard<std::mutex> l(admin_mutex_);
    return verify_key(key, admin_key_hash_);
}

bool NoteFileService::has_admin_api_key() const {
    std::lock_guard<std::mutex> l(admin_mutex_);
    return !admin_key_hash_.empty();
}

std::unique_ptr<AdminToken> NoteFileService::authenticate_admin(
    const std::string& key, pid_t pid)
{
    std::lock_guard<std::mutex> l(admin_mutex_);
    if (!verify_key(key, admin_key_hash_)) return nullptr;
    auto t = std::make_unique<AdminToken>();
    t->session_id = uuid(); t->client_pid = pid; t->created_at_ms = now();
    std::string sid = t->session_id;
    admin_tokens_[sid] = std::move(t);
    auto r = std::make_unique<AdminToken>(*admin_tokens_[sid]);
    return r;
}

void NoteFileService::invalidate_admin_token(const std::string& sid) {
    std::lock_guard<std::mutex> l(admin_mutex_);
    admin_tokens_.erase(sid);
}

// ══════════════════════════════════════════════════════════════════════════
// Clients — filesystem-backed
// ══════════════════════════════════════════════════════════════════════════

std::string NoteFileService::client_data_dir(const std::string& cid) const {
    return config_.data_directory + "/clients/" + cid;
}

std::string NoteFileService::auth_file(const std::string& cid) const {
    return client_data_dir(cid) + "/.auth";
}

std::string NoteFileService::client_ledger_path(const std::string& cid) const {
    return client_data_dir(cid) + "/.ledger";
}

bool NoteFileService::client_exists(const std::string& cid) const {
    return fs::is_directory(client_data_dir(cid));
}

bool NoteFileService::add_client(const std::string& cid,
                                  const std::string& api_key) {
    std::string dir = client_data_dir(cid);
    if (fs::is_directory(dir)) return false;  // already exists

    try {
        fs::create_directories(dir);
    } catch (...) { return false; }

    // Write .auth file (salt + hash)
    auto hash = hash_key(api_key);
    std::ofstream out(auth_file(cid), std::ios::binary);
    if (!out) { fs::remove_all(dir); return false; }
    out.write((const char*)hash.data(), hash.size());
    out.close();
    chmod(auth_file(cid).c_str(), 0600);

    syslog(LOG_INFO, "[NoteFileService] Client created: %s", cid.c_str());
    return true;
}

bool NoteFileService::remove_client(const std::string& cid) {
    std::string dir = client_data_dir(cid);
    if (!fs::is_directory(dir)) return false;
    // Close any active tokens for this client
    {
        std::lock_guard<std::mutex> l(client_mutex_);
        for (auto it = client_tokens_.begin(); it != client_tokens_.end(); ) {
            if (it->second->client_id == cid) it = client_tokens_.erase(it);
            else ++it;
        }
    }
    fs::remove_all(dir);
    syslog(LOG_INFO, "[NoteFileService] Client removed: %s", cid.c_str());
    return true;
}

std::vector<std::string> NoteFileService::list_clients() const {
    std::vector<std::string> result;
    std::string base = config_.data_directory + "/clients";
    if (!fs::is_directory(base)) return result;
    for (auto& entry : fs::directory_iterator(base)) {
        if (entry.is_directory())
            result.push_back(entry.path().filename().string());
    }
    return result;
}

std::unique_ptr<ClientToken> NoteFileService::authenticate_client(
    const std::string& cid, const std::string& api_key, pid_t pid)
{
    // Read .auth file from client's directory
    std::string path = auth_file(cid);
    std::ifstream in(path, std::ios::binary);
    if (!in) return nullptr;
    in.seekg(0, std::ios::end);
    std::streamsize sz = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> hash(sz);
    in.read((char*)hash.data(), sz);

    if (!verify_key(api_key, hash)) return nullptr;

    auto t = std::make_unique<ClientToken>();
    t->session_id = uuid(); t->client_id = cid;
    t->client_pid = pid; t->created_at_ms = now();
    std::string sid = t->session_id;
    std::lock_guard<std::mutex> l(client_mutex_);
    client_tokens_[sid] = std::move(t);
    return std::make_unique<ClientToken>(*client_tokens_[sid]);
}

void NoteFileService::invalidate_client_token(const std::string& sid) {
    std::lock_guard<std::mutex> l(client_mutex_);
    client_tokens_.erase(sid);
}

// ══════════════════════════════════════════════════════════════════════════
// Per-client ledger locking
// ══════════════════════════════════════════════════════════════════════════

std::mutex& NoteFileService::get_ledger_lock(const std::string& cid) const {
    std::lock_guard<std::mutex> l(ledger_locks_mutex_);
    auto& ptr = ledger_locks_[cid];
    if (!ptr) ptr = std::make_unique<std::mutex>();
    return *ptr;
}

// ══════════════════════════════════════════════════════════════════════════
// File paths & I/O
// ══════════════════════════════════════════════════════════════════════════

std::string NoteFileService::generate_data_file_path(const std::string& cid) const {
    auto u = rand_bytes(16);
    std::stringstream ss;
    ss << client_data_dir(cid) << "/";
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << (int)u[i];
        if (i == 3 || i == 5 || i == 7 || i == 9) ss << "-";
    }
    ss << ".dat";
    return ss.str();
}

std::string NoteFileService::resolve_or_create_path(
    const std::string& cid,
    const std::vector<NoteBytes::Value>& path_segments)
{
    std::lock_guard<std::mutex> lock(get_ledger_lock(cid));
    NoteFilePath np(client_ledger_path(cid), path_segments,
                    client_data_dir(cid));
    return NoteFileLedger::find_or_create_path(np);
}

std::vector<uint8_t> NoteFileService::read_file_to_buffer(
    const std::string& path)
{
    struct stat st;
    if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return {};
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::vector<uint8_t> buf(st.st_size);
    in.read((char*)buf.data(), buf.size());
    return buf;
}

bool NoteFileService::write_buffer_to_file(
    const std::string& path, const std::vector<uint8_t>& data)
{
    std::ofstream out(path, std::ios::binary);
    if (!out) return false;
    out.write((const char*)data.data(), data.size());
    return out.good();
}

bool NoteFileService::create_pipe(int& r, int& w) {
    int p[2] = {-1, -1};
    if (::pipe(p) < 0) return false;
    r = p[0]; w = p[1];
    return true;
}

// ══════════════════════════════════════════════════════════════════════════
// File operations
// ══════════════════════════════════════════════════════════════════════════

std::shared_ptr<NoteFileHandle> NoteFileService::get_file(
    const std::string& cid,
    const std::vector<NoteBytes::Value>& path_segments)
{
    if (!initialized_.load() || !client_exists(cid)) return nullptr;

    std::string ps;
    for (size_t i = 0; i < path_segments.size(); i++) {
        if (i > 0) ps += "/";
        ps += path_segments[i].as_string();
    }
    std::string fp = cid + "/" + ps;

    {   // Check cache
        std::lock_guard<std::mutex> l(handles_mutex_);
        auto it = handles_.find(fp);
        if (it != handles_.end()) {
            auto h = it->second.lock();
            if (h) return h;
            handles_.erase(it);
        }
    }

    auto file_path = resolve_or_create_path(cid, path_segments);
    if (file_path.empty()) return nullptr;

    auto handle = std::make_shared<NoteFileHandle>(
        file_path, path_segments, fp, cid, std::vector<uint8_t>(),
        shared_from_this());

    { std::lock_guard<std::mutex> l(handles_mutex_); handles_[fp] = handle; }
    return handle;
}

std::shared_ptr<NoteFileHandle> NoteFileService::get_file(
    const std::string& cid, const std::vector<std::string>& segs)
{
    std::vector<NoteBytes::Value> s;
    for (auto& seg : segs) s.emplace_back(seg);
    return get_file(cid, s);
}

bool NoteFileService::delete_file(
    const std::string& cid,
    const std::vector<NoteBytes::Value>& path_segments,
    bool recursive)
{
    std::lock_guard<std::mutex> lock(get_ledger_lock(cid));
    NoteFilePath np(client_ledger_path(cid), path_segments,
                    client_data_dir(cid), recursive);
    return NoteFileLedger::delete_from_path(np);
}

std::vector<std::string> NoteFileService::list_client_files(
    const std::string& cid)
{
    std::vector<std::string> result;
    auto dir = client_data_dir(cid);
    if (!fs::is_directory(dir)) return result;
    for (auto& p : fs::recursive_directory_iterator(dir)) {
        if (p.is_regular_file() &&
            p.path().extension() == ".dat")
            result.push_back(p.path().string());
    }
    return result;
}

// ══════════════════════════════════════════════════════════════════════════
// Streams
// ══════════════════════════════════════════════════════════════════════════

std::unique_ptr<StreamSession> NoteFileService::open_stream(
    const std::string& cid,
    const std::vector<NoteBytes::Value>& path_segments,
    StreamMode mode)
{
    auto handle = get_file(cid, path_segments);
    if (!handle) return nullptr;

    auto session = std::make_unique<StreamSession>();
    session->stream_id = uuid();
    session->client_id = cid;
    session->handle = handle;
    session->mode = mode;

    { std::lock_guard<std::mutex> l(streams_mutex_);
      streams_[session->stream_id] = std::move(session); }

    std::lock_guard<std::mutex> l(streams_mutex_);
    auto copy = std::make_unique<StreamSession>(*streams_[session->stream_id]);
    return copy;
}

StreamSession* NoteFileService::get_stream(const std::string& sid) {
    std::lock_guard<std::mutex> l(streams_mutex_);
    auto it = streams_.find(sid);
    return it != streams_.end() ? it->second.get() : nullptr;
}

void NoteFileService::close_stream(const std::string& sid) {
    std::lock_guard<std::mutex> l(streams_mutex_);
    streams_.erase(sid);
}

bool NoteFileService::route_channel(const std::string& sid,
                                     NoteDaemon::Channel* channel)
{
    auto* s = get_stream(sid);
    if (!s || !channel) return false;

    if (s->mode == StreamMode::READ) {
        auto rs = s->handle->open_read_stream();
        if (!rs) return false;
        rs->transfer_to(channel);
        return true;
    } else {
        auto ws = s->handle->open_write_stream();
        if (!ws) return false;
        ws->receive_from(channel);
        return true;
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Handle registry
// ══════════════════════════════════════════════════════════════════════════

void NoteFileService::register_handle(NoteFileHandle*) {}

void NoteFileService::unregister_handle(NoteFileHandle* h) {
    if (!h) return;
    std::lock_guard<std::mutex> l(handles_mutex_);
    for (auto it = handles_.begin(); it != handles_.end(); ) {
        auto locked = it->second.lock();
        if (!locked || locked.get() == h) it = handles_.erase(it);
        else ++it;
    }
}

size_t NoteFileService::active_handle_count() const {
    std::lock_guard<std::mutex> l(handles_mutex_);
    size_t n = 0;
    for (auto& [_, w] : handles_) if (!w.expired()) n++;
    return n;
}

// ══════════════════════════════════════════════════════════════════════════
// Global accessor
// ══════════════════════════════════════════════════════════════════════════

namespace {
    NoteFileService* g_fs = nullptr;
    std::mutex g_mtx;
}

NoteFileService* get_file_service() {
    std::lock_guard<std::mutex> l(g_mtx);
    return g_fs;
}

void set_file_service(NoteFileService* s) {
    std::lock_guard<std::mutex> l(g_mtx);
    g_fs = s;
}
