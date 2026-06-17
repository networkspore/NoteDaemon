// src/core/note_file_service.cpp
// NoteFileService – API key auth + per-client zone filesystem

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

    std::vector<uint8_t> random_bytes(size_t len) {
        std::vector<uint8_t> buf(len);
        if (RAND_bytes(buf.data(), (int)len) != 1) {
            FILE* f = fopen("/dev/urandom", "rb");
            if (f) { size_t r = fread(buf.data(), 1, len, f); (void)r; fclose(f); }
        }
        return buf;
    }

    bool constant_time_cmp(const std::vector<uint8_t>& a,
                           const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        uint8_t x = 0;
        for (size_t i = 0; i < a.size(); i++) x |= a[i] ^ b[i];
        return x == 0;
    }

    std::string uuid_str() {
        auto b = random_bytes(16);
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 16; i++) {
            if (i == 4 || i == 6 || i == 8 || i == 10) ss << "-";
            ss << std::setw(2) << (int)b[i];
        }
        return ss.str();
    }

    uint64_t now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

} // namespace

std::vector<uint8_t> NoteFileService::random_bytes(size_t len) const {
    return ::random_bytes(len);
}

// ── NoteFileService ──────────────────────────────────────────────────────

NoteFileService::NoteFileService(const NoteFileConfig& config) : config_(config) {}

NoteFileService::~NoteFileService() {
    shutdown_.store(true);
    admin_tokens_.clear();
    client_tokens_.clear();
}

bool NoteFileService::init() {
    if (initialized_.load()) return true;
    syslog(LOG_INFO, "[NoteFileService] Initializing");

    try { fs::create_directories(config_.data_directory); }
    catch (const std::exception& e) {
        syslog(LOG_ERR, "[NoteFileService] mkdir: %s", e.what());
        return false;
    }

    // Ensure registry parent dir exists
    try { fs::create_directories(
        fs::path(config_.clients_registry).parent_path()); }
    catch (...) {}

    // Load admin key
    std::ifstream ak(config_.admin_key_path, std::ios::binary);
    if (ak) {
        ak.seekg(0, std::ios::end);
        admin_api_key_hash_.resize(ak.tellg());
        ak.seekg(0, std::ios::beg);
        ak.read((char*)admin_api_key_hash_.data(), admin_api_key_hash_.size());
        syslog(LOG_INFO, "[NoteFileService] Admin key loaded");
    }

    // Load client registry
    load_clients_registry();

    initialized_.store(true);
    syslog(LOG_INFO, "[NoteFileService] Ready. admin_key=%s clients=%zu",
           admin_api_key_hash_.empty() ? "NOT SET" : "SET",
           clients_.size());
    return true;
}

// ── Admin API key ────────────────────────────────────────────────────────

std::vector<uint8_t> NoteFileService::hash_api_key(
    const std::string& key) const
{
    auto salt = random_bytes(16);
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

bool NoteFileService::verify_api_key(
    const std::string& key,
    const std::vector<uint8_t>& hash) const
{
    if (hash.size() < 16) return false;
    std::vector<uint8_t> salt(hash.begin(), hash.begin() + 16);
    std::vector<uint8_t> expected(hash.begin() + 16, hash.end());
    std::vector<uint8_t> computed(32);
    unsigned int n = 0;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md, salt.data(), salt.size());
    EVP_DigestUpdate(md, key.data(), key.size());
    EVP_DigestFinal_ex(md, computed.data(), &n);
    EVP_MD_CTX_free(md);
    return constant_time_cmp(computed, expected);
}

bool NoteFileService::set_admin_api_key(const std::string& api_key) {
    std::lock_guard<std::mutex> l(admin_mutex_);
    if (!admin_api_key_hash_.empty()) return false;
    admin_api_key_hash_ = hash_api_key(api_key);
    std::ofstream out(config_.admin_key_path, std::ios::binary);
    if (!out) return false;
    out.write((const char*)admin_api_key_hash_.data(), admin_api_key_hash_.size());
    out.close();
    chmod(config_.admin_key_path.c_str(), 0600);
    syslog(LOG_INFO, "[NoteFileService] Admin API key set");
    return true;
}

bool NoteFileService::verify_admin_api_key(const std::string& api_key) const {
    std::lock_guard<std::mutex> l(admin_mutex_);
    return verify_api_key(api_key, admin_api_key_hash_);
}

bool NoteFileService::has_admin_api_key() const {
    std::lock_guard<std::mutex> l(admin_mutex_);
    return !admin_api_key_hash_.empty();
}

std::unique_ptr<AdminToken> NoteFileService::authenticate_admin(
    const std::string& api_key, pid_t pid)
{
    std::lock_guard<std::mutex> l(admin_mutex_);
    if (!verify_api_key(api_key, admin_api_key_hash_)) return nullptr;
    auto t = std::make_unique<AdminToken>();
    t->session_id = uuid_str();
    t->client_pid = pid;
    t->created_at_ms = now_ms();
    std::string sid = t->session_id;
    admin_tokens_[sid] = std::move(t);
    auto r = std::make_unique<AdminToken>(*admin_tokens_[sid]);
    syslog(LOG_INFO, "[NoteFileService] Admin auth: pid=%d", pid);
    return r;
}

void NoteFileService::invalidate_admin_token(const std::string& sid) {
    std::lock_guard<std::mutex> l(admin_mutex_);
    admin_tokens_.erase(sid);
}

// ── Client registry I/O ──────────────────────────────────────────────────

bool NoteFileService::save_clients_registry() {
    NoteBytes::Object obj;
    for (const auto& [cid, e] : clients_) {
        NoteBytes::Object co;
        co.add(NoteBytes::Value("api_key_hash"),
               NoteBytes::Value(e.api_key_hash));
        co.add(NoteBytes::Value("created"),
               NoteBytes::Value((int64_t)e.created_at_ms));
        obj.add(NoteBytes::Value(cid), co.as_value());
    }
    auto ser = obj.serialize();
    std::ofstream out(config_.clients_registry, std::ios::binary);
    if (!out) return false;
    out.write((const char*)ser.data(), ser.size());
    out.close();
    chmod(config_.clients_registry.c_str(), 0600);
    return true;
}

bool NoteFileService::load_clients_registry() {
    std::ifstream in(config_.clients_registry, std::ios::binary);
    if (!in) return false;
    in.seekg(0, std::ios::end);
    std::streamsize sz = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(sz);
    in.read((char*)buf.data(), sz);
    try {
        auto obj = NoteBytes::Object::deserialize(buf.data(), buf.size());
        for (const auto& p : obj.pairs()) {
            if (p.value().type() == NoteBytes::Type::OBJECT) {
                auto co = NoteBytes::as_object(p.value());
                ClientEntry e;
                auto* h = co.get(NoteBytes::Value("api_key_hash"));
                if (h) e.api_key_hash = h->data();
                auto* c = co.get(NoteBytes::Value("created"));
                if (c) e.created_at_ms = c->as_long();
                clients_[p.key().as_string()] = std::move(e);
            }
        }
    } catch (const std::exception& e) {
        syslog(LOG_ERR, "[NoteFileService] Client registry parse: %s", e.what());
        return false;
    }
    return true;
}

// ── Client management ────────────────────────────────────────────────────

bool NoteFileService::add_client(const std::string& client_id,
                                  const std::string& client_api_key) {
    std::lock_guard<std::mutex> l(clients_mutex_);
    if (clients_.count(client_id)) return false;
    ClientEntry e;
    e.api_key_hash = hash_api_key(client_api_key);
    e.created_at_ms = now_ms();
    clients_[client_id] = std::move(e);
    bool ok = save_clients_registry();
    if (ok) {
        try { fs::create_directories(client_data_dir(client_id)); }
        catch (...) {}
        syslog(LOG_INFO, "[NoteFileService] Client added: %s", client_id.c_str());
    }
    return ok;
}

bool NoteFileService::remove_client(const std::string& client_id) {
    std::lock_guard<std::mutex> l(clients_mutex_);
    if (!clients_.count(client_id)) return false;
    clients_.erase(client_id);
    bool ok = save_clients_registry();
    if (ok) {
        try { fs::remove_all(client_data_dir(client_id)); } catch (...) {}
        syslog(LOG_INFO, "[NoteFileService] Client removed: %s", client_id.c_str());
    }
    return ok;
}

std::vector<std::string> NoteFileService::list_clients() const {
    std::lock_guard<std::mutex> l(clients_mutex_);
    std::vector<std::string> r;
    for (const auto& [id, _] : clients_) r.push_back(id);
    return r;
}

std::unique_ptr<ClientToken> NoteFileService::authenticate_client(
    const std::string& client_id, const std::string& api_key, pid_t pid)
{
    std::lock_guard<std::mutex> l(clients_mutex_);
    auto it = clients_.find(client_id);
    if (it == clients_.end()) return nullptr;
    if (!verify_api_key(api_key, it->second.api_key_hash)) return nullptr;
    auto t = std::make_unique<ClientToken>();
    t->session_id = uuid_str();
    t->client_id = client_id;
    t->client_pid = pid;
    t->created_at_ms = now_ms();
    std::string sid = t->session_id;
    client_tokens_[sid] = std::move(t);
    return std::make_unique<ClientToken>(*client_tokens_[sid]);
}

void NoteFileService::invalidate_client_token(const std::string& sid) {
    std::lock_guard<std::mutex> l(clients_mutex_);
    client_tokens_.erase(sid);
}

// ── File paths ───────────────────────────────────────────────────────────

std::string NoteFileService::client_data_dir(const std::string& client_id) const {
    return config_.data_directory + "/" + client_id;
}

std::string NoteFileService::client_ledger_path(const std::string& client_id) const {
    return client_data_dir(client_id) + "/.ledger";
}

std::string NoteFileService::generate_data_file_path(
    const std::string& client_id) const
{
    auto u = random_bytes(16);
    std::stringstream ss;
    ss << client_data_dir(client_id) << "/";
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << (int)u[i];
        if (i == 3 || i == 5 || i == 7 || i == 9) ss << "-";
    }
    ss << ".dat";
    return ss.str();
}

std::string NoteFileService::resolve_or_create_path(
    const std::string& client_id,
    const std::vector<NoteBytes::Value>& path_segments)
{
    std::lock_guard<std::mutex> lock(ledger_mutex_);
    NoteFilePath np(client_ledger_path(client_id), path_segments,
                    client_data_dir(client_id));
    return NoteFileLedger::find_or_create_path(np);
}

// ── File I/O (plaintext at rest, permission-protected) ───────────────────

std::vector<uint8_t> NoteFileService::read_file_to_buffer(
    const std::string& file_path)
{
    struct stat st;
    if (stat(file_path.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
        return {};
    std::ifstream in(file_path, std::ios::binary);
    if (!in) return {};
    std::vector<uint8_t> buf(st.st_size);
    in.read((char*)buf.data(), buf.size());
    return buf;
}

bool NoteFileService::write_buffer_to_file(
    const std::string& file_path,
    const std::vector<uint8_t>& data)
{
    std::ofstream out(file_path, std::ios::binary);
    if (!out) return false;
    out.write((const char*)data.data(), data.size());
    return out.good();
}

bool NoteFileService::create_pipe(int& r, int& w) {
    int p[2];
    if (::pipe(p) < 0) return false;
    r = p[0]; w = p[1];
    return true;
}

// ── File operations (per-client zone) ────────────────────────────────────

std::shared_ptr<NoteFileHandle> NoteFileService::get_file(
    const std::string& client_id,
    const std::vector<NoteBytes::Value>& path_segments)
{
    if (!initialized_.load()) return nullptr;

    std::string ps;
    for (size_t i = 0; i < path_segments.size(); i++) {
        if (i > 0) ps += "/";
        ps += path_segments[i].as_string();
    }
    std::string fp = client_id + "/" + ps;

    // Check cache
    {
        std::lock_guard<std::mutex> l(handles_mutex_);
        auto it = handles_.find(fp);
        if (it != handles_.end()) {
            auto h = it->second.lock();
            if (h) return h;
            handles_.erase(it);
        }
    }

    std::string file_path = resolve_or_create_path(client_id, path_segments);
    if (file_path.empty()) return nullptr;

    auto handle = std::make_shared<NoteFileHandle>(
        file_path, path_segments, fp, client_id,
        std::vector<uint8_t>(), shared_from_this());

    {
        std::lock_guard<std::mutex> l(handles_mutex_);
        handles_[fp] = handle;
    }
    return handle;
}

std::shared_ptr<NoteFileHandle> NoteFileService::get_file(
    const std::string& client_id,
    const std::vector<std::string>& segments)
{
    std::vector<NoteBytes::Value> s;
    for (auto& seg : segments) s.emplace_back(seg);
    return get_file(client_id, s);
}

bool NoteFileService::delete_file(
    const std::string& client_id,
    const std::vector<NoteBytes::Value>& path_segments,
    bool recursive)
{
    std::lock_guard<std::mutex> lock(ledger_mutex_);
    NoteFilePath np(client_ledger_path(client_id), path_segments,
                    client_data_dir(client_id), recursive);
    return NoteFileLedger::delete_from_path(np);
}

std::vector<std::string> NoteFileService::list_client_files(
    const std::string& client_id)
{
    std::vector<std::string> result;
    std::string dir = client_data_dir(client_id);
    if (!fs::is_directory(dir)) return result;
    for (auto& p : fs::recursive_directory_iterator(dir)) {
        if (p.is_regular_file())
            result.push_back(p.path().string());
    }
    return result;
}

// ── Stream management ────────────────────────────────────────────────────

std::unique_ptr<StreamSession> NoteFileService::open_stream(
    const std::string& client_id,
    const std::vector<NoteBytes::Value>& path_segments,
    StreamMode mode)
{
    auto handle = get_file(client_id, path_segments);
    if (!handle) return nullptr;

    auto session = std::make_unique<StreamSession>();
    session->stream_id = uuid_str();
    session->handle = handle;
    session->mode = mode;

    {
        std::lock_guard<std::mutex> l(streams_mutex_);
        streams_[session->stream_id] = std::move(session);
    }

    // Return a copy (the map owns the original)
    std::lock_guard<std::mutex> l(streams_mutex_);
    auto copy = std::make_unique<StreamSession>(*streams_[session->stream_id]);
    syslog(LOG_INFO, "[NoteFileService] Stream opened: %s mode=%s",
           copy->stream_id.c_str(),
           mode == StreamMode::READ ? "READ" : "WRITE");
    return copy;
}

StreamSession* NoteFileService::get_stream(const std::string& stream_id) {
    std::lock_guard<std::mutex> l(streams_mutex_);
    auto it = streams_.find(stream_id);
    return (it != streams_.end()) ? it->second.get() : nullptr;
}

void NoteFileService::close_stream(const std::string& stream_id) {
    std::lock_guard<std::mutex> l(streams_mutex_);
    streams_.erase(stream_id);
    syslog(LOG_INFO, "[NoteFileService] Stream closed: %s", stream_id.c_str());
}

bool NoteFileService::route_channel(const std::string& stream_id,
                                     NoteDaemon::Channel* channel)
{
    auto* session = get_stream(stream_id);
    if (!session || !channel) return false;

    syslog(LOG_INFO, "[NoteFileService] Routing channel to stream %s",
           stream_id.c_str());

    if (session->mode == StreamMode::READ) {
        auto rs = session->handle->open_read_stream();
        if (rs) {
            rs->transfer_to(channel);
            return true;
        }
    } else {
        auto ws = session->handle->open_write_stream();
        if (ws) {
            ws->receive_from(channel);
            return true;
        }
    }
    return false;
}

// ── Handle registry ──────────────────────────────────────────────────────

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

// ── Global accessor ──────────────────────────────────────────────────────

namespace {
    NoteFileService* g_fs = nullptr;
    std::mutex g_fs_mutex;
}

NoteFileService* get_file_service() {
    std::lock_guard<std::mutex> l(g_fs_mutex);
    return g_fs;
}

void set_file_service(NoteFileService* s) {
    std::lock_guard<std::mutex> l(g_fs_mutex);
    g_fs = s;
}
