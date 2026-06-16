// src/core/note_file_service.cpp
// NoteFileService implementation - auth provider + encrypted file management

#include "note_file_service.h"
#include "note_file_handle.h"
#include "note_file_path.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <array>
#include <filesystem>

namespace fs = std::filesystem;

// =========================================================================
// Utility functions
// =========================================================================

namespace {

    /**
     * Generate random bytes using OpenSSL RAND_bytes.
     */
    std::vector<uint8_t> random_bytes(size_t length) {
        std::vector<uint8_t> buf(length);
        // Use RAND_bytes with fallback to avoid blocking on low-entropy systems
        if (RAND_bytes(buf.data(), static_cast<int>(length)) != 1) {
            // Fallback: use /dev/urandom directly (guaranteed non-blocking)
            FILE* f = fopen("/dev/urandom", "rb");
            if (f) {
                size_t n = fread(buf.data(), 1, length, f);
                fclose(f);
                if (n == length) return buf;
            }
            // Last resort: pseudo-random via rand() + time
            srand(time(nullptr) ^ getpid());
            for (size_t i = 0; i < length; i++)
                buf[i] = static_cast<uint8_t>(rand() & 0xFF);
        }
        return buf;
    }

    /**
     * Constant-time comparison to prevent timing attacks.
     */
    bool constant_time_compare(const std::vector<uint8_t>& a,
                               const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        uint8_t result = 0;
        for (size_t i = 0; i < a.size(); i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * Generate a UUID string for session IDs.
     */
    std::string generate_uuid() {
        auto bytes = random_bytes(16);
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < 16; i++) {
            if (i == 4 || i == 6 || i == 8 || i == 10) ss << "-";
            ss << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return ss.str();
    }

    /**
     * Current time in milliseconds.
     */
    uint64_t now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

} // anonymous namespace

// =========================================================================
// NoteFileService
// =========================================================================

NoteFileService::NoteFileService(const NoteFileConfig& config)
    : config_(config)
{
    // Use default key if provided, otherwise generate one
    if (config_.default_encryption_key.size() == 32) {
        current_key_ = config_.default_encryption_key;
    } else {
        current_key_ = random_bytes(32);
    }
}

NoteFileService::~NoteFileService() {
    shutdown_.store(true);

    // Invalidate all tokens
    std::lock_guard<std::mutex> lock(auth_mutex_);
    active_tokens_.clear();

    // Clear sensitive key material
    current_key_.assign(current_key_.size(), 0);
    current_key_.clear();
    old_key_.assign(old_key_.size(), 0);
    old_key_.clear();
}

// =========================================================================
// Initialization
// =========================================================================

bool NoteFileService::init() {
    if (initialized_.load()) return true;

    syslog(LOG_INFO, "[NoteFileService] Initializing");

    // Create data directory if needed
    try {
        fs::create_directories(config_.data_directory);
    } catch (const std::exception& e) {
        syslog(LOG_ERR, "[NoteFileService] Cannot create data dir: %s", e.what());
        return false;
    }

    // Create ledger directory if needed
    fs::path ledger_parent = fs::path(config_.ledger_path).parent_path();
    if (!ledger_parent.empty()) {
        try {
            fs::create_directories(ledger_parent);
        } catch (const std::exception& e) {
            syslog(LOG_ERR, "[NoteFileService] Cannot create ledger dir: %s", e.what());
            return false;
        }
    }

    // Load auth data
    if (!load_auth_data()) {
        syslog(LOG_INFO, "[NoteFileService] No auth data found (first run)");
    }

    initialized_.store(true);
    syslog(LOG_INFO, "[NoteFileService] Initialized. Password set: %s",
           auth_data_.has_password ? "yes" : "no");
    return true;
}

// =========================================================================
// Authentication
// =========================================================================

bool NoteFileService::load_auth_data() {
    std::lock_guard<std::mutex> lock(auth_mutex_);

    std::ifstream in(config_.settings_path, std::ios::binary);
    if (!in) return false;

    // Read auth data as serialized NoteBytes Object
    in.seekg(0, std::ios::end);
    std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    in.read(reinterpret_cast<char*>(data.data()), size);

    try {
        // Parse as NoteBytes Object
        NoteBytes::Object obj = NoteBytes::Object::deserialize(
            data.data(), data.size());

        auto* bcrypt_val = obj.get(NoteBytes::Value("bcrypt"));
        auto* salt_val = obj.get(NoteBytes::Value("salt"));
        auto* key_val = obj.get(NoteBytes::Value("key"));

        if (bcrypt_val && salt_val) {
            auth_data_.bcrypt_hash = bcrypt_val->data();
            auth_data_.salt = salt_val->data();
            auth_data_.has_password = true;
            if (key_val && key_val->data().size() == 32) {
                current_key_ = key_val->data();
            }
            return true;
        }
    } catch (const std::exception& e) {
        syslog(LOG_ERR, "[NoteFileService] Failed to parse auth data: %s", e.what());
    }
    return false;
}

bool NoteFileService::save_auth_data() {
    // Note: caller must hold auth_mutex_ when calling this
    // (set_initial_password, change_password, and load_auth_data
    //  all call save_auth_data while already holding the lock)

    NoteBytes::Object obj;
    obj.add(NoteBytes::Value("bcrypt"),
            NoteBytes::Value(auth_data_.bcrypt_hash));
    obj.add(NoteBytes::Value("salt"),
            NoteBytes::Value(auth_data_.salt));
    obj.add(NoteBytes::Value("key"),
            NoteBytes::Value(current_key_));

    auto serialized = obj.serialize();

    std::ofstream out(config_.settings_path, std::ios::binary);
    if (!out) return false;

    out.write(reinterpret_cast<const char*>(serialized.data()), serialized.size());
    return out.good();
}

bool NoteFileService::has_password() const {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    return auth_data_.has_password;
}

std::vector<uint8_t> NoteFileService::hash_password(
    const std::string& password) const
{
    // Simplified bcrypt-compatible hashing using SHA-256 + salt
    // In production, use libbcrypt or similar for real bcrypt compatibility
    std::vector<uint8_t> salt = generate_salt(16);

    // SHA-256(salt || password) using EVP API (OpenSSL 3.x compatible)
    std::vector<uint8_t> hash(32);
    unsigned int hash_len = 0;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, salt.data(), salt.size());
    EVP_DigestUpdate(mdctx, password.data(), password.size());
    EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len);
    hash.resize(hash_len);
    EVP_MD_CTX_free(mdctx);

    // Prepend salt to hash for storage
    std::vector<uint8_t> stored;
    stored.insert(stored.end(), salt.begin(), salt.end());
    stored.insert(stored.end(), hash.begin(), hash.end());
    return stored;
}

bool NoteFileService::verify_password(
    const std::string& password,
    const std::vector<uint8_t>& hash) const
{
    if (hash.size() < 16) return false;

    // Extract salt (first 16 bytes)
    std::vector<uint8_t> salt(hash.begin(), hash.begin() + 16);
    std::vector<uint8_t> expected_hash(hash.begin() + 16, hash.end());

    // Recompute: SHA-256(salt || password) using EVP API
    std::vector<uint8_t> computed(32);
    unsigned int hash_len = 0;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, salt.data(), salt.size());
    EVP_DigestUpdate(mdctx, password.data(), password.size());
    EVP_DigestFinal_ex(mdctx, computed.data(), &hash_len);
    computed.resize(hash_len);
    EVP_MD_CTX_free(mdctx);

    return constant_time_compare(computed, expected_hash);
}

std::vector<uint8_t> NoteFileService::generate_salt(size_t length) const {
    return random_bytes(length);
}

std::vector<uint8_t> NoteFileService::derive_key(
    const std::string& password,
    const std::vector<uint8_t>& salt) const
{
    // PBKDF2-compatible key derivation using HMAC-SHA256
    // Uses PKCS5_PBKDF2_HMAC from OpenSSL
    std::vector<uint8_t> key(32); // 256-bit key
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                       salt.data(), static_cast<int>(salt.size()),
                       65536,  // 65536 iterations (matches Java)
                       EVP_sha256(),
                       32, key.data());
    return key;
}

bool NoteFileService::set_initial_password(const std::string& password) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    if (auth_data_.has_password) {
        syslog(LOG_ERR, "[NoteFileService] Password already set");
        return false;
    }

    // Generate salt and derive key
    auth_data_.salt = generate_salt(16);
    auth_data_.bcrypt_hash = hash_password(password);
    current_key_ = derive_key(password, auth_data_.salt);
    auth_data_.has_password = true;

    if (!save_auth_data()) {
        syslog(LOG_ERR, "[NoteFileService] Failed to save auth data");
        auth_data_.has_password = false;
        return false;
    }

    syslog(LOG_INFO, "[NoteFileService] Initial password set");
    return true;
}

bool NoteFileService::change_password(const std::string& old_password,
                                       const std::string& new_password) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    if (!auth_data_.has_password) return false;

    // Verify old password
    if (!verify_password(old_password, auth_data_.bcrypt_hash)) {
        syslog(LOG_WARNING, "[NoteFileService] Password change: old password invalid");
        return false;
    }

    // Store old key for re-encryption
    old_key_ = current_key_;

    // Generate new salt and derive new key
    auto new_salt = generate_salt(16);
    auto new_hash = hash_password(new_password);
    auto new_key = derive_key(new_password, new_salt);

    // Update auth data
    auth_data_.salt = new_salt;
    auth_data_.bcrypt_hash = new_hash;
    current_key_ = new_key;

    if (!save_auth_data()) {
        syslog(LOG_ERR, "[NoteFileService] Password change: save failed");
        return false;
    }

    // Re-encrypt files with old key → new key
    // (current_key_ is the new key, old_key_ is the old one)
    auto old_key_copy = old_key_;
    auto new_key_copy = current_key_;
    
    auth_mutex_.unlock();
    
    bool re_encrypt_ok = NoteFileLedger::re_encrypt_ledger(
        config_.ledger_path, old_key_copy, new_key_copy, nullptr);

    auth_mutex_.lock();

    if (!re_encrypt_ok) {
        syslog(LOG_ERR, "[NoteFileService] Password change: re-encrypt failed");
        return false;
    }

    old_key_.clear();
    syslog(LOG_INFO, "[NoteFileService] Password changed successfully");
    return true;
}

std::unique_ptr<AuthToken> NoteFileService::authenticate(
    const std::string& password, pid_t client_pid)
{
    std::lock_guard<std::mutex> lock(auth_mutex_);

    if (!auth_data_.has_password) {
        syslog(LOG_WARNING, "[NoteFileService] Auth attempted but no password set");
        return nullptr;
    }

    if (!verify_password(password, auth_data_.bcrypt_hash)) {
        syslog(LOG_WARNING, "[NoteFileService] Auth failed for pid=%d", client_pid);
        return nullptr;
    }

    // Derive the key (matches what's in current_key_)
    auto derived = derive_key(password, auth_data_.salt);

    // Create session token
    auto token = std::make_unique<AuthToken>();
    token->session_id = generate_uuid();
    token->client_pid = client_pid;
    token->derived_key = derived;
    token->created_at_ms = now_ms();

    // Save session_id BEFORE move so we can look it up afterwards
    std::string saved_session_id = token->session_id;
    active_tokens_[saved_session_id] = std::move(token);

    syslog(LOG_INFO, "[NoteFileService] Auth success for pid=%d, session=%s",
           client_pid, saved_session_id.c_str());

    // Return a copy of the token (the map owns the original)
    auto& stored = active_tokens_[saved_session_id];
    auto result = std::make_unique<AuthToken>(*stored);
    return result;
}

void NoteFileService::invalidate_token(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    auto it = active_tokens_.find(session_id);
    if (it != active_tokens_.end()) {
        it->second->valid = false;
        active_tokens_.erase(it);
        syslog(LOG_INFO, "[NoteFileService] Token invalidated: %s", session_id.c_str());
    }
}

// =========================================================================
// File operations
// =========================================================================

std::shared_ptr<NoteFileHandle> NoteFileService::get_file(
    const std::vector<NoteBytes::Value>& path_segments)
{
    if (!initialized_.load()) return nullptr;

    // Build path string for lookup
    std::string path_string;
    for (size_t i = 0; i < path_segments.size(); i++) {
        if (i > 0) path_string += "/";
        path_string += path_segments[i].as_string();
    }

    // Check existing handle
    {
        std::lock_guard<std::mutex> lock(handles_mutex_);
        auto it = handles_.find(path_string);
        if (it != handles_.end()) {
            auto handle = it->second.lock();
            if (handle) return handle;
            handles_.erase(it); // Stale weak_ptr
        }
    }

    // Resolve path to actual file on disk
    std::string file_path = resolve_or_create_path(path_segments);
    if (file_path.empty()) {
        syslog(LOG_ERR, "[NoteFileService] Failed to resolve path: %s",
               path_string.c_str());
        return nullptr;
    }

    // Create handle
    auto handle = std::make_shared<NoteFileHandle>(
        file_path, path_segments, path_string, shared_from_this());

    // Register handle
    {
        std::lock_guard<std::mutex> lock(handles_mutex_);
        handles_[path_string] = handle;
    }

    syslog(LOG_INFO, "[NoteFileService] File handle created: %s -> %s",
           path_string.c_str(), file_path.c_str());
    return handle;
}

std::shared_ptr<NoteFileHandle> NoteFileService::get_file(
    const std::vector<std::string>& path_segments)
{
    std::vector<NoteBytes::Value> segments;
    for (const auto& s : path_segments) {
        segments.emplace_back(s);
    }
    return get_file(segments);
}

bool NoteFileService::file_exists(
    const std::vector<NoteBytes::Value>& path_segments)
{
    // For now, just check if a handle resolves
    auto handle = get_file(path_segments);
    return handle != nullptr && handle->exists();
}

bool NoteFileService::delete_file(
    const std::vector<NoteBytes::Value>& path_segments, bool recursive)
{
    if (!initialized_.load()) return false;

    std::string path_string;
    for (size_t i = 0; i < path_segments.size(); i++) {
        if (i > 0) path_string += "/";
        path_string += path_segments[i].as_string();
    }

    // Close any existing handle
    {
        std::lock_guard<std::mutex> lock(handles_mutex_);
        handles_.erase(path_string);
    }

    // Delete from ledger
    NoteFilePath note_path(config_.ledger_path, path_segments,
                           config_.data_directory, recursive);
    return NoteFileLedger::delete_from_path(note_path, current_key_);
}

std::vector<std::string> NoteFileService::list_files() {
    if (!initialized_.load()) return {};

    struct stat st;
    if (stat(config_.ledger_path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        return {};
    }

    return NoteFileLedger::collect_file_paths(config_.ledger_path, current_key_);
}

// =========================================================================
// Key management
// =========================================================================

bool NoteFileService::re_encrypt_all(const std::vector<uint8_t>& new_key) {
    syslog(LOG_INFO, "[NoteFileService] Re-encrypting all files");

    // Re-encrypt ledger and all data files
    if (!NoteFileLedger::re_encrypt_ledger(config_.ledger_path,
                                           current_key_, new_key,
                                           nullptr)) {
        syslog(LOG_ERR, "[NoteFileService] re_encrypt_all failed");
        return false;
    }

    current_key_ = new_key;
    return true;
}

// =========================================================================
// Internal: path resolution, encrypt/decrypt
// =========================================================================

std::string NoteFileService::resolve_or_create_path(
    const std::vector<NoteBytes::Value>& path_segments)
{
    std::lock_guard<std::mutex> lock(ledger_mutex_);

    NoteFilePath note_path(config_.ledger_path, path_segments,
                           config_.data_directory);
    return NoteFileLedger::find_or_create_path(note_path, current_key_);
}

int NoteFileService::decrypt_file(const std::string& file_path) {
    struct stat st;
    if (stat(file_path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        syslog(LOG_WARNING, "[NoteFileService] decrypt_file: not found: %s",
               file_path.c_str());
        return -1;
    }

    // Create a temp path for decrypted output
    std::string tmp_path = file_path + ".decrypted";

    if (!NoteFileLedger::aes_decrypt_file(file_path, tmp_path, current_key_)) {
        syslog(LOG_ERR, "[NoteFileService] decrypt_file failed: %s",
               file_path.c_str());
        return -1;
    }

    // Open the decrypted file for reading
    int fd = ::open(tmp_path.c_str(), O_RDONLY);
    if (fd < 0) {
        syslog(LOG_ERR, "[NoteFileService] Cannot open decrypted file: %s",
               strerror(errno));
        unlink(tmp_path.c_str());
        return -1;
    }

    // Unlink now — fd stays valid until closed, then file vanishes automatically
    unlink(tmp_path.c_str());
    return fd;
}

bool NoteFileService::encrypt_file_swap(const std::string& file_path,
                                         int pipe_fd) {
    if (pipe_fd < 0) return false;

    // Read plaintext from pipe
    std::vector<uint8_t> plaintext;
    uint8_t buf[65536];
    ssize_t n;
    while ((n = ::read(pipe_fd, buf, sizeof(buf))) > 0) {
        plaintext.insert(plaintext.end(), buf, buf + n);
    }
    ::close(pipe_fd);

    // Write encrypted to temp file, then atomically swap
    std::string tmp_path = file_path + ".encrypted";

    if (!NoteFileLedger::aes_encrypt_buffer_to_file(plaintext, tmp_path,
                                                     current_key_)) {
        syslog(LOG_ERR, "[NoteFileService] encrypt_file_swap failed: %s",
               file_path.c_str());
        unlink(tmp_path.c_str());
        return false;
    }

    // Atomic swap
    if (rename(tmp_path.c_str(), file_path.c_str()) != 0) {
        syslog(LOG_ERR, "[NoteFileService] rename failed: %s", strerror(errno));
        unlink(tmp_path.c_str());
        return false;
    }

    return true;
}

bool NoteFileService::encrypt_new_file(const std::string& file_path,
                                        int pipe_fd) {
    return encrypt_file_swap(file_path, pipe_fd);
}

std::vector<uint8_t> NoteFileService::read_file_to_buffer(
    const std::string& file_path)
{
    struct stat st;
    if (stat(file_path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        syslog(LOG_WARNING, "[NoteFileService] read_file_to_buffer: not found: %s",
               file_path.c_str());
        return {};
    }
    return NoteFileLedger::aes_decrypt_to_buffer(file_path, current_key_);
}

bool NoteFileService::encrypt_buffer_to_file(
    const std::string& file_path,
    const std::vector<uint8_t>& data)
{
    std::string tmp_path = file_path + ".encrypted";
    if (!NoteFileLedger::aes_encrypt_buffer_to_file(data, tmp_path,
                                                     current_key_)) {
        syslog(LOG_ERR, "[NoteFileService] encrypt_buffer_to_file failed: %s",
               file_path.c_str());
        unlink(tmp_path.c_str());
        return false;
    }
    if (rename(tmp_path.c_str(), file_path.c_str()) != 0) {
        syslog(LOG_ERR, "[NoteFileService] rename failed: %s", strerror(errno));
        unlink(tmp_path.c_str());
        return false;
    }
    return true;
}

bool NoteFileService::create_pipe(int& read_fd, int& write_fd) {
    int pipefd[2];
    if (::pipe(pipefd) < 0) {
        syslog(LOG_ERR, "[NoteFileService] pipe() failed: %s", strerror(errno));
        return false;
    }
    read_fd = pipefd[0];
    write_fd = pipefd[1];
    return true;
}

std::string NoteFileService::generate_data_file_path() {
    auto uuid_bytes = random_bytes(16);
    std::stringstream ss;
    ss << config_.data_directory << "/";
    for (size_t i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(uuid_bytes[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) ss << "-";
    }
    ss << ".dat";
    return ss.str();
}

void NoteFileService::register_handle(NoteFileHandle* handle) {
    // Handles register themselves in get_file
    (void)handle;
}

void NoteFileService::unregister_handle(NoteFileHandle* handle) {
    if (!handle) return;
    std::lock_guard<std::mutex> lock(handles_mutex_);
    // Remove from registry if the weak_ptr points to this handle
    for (auto it = handles_.begin(); it != handles_.end(); ) {
        auto locked = it->second.lock();
        if (!locked || locked.get() == handle) {
            it = handles_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t NoteFileService::active_handle_count() const {
    std::lock_guard<std::mutex> lock(handles_mutex_);
    size_t count = 0;
    for (const auto& [_, weak] : handles_) {
        if (!weak.expired()) count++;
    }
    return count;
}

// =========================================================================
// Static global accessor
// =========================================================================

namespace {
    NoteFileService* g_file_service = nullptr;
    std::mutex g_file_service_mutex;
}

NoteFileService* get_file_service() {
    std::lock_guard<std::mutex> lock(g_file_service_mutex);
    return g_file_service;
}

void set_file_service(NoteFileService* service) {
    std::lock_guard<std::mutex> lock(g_file_service_mutex);
    g_file_service = service;
}
