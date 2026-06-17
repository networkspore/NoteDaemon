// src/core/note_file_service.cpp
// NoteFileService – three-layer auth: server key + admin API key + key locker

#include "note_file_service.h"
#include "note_file_handle.h"
#include "note_file_path.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>

namespace fs = std::filesystem;

// ── Utility helpers ──────────────────────────────────────────────────────

namespace {

    std::vector<uint8_t> random_bytes(size_t length) {
        std::vector<uint8_t> buf(length);
        if (RAND_bytes(buf.data(), static_cast<int>(length)) != 1) {
            FILE* f = fopen("/dev/urandom", "rb");
            if (f) {
                size_t r = fread(buf.data(), 1, length, f);
                (void)r;
                fclose(f);
            }
        }
        return buf;
    }

    bool constant_time_compare(const std::vector<uint8_t>& a,
                               const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        uint8_t result = 0;
        for (size_t i = 0; i < a.size(); i++) result |= a[i] ^ b[i];
        return result == 0;
    }

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

    uint64_t now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

} // anonymous namespace

// ── Forward declarations ─────────────────────────────────────────────────

static bool parse_locker_data_impl(
    const std::vector<uint8_t>& data,
    KeyLocker& locker,
    std::unordered_map<std::string, ClientEntry>& clients);

// ── NoteFileService ──────────────────────────────────────────────────────

NoteFileService::NoteFileService(const NoteFileConfig& config)
    : config_(config) {}

NoteFileService::~NoteFileService() {
    shutdown_.store(true);
    std::lock_guard<std::mutex> al(admin_mutex_);
    admin_tokens_.clear();
    std::lock_guard<std::mutex> ll(locker_mutex_);
    locker_.clients.clear();
    locker_key_.assign(locker_key_.size(), 0);
    locker_key_.clear();
}

// ── Init ─────────────────────────────────────────────────────────────────

bool NoteFileService::init() {
    if (initialized_.load()) return true;

    syslog(LOG_INFO, "[NoteFileService] Initializing with three-layer auth");

    // Create data directory
    try { fs::create_directories(config_.data_directory); }
    catch (const std::exception& e) {
        syslog(LOG_ERR, "[NoteFileService] Cannot create data dir: %s", e.what());
        return false;
    }

    // Load or generate server key pair
    if (!load_or_generate_server_key()) {
        syslog(LOG_ERR, "[NoteFileService] Failed to init server key");
        return false;
    }

    // Load admin API key if exists
    std::ifstream akf(config_.admin_api_key_path, std::ios::binary);
    if (akf) {
        akf.seekg(0, std::ios::end);
        std::streamsize sz = akf.tellg();
        akf.seekg(0, std::ios::beg);
        admin_api_key_hash_.resize(sz);
        akf.read(reinterpret_cast<char*>(admin_api_key_hash_.data()), sz);
        syslog(LOG_INFO, "[NoteFileService] Admin API key loaded");
    }

    // Load key locker if exists
    if (!load_key_locker()) {
        syslog(LOG_INFO, "[NoteFileService] No key locker yet (first run)");
    }

    initialized_.store(true);
    syslog(LOG_INFO, "[NoteFileService] Initialized. Admin key: %s, Locker: %s",
           admin_api_key_hash_.empty() ? "NOT SET" : "SET",
           locker_key_.empty() ? "NOT SET" : "SET");
    return true;
}

// ── Server key ───────────────────────────────────────────────────────────

bool NoteFileService::load_or_generate_server_key() {
    std::ifstream in(config_.server_key_path, std::ios::binary);
    if (in) {
        // Read existing 64-byte key (seed + public)
        in.seekg(0, std::ios::end);
        std::streamsize sz = in.tellg();
        in.seekg(0, std::ios::beg);
        std::vector<uint8_t> buf(sz);
        in.read(reinterpret_cast<char*>(buf.data()), sz);
        if (sz >= 64) {
            server_key_.private_key.assign(buf.begin(), buf.begin() + 32);
            server_key_.public_key.assign(buf.begin() + 32, buf.begin() + 64);
            syslog(LOG_INFO, "[NoteFileService] Loaded server key from %s",
                   config_.server_key_path.c_str());
            return true;
        }
    }

    // Generate new Ed25519 key pair
    syslog(LOG_INFO, "[NoteFileService] Generating new Ed25519 server key");
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                    nullptr, 0);
    if (!pkey) {
        // Use fallback: AES-256 key as server key
        server_key_.private_key = random_bytes(32);
        // For the public key, we just use a second random 32 bytes
        // (In production, use proper Ed25519 via EVP_PKEY_keygen)
        server_key_.public_key = random_bytes(32);
    } else {
        size_t priv_len = 32;
        EVP_PKEY_get_raw_private_key(pkey, server_key_.private_key.data(), &priv_len);
        server_key_.private_key.resize(priv_len);
        size_t pub_len = 32;
        EVP_PKEY_get_raw_public_key(pkey, server_key_.public_key.data(), &pub_len);
        server_key_.public_key.resize(pub_len);
        EVP_PKEY_free(pkey);
    }

    return save_server_key();
}

bool NoteFileService::save_server_key() {
    try {
        fs::create_directories(
            fs::path(config_.server_key_path).parent_path());
    } catch (...) {}

    std::vector<uint8_t> buf;
    buf.insert(buf.end(), server_key_.private_key.begin(), server_key_.private_key.end());
    buf.insert(buf.end(), server_key_.public_key.begin(), server_key_.public_key.end());

    std::ofstream out(config_.server_key_path, std::ios::binary);
    if (!out) {
        syslog(LOG_ERR, "[NoteFileService] Cannot write server key to %s",
               config_.server_key_path.c_str());
        return false;
    }
    out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    out.close();

    // Set permissions: owner read/write only
    chmod(config_.server_key_path.c_str(), 0600);

    syslog(LOG_INFO, "[NoteFileService] Server key saved to %s (%zu bytes)",
           config_.server_key_path.c_str(), buf.size());
    return true;
}

std::vector<uint8_t> NoteFileService::wrap_with_server_key(
    const std::vector<uint8_t>& data) const
{
    // Simple XOR "wrap" using the server key as a symmetric key
    // In production, use proper key wrapping with AES-KW or similar
    std::vector<uint8_t> result(data);
    for (size_t i = 0; i < result.size(); i++)
        result[i] ^= server_key_.private_key[i % server_key_.private_key.size()];
    return result;
}

std::vector<uint8_t> NoteFileService::unwrap_with_server_key(
    const std::vector<uint8_t>& wrapped) const
{
    return wrap_with_server_key(wrapped);  // XOR is its own inverse
}

// ── Admin API key ────────────────────────────────────────────────────────

bool NoteFileService::set_admin_api_key(const std::string& api_key) {
    std::lock_guard<std::mutex> lock(admin_mutex_);
    if (!admin_api_key_hash_.empty()) {
        syslog(LOG_ERR, "[NoteFileService] Admin API key already set");
        return false;
    }
    // Hash using SHA-256 as a simple keyed hash (use bcrypt in production)
    auto salt = random_bytes(16);
    std::vector<uint8_t> hash(32);
    unsigned int hlen = 0;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md, salt.data(), salt.size());
    EVP_DigestUpdate(md, api_key.data(), api_key.size());
    EVP_DigestFinal_ex(md, hash.data(), &hlen);
    EVP_MD_CTX_free(md);

    admin_api_key_hash_.clear();
    admin_api_key_hash_.insert(admin_api_key_hash_.end(), salt.begin(), salt.end());
    admin_api_key_hash_.insert(admin_api_key_hash_.end(), hash.begin(), hash.end());

    // Save to disk
    std::ofstream out(config_.admin_api_key_path, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(admin_api_key_hash_.data()),
              admin_api_key_hash_.size());
    out.close();
    chmod(config_.admin_api_key_path.c_str(), 0600);

    syslog(LOG_INFO, "[NoteFileService] Admin API key set");
    return true;
}

bool NoteFileService::verify_admin_api_key(const std::string& api_key) const {
    if (admin_api_key_hash_.size() < 16) return false;
    auto salt = std::vector<uint8_t>(admin_api_key_hash_.begin(),
                                     admin_api_key_hash_.begin() + 16);
    auto expected = std::vector<uint8_t>(admin_api_key_hash_.begin() + 16,
                                         admin_api_key_hash_.end());

    std::vector<uint8_t> computed(32);
    unsigned int hlen = 0;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md, salt.data(), salt.size());
    EVP_DigestUpdate(md, api_key.data(), api_key.size());
    EVP_DigestFinal_ex(md, computed.data(), &hlen);
    EVP_MD_CTX_free(md);

    return constant_time_compare(computed, expected);
}

bool NoteFileService::has_admin_api_key() const {
    std::lock_guard<std::mutex> lock(admin_mutex_);
    return !admin_api_key_hash_.empty();
}

std::unique_ptr<AdminToken> NoteFileService::authenticate_admin(
    const std::string& api_key, pid_t client_pid)
{
    std::lock_guard<std::mutex> lock(admin_mutex_);
    if (!verify_admin_api_key(api_key)) return nullptr;

    auto token = std::make_unique<AdminToken>();
    token->session_id = generate_uuid();
    token->client_pid = client_pid;
    token->created_at_ms = now_ms();
    std::string sid = token->session_id;
    admin_tokens_[sid] = std::move(token);
    auto result = std::make_unique<AdminToken>(*admin_tokens_[sid]);
    syslog(LOG_INFO, "[NoteFileService] Admin auth: pid=%d session=%s",
           client_pid, sid.c_str());
    return result;
}

void NoteFileService::invalidate_admin_token(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(admin_mutex_);
    admin_tokens_.erase(session_id);
}

// ── Key locker ───────────────────────────────────────────────────────────

std::vector<uint8_t> NoteFileService::derive_locker_key(
    const std::string& password) const
{
    // Locker key = SHA-256(server_private_key || password)
    // This binds the locker to this specific server instance
    std::vector<uint8_t> input;
    input.insert(input.end(), server_key_.private_key.begin(),
                 server_key_.private_key.end());
    input.insert(input.end(), password.begin(), password.end());

    std::vector<uint8_t> key(32);
    unsigned int hlen = 0;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md, input.data(), input.size());
    EVP_DigestFinal_ex(md, key.data(), &hlen);
    EVP_MD_CTX_free(md);
    return key;
}

bool NoteFileService::set_locker_password(const std::string& password) {
    std::lock_guard<std::mutex> lock(locker_mutex_);
    if (!locker_key_.empty()) {
        syslog(LOG_ERR, "[NoteFileService] Locker password already set");
        return false;
    }

    locker_.salt = random_bytes(16);
    // Locker key derived from password + server key binding
    locker_key_ = derive_locker_key(password);

    // Wrap the locker key with the server key for storage
    locker_.wrapped_locker_key = wrap_with_server_key(locker_key_);

    // Save empty locker
    if (!save_key_locker()) return false;

    syslog(LOG_INFO, "[NoteFileService] Key locker password set");
    return true;
}

bool NoteFileService::change_locker_password(const std::string& old_pw,
                                              const std::string& new_pw) {
    std::lock_guard<std::mutex> lock(locker_mutex_);
    auto expected = derive_locker_key(old_pw);
    if (!constant_time_compare(expected, locker_key_)) {
        syslog(LOG_WARNING, "[NoteFileService] Wrong locker password");
        return false;
    }
    locker_key_ = derive_locker_key(new_pw);
    locker_.wrapped_locker_key = wrap_with_server_key(locker_key_);
    return save_key_locker();
}

bool NoteFileService::save_key_locker() {
    // Serialize locker to NoteBytes::Object
    NoteBytes::Object obj;
    obj.add(NoteBytes::Value("salt"),
            NoteBytes::Value(locker_.salt));
    obj.add(NoteBytes::Value("wrapped_key"),
            NoteBytes::Value(locker_.wrapped_locker_key));

    // Serialize clients
    NoteBytes::Object clients_obj;
    for (const auto& [cid, entry] : locker_.clients) {
        NoteBytes::Object client_obj;
        client_obj.add(NoteBytes::Value("bcrypt"),
                       NoteBytes::Value(entry.bcrypt_hash));
        client_obj.add(NoteBytes::Value("salt"),
                       NoteBytes::Value(entry.salt));
        if (entry.has_encryption) {
            client_obj.add(NoteBytes::Value("enc_key"),
                           NoteBytes::Value(entry.encryption_key));
            client_obj.add(NoteBytes::Value("encrypted"),
                           NoteBytes::Value(true));
        }
        if (entry.has_old()) {
            client_obj.add(NoteBytes::Value("old_bcrypt"),
                           NoteBytes::Value(entry.old_bcrypt_hash));
            client_obj.add(NoteBytes::Value("old_salt"),
                           NoteBytes::Value(entry.old_salt));
            client_obj.add(NoteBytes::Value("old_enc_key"),
                           NoteBytes::Value(entry.old_encryption_key));
        }
        clients_obj.add(NoteBytes::Value(cid), client_obj.as_value());
    }
    obj.add(NoteBytes::Value("clients"), clients_obj.as_value());

    auto serialized = obj.serialize();

    if (locker_key_.empty()) {
        // No locker password — store plaintext (permission-protected on disk)
        std::ofstream out(config_.key_locker_path, std::ios::binary);
        if (!out) return false;
        out.write(reinterpret_cast<const char*>(serialized.data()), serialized.size());
        out.close();
    } else {
        // Encrypt with locker key and write
        if (!NoteFileLedger::aes_encrypt_buffer_to_file(
                serialized, config_.key_locker_path, locker_key_)) {
            syslog(LOG_ERR, "[NoteFileService] Failed to save key locker");
            return false;
        }
    }
    chmod(config_.key_locker_path.c_str(), 0600);
    return true;
}

bool NoteFileService::load_key_locker() {
    struct stat st;
    if (stat(config_.key_locker_path.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
        return false;

    // Read the raw locker data
    std::vector<uint8_t> data;
    {
        std::ifstream in(config_.key_locker_path, std::ios::binary);
        if (!in) return false;
        in.seekg(0, std::ios::end);
        data.resize(in.tellg());
        in.seekg(0, std::ios::beg);
        in.read(reinterpret_cast<char*>(data.data()), data.size());
    }

    if (locker_key_.empty()) {
        // No locker password — stored plaintext
        return parse_locker_data_impl(data, locker_, locker_.clients);
    }

    // Decrypt with locker key
    // We need to re-read via the AES decrypt which expects encrypted format
    auto decrypted = NoteFileLedger::aes_decrypt_to_buffer(
        config_.key_locker_path, locker_key_);
    if (!decrypted.empty()) {
        return parse_locker_data_impl(decrypted, locker_, locker_.clients);
    }

    return false;
}

// Helper to parse loaded locker data
static bool parse_locker_data_impl(const std::vector<uint8_t>& data,
                                    KeyLocker& locker,
                                    std::unordered_map<std::string, ClientEntry>& clients)
{
    try {
        auto obj = NoteBytes::Object::deserialize(data.data(), data.size());
        auto* salt_val = obj.get(NoteBytes::Value("salt"));
        auto* wk_val = obj.get(NoteBytes::Value("wrapped_key"));
        if (salt_val) locker.salt = salt_val->data();
        if (wk_val) locker.wrapped_locker_key = wk_val->data();

        auto* clients_val = obj.get(NoteBytes::Value("clients"));
        if (clients_val && clients_val->type() == NoteBytes::Type::OBJECT) {
            auto clients_obj = NoteBytes::as_object(*clients_val);
            for (const auto& pair : clients_obj.pairs()) {
                std::string cid = pair.key().as_string();
                if (pair.value().type() == NoteBytes::Type::OBJECT) {
                    auto cobj = NoteBytes::as_object(pair.value());
                    ClientEntry entry;
                    auto* bc = cobj.get(NoteBytes::Value("bcrypt"));
                    auto* sa = cobj.get(NoteBytes::Value("salt"));
                    if (bc) entry.bcrypt_hash = bc->data();
                    if (sa) entry.salt = sa->data();
                    auto* ek = cobj.get(NoteBytes::Value("enc_key"));
                    if (ek) { entry.encryption_key = ek->data(); entry.has_encryption = true; }
                    auto* ob = cobj.get(NoteBytes::Value("old_bcrypt"));
                    auto* os = cobj.get(NoteBytes::Value("old_salt"));
                    auto* oe = cobj.get(NoteBytes::Value("old_enc_key"));
                    if (ob) entry.old_bcrypt_hash = ob->data();
                    if (os) entry.old_salt = os->data();
                    if (oe) entry.old_encryption_key = oe->data();
                    clients[cid] = std::move(entry);
                }
            }
        }
        return true;
    } catch (const std::exception& e) {
        syslog(LOG_ERR, "[NoteFileService] Failed to parse locker: %s", e.what());
        return false;
    }
}

// ── Client management ────────────────────────────────────────────────────

bool NoteFileService::add_client(const std::string& client_id,
                                  const std::string& password) {
    std::lock_guard<std::mutex> lock(locker_mutex_);
    if (locker_.clients.count(client_id)) {
        syslog(LOG_WARNING, "[NoteFileService] Client already exists: %s",
               client_id.c_str());
        return false;
    }

    ClientEntry entry;
    if (!password.empty()) {
        // Client wants encryption
        entry.salt = generate_salt(16);
        entry.bcrypt_hash = hash_password(password);
        entry.encryption_key = derive_key(password, entry.salt);
        entry.has_encryption = true;
    }

    locker_.clients[client_id] = std::move(entry);
    bool ok = save_key_locker();

    // Create client data directory
    try { fs::create_directories(client_data_dir(client_id)); }
    catch (...) {}

    syslog(LOG_INFO, "[NoteFileService] Client added: %s (encryption=%s)",
           client_id.c_str(), password.empty() ? "OFF" : "ON");
    return ok;
}

bool NoteFileService::remove_client(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(locker_mutex_);
    auto it = locker_.clients.find(client_id);
    if (it == locker_.clients.end()) return false;
    locker_.clients.erase(it);
    return save_key_locker();
}

std::vector<std::string> NoteFileService::list_clients() const {
    std::lock_guard<std::mutex> lock(locker_mutex_);
    std::vector<std::string> result;
    for (const auto& [cid, _] : locker_.clients)
        result.push_back(cid);
    return result;
}

bool NoteFileService::change_client_password(
    const std::string& client_id,
    const std::string& old_password,
    const std::string& new_password)
{
    std::lock_guard<std::mutex> lock(locker_mutex_);
    auto it = locker_.clients.find(client_id);
    if (it == locker_.clients.end()) {
        syslog(LOG_WARNING, "[NoteFileService] Client not found: %s",
               client_id.c_str());
        return false;
    }

    ClientEntry& entry = it->second;

    // Verify old password
    if (!entry.has_encryption) {
        syslog(LOG_WARNING, "[NoteFileService] Client has no encryption: %s",
               client_id.c_str());
        return false;
    }
    if (!verify_password(old_password, entry.bcrypt_hash)) {
        syslog(LOG_WARNING, "[NoteFileService] Wrong password for client: %s",
               client_id.c_str());
        return false;
    }

    // Store old key for re-encryption
    entry.old_bcrypt_hash = entry.bcrypt_hash;
    entry.old_salt = entry.salt;
    entry.old_encryption_key = entry.encryption_key;

    // Derive new key
    entry.salt = generate_salt(16);
    entry.bcrypt_hash = hash_password(new_password);
    auto new_key = derive_key(new_password, entry.salt);
    auto old_key = entry.encryption_key;
    entry.encryption_key = new_key;

    // Save locker first (so new key is persisted)
    if (!save_key_locker()) return false;

    // Release lock during re-encrypt
    locker_mutex_.unlock();

    // Re-encrypt all client files
    auto ledger = client_ledger_path(client_id);
    NoteFileLedger::re_encrypt_ledger(ledger, old_key, new_key, nullptr);

    locker_mutex_.lock();

    // Clear old fields
    entry.old_bcrypt_hash.clear();
    entry.old_salt.clear();
    entry.old_encryption_key.clear();
    save_key_locker();

    syslog(LOG_INFO, "[NoteFileService] Client password changed: %s",
           client_id.c_str());
    return true;
}

bool NoteFileService::client_has_encryption(const std::string& client_id) const {
    std::lock_guard<std::mutex> lock(locker_mutex_);
    auto it = locker_.clients.find(client_id);
    return it != locker_.clients.end() && it->second.has_encryption;
}

std::vector<uint8_t> NoteFileService::get_client_key(
    const std::string& client_id) const
{
    std::lock_guard<std::mutex> lock(locker_mutex_);
    auto it = locker_.clients.find(client_id);
    if (it == locker_.clients.end())
        return {};
    if (it->second.has_encryption)
        return it->second.encryption_key;
    // No encryption password — derive deterministic key from server key
    // This keeps the ledger encrypted without requiring a user password
    std::vector<uint8_t> input;
    input.insert(input.end(), server_key_.private_key.begin(),
                 server_key_.private_key.end());
    input.insert(input.end(), client_id.begin(), client_id.end());
    std::vector<uint8_t> derived(32);
    unsigned int hlen = 0;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md, input.data(), input.size());
    EVP_DigestFinal_ex(md, derived.data(), &hlen);
    EVP_MD_CTX_free(md);
    return derived;
}

NoteFileService::ClientAuthResult NoteFileService::authenticate_client(
    const std::string& client_id, const std::string& password)
{
    std::lock_guard<std::mutex> lock(locker_mutex_);
    auto it = locker_.clients.find(client_id);
    if (it == locker_.clients.end())
        return {{}, false};

    ClientEntry& entry = it->second;
    if (!entry.has_encryption) {
        // No encryption — client auth is just existence check
        return {{}, true};
    }

    if (!verify_password(password, entry.bcrypt_hash))
        return {{}, false};

    return {entry.encryption_key, true};
}

// ── Password helpers ─────────────────────────────────────────────────────

std::vector<uint8_t> NoteFileService::hash_password(
    const std::string& password) const
{
    auto salt = generate_salt(16);
    std::vector<uint8_t> hash(32);
    unsigned int hlen = 0;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md, salt.data(), salt.size());
    EVP_DigestUpdate(md, password.data(), password.size());
    EVP_DigestFinal_ex(md, hash.data(), &hlen);
    hash.resize(hlen);
    EVP_MD_CTX_free(md);

    std::vector<uint8_t> stored;
    stored.insert(stored.end(), salt.begin(), salt.end());
    stored.insert(stored.end(), hash.begin(), hash.end());
    return stored;
}

bool NoteFileService::verify_password(const std::string& password,
                                       const std::vector<uint8_t>& hash) const
{
    if (hash.size() < 16) return false;
    auto salt = std::vector<uint8_t>(hash.begin(), hash.begin() + 16);
    auto expected = std::vector<uint8_t>(hash.begin() + 16, hash.end());

    std::vector<uint8_t> computed(32);
    unsigned int hlen = 0;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
    EVP_DigestUpdate(md, salt.data(), salt.size());
    EVP_DigestUpdate(md, password.data(), password.size());
    EVP_DigestFinal_ex(md, computed.data(), &hlen);
    EVP_MD_CTX_free(md);

    return constant_time_compare(computed, expected);
}

std::vector<uint8_t> NoteFileService::derive_key(
    const std::string& password,
    const std::vector<uint8_t>& salt) const
{
    std::vector<uint8_t> key(32);
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                       salt.data(), static_cast<int>(salt.size()),
                       65536, EVP_sha256(), 32, key.data());
    return key;
}

std::vector<uint8_t> NoteFileService::generate_salt(size_t length) const {
    return random_bytes(length);
}

std::vector<uint8_t> NoteFileService::random_bytes(size_t length) const {
    return ::random_bytes(length);
}

// ── File operations (per-client) ─────────────────────────────────────────

std::string NoteFileService::client_data_dir(const std::string& client_id) const {
    return config_.data_directory + "/" + client_id;
}

std::string NoteFileService::client_ledger_path(const std::string& client_id) const {
    return client_data_dir(client_id) + "/ledger.dat";
}

std::string NoteFileService::generate_data_file_path(const std::string& client_id) const {
    auto uuid = random_bytes(16);
    std::stringstream ss;
    ss << client_data_dir(client_id) << "/";
    for (size_t i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(uuid[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) ss << "-";
    }
    ss << ".dat";
    return ss.str();
}

std::shared_ptr<NoteFileHandle> NoteFileService::get_file(
    const std::string& client_id,
    const std::vector<NoteBytes::Value>& path_segments)
{
    if (!initialized_.load()) return nullptr;

    auto key = get_client_key(client_id);

    // Build path string for lookup
    std::string path_string;
    for (size_t i = 0; i < path_segments.size(); i++) {
        if (i > 0) path_string += "/";
        path_string += path_segments[i].as_string();
    }
    std::string full_path = client_id + "/" + path_string;

    // Check existing handle
    {
        std::lock_guard<std::mutex> lock(handles_mutex_);
        auto it = handles_.find(full_path);
        if (it != handles_.end()) {
            auto h = it->second.lock();
            if (h) return h;
            handles_.erase(it);
        }
    }

    // Ensure client dir exists
    try { fs::create_directories(client_data_dir(client_id)); }
    catch (...) { return nullptr; }

    // Resolve path
    std::lock_guard<std::mutex> lock(ledger_mutex_);
    NoteFilePath np(client_ledger_path(client_id), path_segments,
                    client_data_dir(client_id));
    auto file_path = NoteFileLedger::find_or_create_path(np, key);
    if (file_path.empty()) return nullptr;

    auto handle = std::make_shared<NoteFileHandle>(
        file_path, path_segments, full_path, client_id, key, shared_from_this());

    {
        std::lock_guard<std::mutex> hl(handles_mutex_);
        handles_[full_path] = handle;
    }
    return handle;
}

std::shared_ptr<NoteFileHandle> NoteFileService::get_file(
    const std::string& client_id,
    const std::vector<std::string>& path_segments)
{
    std::vector<NoteBytes::Value> segs;
    for (const auto& s : path_segments) segs.emplace_back(s);
    return get_file(client_id, segs);
}

bool NoteFileService::delete_file(
    const std::string& client_id,
    const std::vector<NoteBytes::Value>& path_segments,
    bool recursive)
{
    auto key = get_client_key(client_id);
    std::lock_guard<std::mutex> lock(ledger_mutex_);
    NoteFilePath np(client_ledger_path(client_id), path_segments,
                    client_data_dir(client_id), recursive);
    return NoteFileLedger::delete_from_path(np, key);
}

std::vector<std::string> NoteFileService::list_files(const std::string& client_id) {
    auto key = get_client_key(client_id);
    return NoteFileLedger::collect_file_paths(client_ledger_path(client_id), key);
}

std::string NoteFileService::resolve_or_create_path(
    const std::string& client_id,
    const std::vector<NoteBytes::Value>& path_segments)
{
    auto key = get_client_key(client_id);
    std::lock_guard<std::mutex> lock(ledger_mutex_);
    NoteFilePath np(client_ledger_path(client_id), path_segments,
                    client_data_dir(client_id));
    return NoteFileLedger::find_or_create_path(np, key);
}

std::vector<uint8_t> NoteFileService::read_file_to_buffer(
    const std::string& file_path, const std::vector<uint8_t>& key)
{
    struct stat st;
    if (stat(file_path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return {};
    return NoteFileLedger::aes_decrypt_to_buffer(file_path, key);
}

bool NoteFileService::encrypt_buffer_to_file(
    const std::string& file_path,
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& key)
{
    std::string tmp = file_path + ".encrypted";
    if (!NoteFileLedger::aes_encrypt_buffer_to_file(data, tmp, key)) {
        unlink(tmp.c_str());
        return false;
    }
    if (rename(tmp.c_str(), file_path.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

bool NoteFileService::create_pipe(int& read_fd, int& write_fd) {
    int pfd[2];
    if (::pipe(pfd) < 0) return false;
    read_fd = pfd[0];
    write_fd = pfd[1];
    return true;
}

// ── Handle registry ──────────────────────────────────────────────────────

void NoteFileService::register_handle(NoteFileHandle*) {}

void NoteFileService::unregister_handle(NoteFileHandle* handle) {
    if (!handle) return;
    std::lock_guard<std::mutex> lock(handles_mutex_);
    for (auto it = handles_.begin(); it != handles_.end(); ) {
        auto locked = it->second.lock();
        if (!locked || locked.get() == handle)
            it = handles_.erase(it);
        else
            ++it;
    }
}

size_t NoteFileService::active_handle_count() const {
    std::lock_guard<std::mutex> lock(handles_mutex_);
    size_t n = 0;
    for (const auto& [_, w] : handles_)
        if (!w.expired()) n++;
    return n;
}

// ── Global accessor ──────────────────────────────────────────────────────

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
