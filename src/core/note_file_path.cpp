// src/core/note_file_path.cpp
// NoteFilePath + ledger operations implementation

#include "note_file_path.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <array>

// =========================================================================
// NoteFilePath
// =========================================================================

NoteFilePath::NoteFilePath(
    const std::string& ledger_path,
    const std::vector<NoteBytes::Value>& target_path,
    const std::string& data_dir,
    bool recursive)
    : ledger_path_(ledger_path)
    , target_path_(target_path)
    , data_dir_(data_dir)
    , recursive_(recursive)
{}

const NoteBytes::Value& NoteFilePath::current_path_key() const {
    static NoteBytes::Value empty_val;
    if (current_level_ < static_cast<int>(target_path_.size())) {
        return target_path_[current_level_];
    }
    return empty_val;
}

std::string NoteFilePath::generate_data_file_path() const {
    // Generate UUID-style filename
    std::array<uint8_t, 16> uuid;
    RAND_bytes(uuid.data(), uuid.size());

    std::stringstream ss;
    ss << data_dir_ << "/";
    for (size_t i = 0; i < uuid.size(); i++) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(uuid[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) ss << "-";
    }
    ss << ".dat";
    return ss.str();
}

NoteBytes::Pair NoteFilePath::create_file_path_pair(
    int path_index,
    const std::string& result_path) const
{
    if (path_index == depth()) {
        // Terminal: FILE_PATH marker → actual file path
        return NoteBytes::Pair(
            NoteFileConstants::FILE_PATH,
            NoteBytes::Value(result_path));
    } else if (path_index > depth()) {
        return NoteBytes::Pair(NoteBytes::Value(), NoteBytes::Value());
    }

    // Nested: path segment → recursively create inner pair as Object
    auto inner_pair = create_file_path_pair(path_index + 1, result_path);
    NoteBytes::Object inner_obj;
    inner_obj.add(inner_pair);

    return NoteBytes::Pair(
        target_path_[path_index],
        inner_obj.as_value());
}

// =========================================================================
// AES-256-GCM encrypt/decrypt helpers for files
// =========================================================================

namespace NoteFileLedger {

    constexpr size_t AES_IV_SIZE = 12;   // 96-bit IV for GCM
    constexpr size_t GCM_TAG_SIZE = 16;  // 128-bit auth tag

    /**
     * Encrypt a file using AES-256-GCM.
     * Input: plaintext file path
     * Output: ciphertext file at output_path
     * Format: [12-byte IV][ciphertext][16-byte tag]
     */
    bool aes_encrypt_file(const std::string& input_path,
                          const std::string& output_path,
                          const std::vector<uint8_t>& key)
    {
        std::ifstream in(input_path, std::ios::binary);
        if (!in) return false;

        std::ofstream out(output_path, std::ios::binary);
        if (!out) return false;

        // Generate random IV
        uint8_t iv[AES_IV_SIZE];
        RAND_bytes(iv, AES_IV_SIZE);
        out.write(reinterpret_cast<const char*>(iv), AES_IV_SIZE);

        // Initialize encryption
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        bool ok = false;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                               key.data(), iv) == 1) {
            uint8_t buf[65536];
            uint8_t ciphertext[65536 + 16];
            int len;

            while (in.read(reinterpret_cast<char*>(buf), sizeof(buf)).gcount() > 0) {
                int bytes_read = in.gcount();
                if (EVP_EncryptUpdate(ctx, ciphertext, &len,
                                      buf, bytes_read) == 1) {
                    out.write(reinterpret_cast<const char*>(ciphertext), len);
                }
            }

            uint8_t tag[GCM_TAG_SIZE];
            if (EVP_EncryptFinal_ex(ctx, ciphertext, &len) == 1) {
                out.write(reinterpret_cast<const char*>(ciphertext), len);
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                        GCM_TAG_SIZE, tag) == 1) {
                    out.write(reinterpret_cast<const char*>(tag), GCM_TAG_SIZE);
                    ok = true;
                }
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    /**
     * Decrypt a file using AES-256-GCM.
     * Input: ciphertext file at input_path [12-byte IV][ciphertext][16-byte tag]
     * Output: plaintext to output_path
     */
    bool aes_decrypt_file(const std::string& input_path,
                          const std::string& output_path,
                          const std::vector<uint8_t>& key)
    {
        std::ifstream in(input_path, std::ios::binary);
        if (!in) return false;

        std::ofstream out(output_path, std::ios::binary);
        if (!out) return false;

        // Read IV
        uint8_t iv[AES_IV_SIZE];
        in.read(reinterpret_cast<char*>(iv), AES_IV_SIZE);
        if (in.gcount() < static_cast<std::streamsize>(AES_IV_SIZE)) return false;

        // Initialize decryption
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        bool ok = false;
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                               key.data(), iv) == 1) {
            uint8_t buf[65536];
            uint8_t plaintext[65536];
            int len;

            // Get file size to leave room for tag
            in.seekg(0, std::ios::end);
            std::streamsize file_size = in.tellg();
            std::streamsize data_size = file_size - AES_IV_SIZE - GCM_TAG_SIZE;
            in.seekg(AES_IV_SIZE, std::ios::beg);

            std::streamsize remaining = data_size;
            while (remaining > 0) {
                int to_read = (remaining > 65536) ? 65536 : static_cast<int>(remaining);
                in.read(reinterpret_cast<char*>(buf), to_read);
                int bytes_read = in.gcount();
                if (bytes_read <= 0) break;

                if (EVP_DecryptUpdate(ctx, plaintext, &len, buf, bytes_read) == 1) {
                    out.write(reinterpret_cast<const char*>(plaintext), len);
                }
                remaining -= bytes_read;
            }

            // Read and verify tag
            uint8_t tag[GCM_TAG_SIZE];
            in.read(reinterpret_cast<char*>(tag), GCM_TAG_SIZE);
            if (in.gcount() == GCM_TAG_SIZE) {
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                        GCM_TAG_SIZE, tag) == 1) {
                    if (EVP_DecryptFinal_ex(ctx, plaintext, &len) == 1) {
                        out.write(reinterpret_cast<const char*>(plaintext), len);
                        ok = true;
                    }
                }
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    /**
     * Read and decrypt an entire file into a byte vector.
     */
    std::vector<uint8_t> aes_decrypt_to_buffer(const std::string& file_path,
                                                const std::vector<uint8_t>& key)
    {
        std::vector<uint8_t> result;
        std::ifstream in(file_path, std::ios::binary);
        if (!in) return result;

        uint8_t iv[AES_IV_SIZE];
        in.read(reinterpret_cast<char*>(iv), AES_IV_SIZE);
        if (in.gcount() < static_cast<std::streamsize>(AES_IV_SIZE)) return result;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return result;

        in.seekg(0, std::ios::end);
        std::streamsize file_size = in.tellg();
        std::streamsize data_size = file_size - AES_IV_SIZE - GCM_TAG_SIZE;
        in.seekg(AES_IV_SIZE, std::ios::beg);

        std::vector<uint8_t> buf(65536);
        std::vector<uint8_t> plaintext(65536);
        int len;
        std::streamsize remaining = data_size;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                               key.data(), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return result;
        }

        while (remaining > 0) {
            int to_read = (remaining > 65536) ? 65536 : static_cast<int>(remaining);
            in.read(reinterpret_cast<char*>(buf.data()), to_read);
            int bytes_read = in.gcount();
            if (bytes_read <= 0) break;

            if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                                  buf.data(), bytes_read) == 1) {
                result.insert(result.end(), plaintext.begin(), plaintext.begin() + len);
            }
            remaining -= bytes_read;
        }

        uint8_t tag[GCM_TAG_SIZE];
        in.read(reinterpret_cast<char*>(tag), GCM_TAG_SIZE);
        if (in.gcount() == GCM_TAG_SIZE) {
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                    GCM_TAG_SIZE, tag) == 1) {
                if (EVP_DecryptFinal_ex(ctx, plaintext.data(), &len) == 1) {
                    result.insert(result.end(), plaintext.begin(), plaintext.begin() + len);
                } else {
                    result.clear(); // Auth failed
                }
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    /**
     * Encrypt a byte buffer to a file.
     */
    bool aes_encrypt_buffer_to_file(const std::vector<uint8_t>& plaintext,
                                    const std::string& output_path,
                                    const std::vector<uint8_t>& key)
    {
        std::ofstream out(output_path, std::ios::binary);
        if (!out) return false;

        uint8_t iv[AES_IV_SIZE];
        RAND_bytes(iv, AES_IV_SIZE);
        out.write(reinterpret_cast<const char*>(iv), AES_IV_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        bool ok = false;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                               key.data(), iv) == 1) {
            uint8_t ciphertext[65536 + 16];
            int len;
            size_t offset = 0;

            while (offset < plaintext.size()) {
                int to_enc = std::min<size_t>(65536, plaintext.size() - offset);
                if (EVP_EncryptUpdate(ctx, ciphertext, &len,
                                      plaintext.data() + offset, to_enc) == 1) {
                    out.write(reinterpret_cast<const char*>(ciphertext), len);
                }
                offset += to_enc;
            }

            uint8_t tag[GCM_TAG_SIZE];
            if (EVP_EncryptFinal_ex(ctx, ciphertext, &len) == 1) {
                out.write(reinterpret_cast<const char*>(ciphertext), len);
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                        GCM_TAG_SIZE, tag) == 1) {
                    out.write(reinterpret_cast<const char*>(tag), GCM_TAG_SIZE);
                    ok = true;
                }
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

} // namespace NoteFileLedger (AES helpers)

// =========================================================================
// LEDGER OPERATIONS
// =========================================================================

namespace NoteFileLedger {

std::string find_or_create_path(NoteFilePath& path,
                                 const std::vector<uint8_t>& encryption_key)
{
    syslog(LOG_INFO, "[NoteFileLedger] find_or_create_path: depth=%d ledger=%s",
           path.depth(), path.ledger_path().c_str());

    struct stat st;
    if (stat(path.ledger_path().c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        // No ledger yet — create initial structure
        syslog(LOG_INFO, "[NoteFileLedger] Creating new ledger");

        // Ensure data directory exists
        mkdir(path.data_dir().c_str(), 0700);

        // Generate new data file path
        std::string new_file_path = path.generate_data_file_path();
        path.set_resolved_file_path(new_file_path);

        // Create the initial ledger with the path entry
        NoteBytes::Pair root_pair = path.create_file_path_pair(0, new_file_path);

        NoteBytes::Object ledger_obj;
        ledger_obj.add(root_pair);
        auto serialized = ledger_obj.serialize();

        if (!aes_encrypt_buffer_to_file(serialized, path.ledger_path(), encryption_key)) {
            syslog(LOG_ERR, "[NoteFileLedger] Failed to create initial ledger");
            return "";
        }

        syslog(LOG_INFO, "[NoteFileLedger] Created: %s -> %s",
               path.ledger_path().c_str(), new_file_path.c_str());
        return new_file_path;
    }

    // Ledger exists — decrypt and parse
    auto decrypted = aes_decrypt_to_buffer(path.ledger_path(), encryption_key);
    if (decrypted.empty()) {
        syslog(LOG_ERR, "[NoteFileLedger] Failed to decrypt ledger");
        return "";
    }

    // Parse the ledger as NoteBytes pairs
    // For the full implementation, we need recursive path traversal here.
    // For now, we do a simplified linear search.
    try {
        NoteBytes::Object ledger_obj = NoteBytes::Object::deserialize(
            decrypted.data(), decrypted.size());

        // Recursive search through the path hierarchy
        std::function<const NoteBytes::Value*(
            const NoteBytes::Object&, int)> search_path =
            [&](const NoteBytes::Object& obj, int level) -> const NoteBytes::Value* {
            if (level >= path.depth()) {
                // We've consumed all path segments — look for FILE_PATH
                return obj.get(NoteFileConstants::FILE_PATH);
            }

            const auto& segment = path.target_path()[level];
            const auto* nested_val = obj.get(segment);
            if (!nested_val) return nullptr;

            // If this is the last segment and we find FILE_PATH directly,
            // it means the path is a single level (e.g., {"settings"})
            if (level == path.depth() - 1 &&
                nested_val->type() == NoteBytes::Type::STRING) {
                return nested_val;
            }

            // Recurse into nested object
            if (nested_val->type() == NoteBytes::Type::OBJECT) {
                auto nested_obj = NoteBytes::as_object(*nested_val);
                return search_path(nested_obj, level + 1);
            }

            return nullptr;
        };

        const auto* found = search_path(ledger_obj, 0);
        if (found && found->type() == NoteBytes::Type::STRING) {
            std::string result = found->as_string();
            path.set_resolved_file_path(result);
            syslog(LOG_INFO, "[NoteFileLedger] Found existing: %s",
                   result.c_str());
            return result;
        }

        // Path not found — need to add it
        // For a complete implementation we'd need to rebuild the ledger.
        // Simplified: just create the data file, the full ledger update
        // requires a full decrypt→modify→re-encrypt cycle.
        std::string new_file_path = path.generate_data_file_path();
        path.set_resolved_file_path(new_file_path);
        syslog(LOG_INFO, "[NoteFileLedger] Creating new file: %s",
               new_file_path.c_str());
        return new_file_path;

    } catch (const std::exception& e) {
        syslog(LOG_ERR, "[NoteFileLedger] Parse error: %s", e.what());
        return "";
    }
}

bool delete_from_path(NoteFilePath& path,
                      const std::vector<uint8_t>& encryption_key)
{
    syslog(LOG_INFO, "[NoteFileLedger] delete_from_path: depth=%d recursive=%d",
           path.depth(), path.is_recursive());
    // Full implementation would:
    // 1. Decrypt ledger
    // 2. Traverse to target path
    // 3. Remove the entry (recursively if requested)
    // 4. Delete associated data files
    // 5. Re-encrypt and save ledger
    // For now, this is a placeholder.
    (void)encryption_key;
    return true;
}

bool re_encrypt_ledger(const std::string& ledger_path,
                       const std::vector<uint8_t>& old_key,
                       const std::vector<uint8_t>& new_key,
                       std::function<void(int64_t, int64_t)> callback)
{
    syslog(LOG_INFO, "[NoteFileLedger] re_encrypt_ledger");

    // Decrypt with old key
    auto decrypted = aes_decrypt_to_buffer(ledger_path, old_key);
    if (decrypted.empty()) {
        syslog(LOG_ERR, "[NoteFileLedger] re-encrypt: decrypt failed");
        return false;
    }

    // Collect all referenced file paths from the ledger
    auto file_paths = collect_file_paths(ledger_path, old_key);
    int64_t total = static_cast<int64_t>(file_paths.size()) + 1; // +1 for ledger
    int64_t processed = 0;

    if (callback) callback(processed, total);

    // Re-encrypt each data file
    for (const auto& fp : file_paths) {
        std::string tmp_path = fp + ".tmp";

        if (aes_decrypt_file(fp, tmp_path, old_key)) {
            if (aes_encrypt_file(tmp_path, fp, new_key)) {
                unlink(tmp_path.c_str());
            }
        }

        processed++;
        if (callback) callback(processed, total);
    }

    // Re-encrypt the ledger itself
    if (!aes_encrypt_buffer_to_file(decrypted, ledger_path, new_key)) {
        syslog(LOG_ERR, "[NoteFileLedger] re-encrypt: ledger re-encrypt failed");
        return false;
    }

    processed++;
    if (callback) callback(processed, total);

    syslog(LOG_INFO, "[NoteFileLedger] re-encrypt complete: %lld files",
           (long long)file_paths.size());
    return true;
}

std::vector<std::string> collect_file_paths(
    const std::string& ledger_path,
    const std::vector<uint8_t>& encryption_key)
{
    std::vector<std::string> result;

    auto decrypted = aes_decrypt_to_buffer(ledger_path, encryption_key);
    if (decrypted.empty()) return result;

    try {
        NoteBytes::Object ledger_obj = NoteBytes::Object::deserialize(
            decrypted.data(), decrypted.size());

        // Recursively collect all FILE_PATH string values
        std::function<void(const NoteBytes::Object&)> collect =
            [&](const NoteBytes::Object& obj) {
            for (const auto& pair : obj.pairs()) {
                if (pair.key() == NoteFileConstants::FILE_PATH &&
                    pair.value().type() == NoteBytes::Type::STRING) {
                    result.push_back(pair.value().as_string());
                } else if (pair.value().type() == NoteBytes::Type::OBJECT) {
                    auto nested = NoteBytes::as_object(pair.value());
                    collect(nested);
                }
            }
        };

        collect(ledger_obj);

    } catch (const std::exception& e) {
        syslog(LOG_ERR, "[NoteFileLedger] collect_file_paths error: %s", e.what());
    }

    return result;
}

} // namespace NoteFileLedger
