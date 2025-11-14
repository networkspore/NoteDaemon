// src/encryption.h
// Encryption module for secure communication
// Implements DH key exchange and AES-256-GCM encryption

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <syslog.h>

namespace Encryption {

/**
 * Diffie-Hellman Key Exchange
 * Generates 2048-bit DH parameters and derives shared secret
 */
class DHKeyExchange {
private:
    EVP_PKEY_CTX* pkey_ctx_ = nullptr;
    EVP_PKEY* pkey_ = nullptr;
    EVP_PKEY* peer_key_ = nullptr;
    unsigned char shared_secret_[32];
    bool initialized_ = false;
    
public:
    DHKeyExchange() {
        memset(shared_secret_, 0, sizeof(shared_secret_));
        
        // Generate DH parameters (2048-bit)
        pkey_ctx_ = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
        if (!pkey_ctx_) {
            syslog(LOG_ERR, "DHKeyExchange: Failed to create context");
            return;
        }
        
        if (EVP_PKEY_paramgen_init(pkey_ctx_) <= 0) {
            syslog(LOG_ERR, "DHKeyExchange: paramgen_init failed");
            return;
        }
        
        // Set key length to 2048 bits
        if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pkey_ctx_, 2048) <= 0) {
            syslog(LOG_ERR, "DHKeyExchange: set_dh_paramgen_prime_len failed");
            return;
        }
        
        EVP_PKEY* params = nullptr;
        if (EVP_PKEY_paramgen(pkey_ctx_, &params) <= 0) {
            syslog(LOG_ERR, "DHKeyExchange: paramgen failed");
            return;
        }
        
        // Generate key pair
        EVP_PKEY_CTX* keygen_ctx = EVP_PKEY_CTX_new(params, nullptr);
        if (!keygen_ctx) {
            EVP_PKEY_free(params);
            syslog(LOG_ERR, "DHKeyExchange: keygen context creation failed");
            return;
        }
        
        if (EVP_PKEY_keygen_init(keygen_ctx) <= 0) {
            EVP_PKEY_CTX_free(keygen_ctx);
            EVP_PKEY_free(params);
            syslog(LOG_ERR, "DHKeyExchange: keygen_init failed");
            return;
        }
        
        if (EVP_PKEY_keygen(keygen_ctx, &pkey_) <= 0) {
            EVP_PKEY_CTX_free(keygen_ctx);
            EVP_PKEY_free(params);
            syslog(LOG_ERR, "DHKeyExchange: keygen failed");
            return;
        }
        
        EVP_PKEY_CTX_free(keygen_ctx);
        EVP_PKEY_free(params);
        
        initialized_ = true;
        syslog(LOG_INFO, "DHKeyExchange: Initialized successfully");
    }
    
    ~DHKeyExchange() {
        if (pkey_ctx_) EVP_PKEY_CTX_free(pkey_ctx_);
        if (pkey_) EVP_PKEY_free(pkey_);
        if (peer_key_) EVP_PKEY_free(peer_key_);
        
        // Secure erase shared secret
        OPENSSL_cleanse(shared_secret_, sizeof(shared_secret_));
    }
    
    bool is_initialized() const { 
        return initialized_; 
    }
    
    /**
     * Get our public key to send to peer
     * Returns DER-encoded public key
     */
    bool get_public_key(unsigned char* buffer, size_t* len) {
        if (!pkey_ || !buffer || !len || *len == 0) {
            syslog(LOG_ERR, "get_public_key: invalid state or buffer");
            return false;
        }

        unsigned char* pub_key = nullptr;
        int pub_len = i2d_PUBKEY(pkey_, &pub_key);

        if (pub_len <= 0 || pub_len > (int)*len) {
            syslog(LOG_ERR, "get_public_key: public key size invalid (%d bytes)", pub_len);
            if (pub_key) OPENSSL_free(pub_key);
            return false;
        }

        memcpy(buffer, pub_key, pub_len);
        *len = pub_len;
        OPENSSL_free(pub_key);

        syslog(LOG_INFO, "get_public_key: Exported %zu bytes", *len);
        return true;
    }
    
    /**
     * Get our public key as vector
     */
    std::vector<uint8_t> get_public_key_vec() {
        unsigned char buffer[512];
        size_t len = sizeof(buffer);
        
        if (get_public_key(buffer, &len)) {
            return std::vector<uint8_t>(buffer, buffer + len);
        }
        return std::vector<uint8_t>();
    }
    
    /**
     * Receive peer's public key (DER-encoded)
     */
    bool set_peer_public_key(const unsigned char* buffer, size_t len) {
        if (!buffer || len == 0) {
            syslog(LOG_ERR, "set_peer_public_key: invalid buffer or length");
            return false;
        }

        const unsigned char* p = buffer;

        if (peer_key_) {
            EVP_PKEY_free(peer_key_);
            peer_key_ = nullptr;
        }

        peer_key_ = d2i_PUBKEY(nullptr, &p, len);
        if (!peer_key_) {
            syslog(LOG_ERR, "set_peer_public_key: Failed to parse peer public key");
            return false;
        }

        syslog(LOG_INFO, "set_peer_public_key: Imported %zu bytes", len);
        return true;
    }
    
    /**
     * Set peer's public key from vector
     */
    bool set_peer_public_key(const std::vector<uint8_t>& key) {
        return set_peer_public_key(key.data(), key.size());
    }
    
    /**
     * Derive shared secret after exchanging public keys
     * Hashes the result with SHA-256 to get 256-bit key
     */
    bool derive_shared_secret() {
        if (!pkey_ || !peer_key_) {
            syslog(LOG_ERR, "derive_shared_secret: keys not ready");
            return false;
        }
        
        EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
        if (!derive_ctx) {
            syslog(LOG_ERR, "derive_shared_secret: context creation failed");
            return false;
        }
        
        if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
            EVP_PKEY_CTX_free(derive_ctx);
            syslog(LOG_ERR, "derive_shared_secret: derive_init failed");
            return false;
        }
        
        if (EVP_PKEY_derive_set_peer(derive_ctx, peer_key_) <= 0) {
            EVP_PKEY_CTX_free(derive_ctx);
            syslog(LOG_ERR, "derive_shared_secret: set_peer failed");
            return false;
        }
        
        // First, get the size
        size_t secret_len = 0;
        if (EVP_PKEY_derive(derive_ctx, nullptr, &secret_len) <= 0) {
            EVP_PKEY_CTX_free(derive_ctx);
            syslog(LOG_ERR, "derive_shared_secret: size query failed");
            return false;
        }
        
        // Allocate and derive
        std::vector<uint8_t> raw_secret(secret_len);
        if (EVP_PKEY_derive(derive_ctx, raw_secret.data(), &secret_len) <= 0) {
            EVP_PKEY_CTX_free(derive_ctx);
            syslog(LOG_ERR, "derive_shared_secret: derivation failed");
            return false;
        }
        
        EVP_PKEY_CTX_free(derive_ctx);
        
        // Hash the shared secret to get 256-bit key (SHA-256)
        unsigned char hash[32];
        unsigned int hash_len = 0;
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        
        if (!md_ctx) {
            syslog(LOG_ERR, "derive_shared_secret: MD context creation failed");
            return false;
        }
        
        if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(md_ctx, raw_secret.data(), secret_len) != 1 ||
            EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            syslog(LOG_ERR, "derive_shared_secret: hashing failed");
            return false;
        }
        
        EVP_MD_CTX_free(md_ctx);
        
        memcpy(shared_secret_, hash, 32);
        
        syslog(LOG_INFO, "derive_shared_secret: Derived 256-bit key");
        return true;
    }
    
    /**
     * Get the derived shared secret (256-bit key)
     */
    const unsigned char* get_shared_secret() const {
        return shared_secret_;
    }
};

/**
 * Encrypted session using AES-256-GCM
 * Provides authenticated encryption for key events
 */
class EncryptedSession {
private:
    EVP_CIPHER_CTX* cipher_ctx_ = nullptr;
    unsigned char shared_secret_[32];
    unsigned char iv_[16];
    bool active_ = false;
    
public:
    EncryptedSession() {
        memset(shared_secret_, 0, sizeof(shared_secret_));
        memset(iv_, 0, sizeof(iv_));
    }
    
    ~EncryptedSession() {
        if (cipher_ctx_) {
            EVP_CIPHER_CTX_free(cipher_ctx_);
        }
        
        // Secure erase sensitive data
        OPENSSL_cleanse(shared_secret_, sizeof(shared_secret_));
        OPENSSL_cleanse(iv_, sizeof(iv_));
    }
    
    /**
     * Initialize encryption with shared secret from DH exchange
     */
    bool init(const unsigned char* secret) {
        if (!secret) {
            syslog(LOG_ERR, "EncryptedSession::init: null secret");
            return false;
        }
        
        memcpy(shared_secret_, secret, 32);
        
        // Generate random IV (initialization vector)
        if (RAND_bytes(iv_, sizeof(iv_)) != 1) {
            syslog(LOG_ERR, "EncryptedSession::init: IV generation failed");
            return false;
        }
        
        // Create cipher context for AES-256-GCM
        cipher_ctx_ = EVP_CIPHER_CTX_new();
        if (!cipher_ctx_) {
            syslog(LOG_ERR, "EncryptedSession::init: context creation failed");
            return false;
        }
        
        active_ = true;
        syslog(LOG_INFO, "EncryptedSession: Initialized with AES-256-GCM");
        return true;
    }
    
    bool is_active() const { 
        return active_; 
    }
    
    /**
     * Encrypt a packet using AES-256-GCM
     * Output format: [ciphertext][16-byte auth tag]
     */
    bool encrypt_packet(const unsigned char* plaintext, size_t plain_len,
                       unsigned char* ciphertext, size_t* cipher_len) {
        if (!active_ || !plaintext || !ciphertext || !cipher_len) {
            syslog(LOG_ERR, "encrypt_packet: invalid state or parameters");
            return false;
        }
        
        // Reset cipher for new encryption
        if (EVP_EncryptInit_ex(cipher_ctx_, EVP_aes_256_gcm(), 
                              nullptr, shared_secret_, iv_) != 1) {
            syslog(LOG_ERR, "encrypt_packet: EncryptInit failed");
            return false;
        }
        
        int len;
        if (EVP_EncryptUpdate(cipher_ctx_, ciphertext, &len,
                             plaintext, plain_len) != 1) {
            syslog(LOG_ERR, "encrypt_packet: EncryptUpdate failed");
            return false;
        }
        
        int ciphertext_len = len;
        
        if (EVP_EncryptFinal_ex(cipher_ctx_, 
                               ciphertext + len, &len) != 1) {
            syslog(LOG_ERR, "encrypt_packet: EncryptFinal failed");
            return false;
        }
        
        ciphertext_len += len;
        
        // Get authentication tag (16 bytes for GCM)
        unsigned char tag[16];
        if (EVP_CIPHER_CTX_ctrl(cipher_ctx_, EVP_CTRL_GCM_GET_TAG,
                               16, tag) != 1) {
            syslog(LOG_ERR, "encrypt_packet: get tag failed");
            return false;
        }
        
        // Append tag to ciphertext
        memcpy(ciphertext + ciphertext_len, tag, 16);
        *cipher_len = ciphertext_len + 16;
        
        // Increment IV for next packet (simple counter mode)
        for (int i = 15; i >= 0; i--) {
            if (++iv_[i] != 0) break;
        }
        
        return true;
    }
    
    /**
     * Encrypt packet and return as vector
     */
    std::vector<uint8_t> encrypt_packet(const unsigned char* plaintext, size_t plain_len) {
        std::vector<uint8_t> result(plain_len + 32); // Extra space for padding + tag
        size_t cipher_len = result.size();
        
        if (encrypt_packet(plaintext, plain_len, result.data(), &cipher_len)) {
            result.resize(cipher_len);
            return result;
        }
        
        return std::vector<uint8_t>();
    }
    
    /**
     * Decrypt a packet using AES-256-GCM
     * Input format: [ciphertext][16-byte auth tag]
     */
    bool decrypt_packet(const unsigned char* ciphertext, size_t cipher_len,
                       unsigned char* plaintext, size_t* plain_len) {
        if (!active_ || !ciphertext || !plaintext || !plain_len) {
            return false;
        }
        
        if (cipher_len < 16) { // Need at least the tag
            syslog(LOG_ERR, "decrypt_packet: packet too short");
            return false;
        }
        
        // Tag is last 16 bytes
        size_t actual_cipher_len = cipher_len - 16;
        const unsigned char* tag = ciphertext + actual_cipher_len;
        
        // Initialize decryption
        if (EVP_DecryptInit_ex(cipher_ctx_, EVP_aes_256_gcm(),
                              nullptr, shared_secret_, iv_) != 1) {
            return false;
        }
        
        int len;
        if (EVP_DecryptUpdate(cipher_ctx_, plaintext, &len,
                             ciphertext, actual_cipher_len) != 1) {
            return false;
        }
        
        int plaintext_len = len;
        
        // Set expected tag
        if (EVP_CIPHER_CTX_ctrl(cipher_ctx_, EVP_CTRL_GCM_SET_TAG,
                               16, (void*)tag) != 1) {
            return false;
        }
        
        // Finalize and verify tag
        if (EVP_DecryptFinal_ex(cipher_ctx_, plaintext + len, &len) != 1) {
            syslog(LOG_WARNING, "decrypt_packet: authentication failed");
            return false;
        }
        
        plaintext_len += len;
        *plain_len = plaintext_len;
        
        // Increment IV
        for (int i = 15; i >= 0; i--) {
            if (++iv_[i] != 0) break;
        }
        
        return true;
    }
    
    /**
     * Get current IV to send to client
     */
    const unsigned char* get_iv() const {
        return iv_;
    }
    
    /**
     * Get IV as vector
     */
    std::vector<uint8_t> get_iv_vec() const {
        return std::vector<uint8_t>(iv_, iv_ + 16);
    }
};

} // namespace Encryption

#endif // ENCRYPTION_H