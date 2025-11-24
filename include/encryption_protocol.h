// include/encryption_protocol.h
// Protocol integration for encryption handshake
// NOTE: This class ONLY handles encryption/decryption, NOT socket I/O

#ifndef ENCRYPTION_PROTOCOL_H
#define ENCRYPTION_PROTOCOL_H

#include "atomic_sequence.h"
#include "encryption.h"
#include "note_messaging.h"
#include "notebytes.h"
#include "event_bytes.h"
#include <memory>
#include <syslog.h>
#include <vector>

namespace EncryptionProtocol {

/**
 * Encryption state for a session
 */
enum class State {
    DISABLED,           // Encryption not supported/requested
    NEGOTIATING,        // Exchanging keys
    ACTIVE,            // Encryption active
    FAILED             // Key exchange failed
};

/**
 * Encryption handshake manager
 * Handles DH key exchange and encrypt/decrypt operations
 * Does NOT handle socket I/O - caller is responsible for sending/receiving
 */
class EncryptionHandshake {
private:
    std::unique_ptr<Encryption::DHKeyExchange> dh_;
    std::unique_ptr<Encryption::EncryptedSession> session_;
    State state_ = State::DISABLED;
    std::string device_id_;  // For logging only
    
public:
    EncryptionHandshake() = default;
    
    explicit EncryptionHandshake(const std::string& device_id) 
        : device_id_(device_id) {}
    
    /**
     * Check if encryption is available (OpenSSL compiled in)
     */
    static bool is_available() {
        #ifdef HAVE_OPENSSL
            return true;
        #else
            return false;
        #endif
    }
    
    /**
     * Start encryption negotiation
     * Generates our DH key pair
     * Returns true if ready to exchange keys
     */
    bool start_negotiation() {
        if (!is_available()) {
            syslog(LOG_WARNING, "Encryption requested but OpenSSL not available");
            state_ = State::FAILED;
            return false;
        }
        
        syslog(LOG_INFO, "Starting encryption negotiation for device: %s", 
               device_id_.c_str());
        
        dh_ = std::make_unique<Encryption::DHKeyExchange>();
        if (!dh_->is_initialized()) {
            syslog(LOG_ERR, "Failed to initialize DH key exchange");
            state_ = State::FAILED;
            return false;
        }
        
        state_ = State::NEGOTIATING;
        return true;
    }
    
    /**
     * Get our public key to send to peer
     * Returns empty vector if negotiation not started
     */
    std::vector<uint8_t> get_public_key() const {
        if (!dh_) {
            return std::vector<uint8_t>();
        }
        return dh_->get_public_key_vec();
    }
    
    /**
     * Set peer's public key and finalize encryption
     * After this, encrypt/decrypt will be available
     */
    bool finalize(const std::vector<uint8_t>& peer_public_key) {
        if (state_ != State::NEGOTIATING || !dh_) {
            syslog(LOG_ERR, "finalize: Invalid state for device %s", device_id_.c_str());
            return false;
        }
        
        // Set peer's public key
        if (!dh_->set_peer_public_key(peer_public_key)) {
            syslog(LOG_ERR, "finalize: Failed to set peer public key for device %s", 
                   device_id_.c_str());
            state_ = State::FAILED;
            return false;
        }
        
        // Derive shared secret
        if (!dh_->derive_shared_secret()) {
            syslog(LOG_ERR, "finalize: Failed to derive shared secret for device %s", 
                   device_id_.c_str());
            state_ = State::FAILED;
            return false;
        }
        
        // Initialize encrypted session
        session_ = std::make_unique<Encryption::EncryptedSession>();
        if (!session_->init(dh_->get_shared_secret())) {
            syslog(LOG_ERR, "finalize: Failed to initialize session for device %s", 
                   device_id_.c_str());
            state_ = State::FAILED;
            return false;
        }
        
        state_ = State::ACTIVE;
        syslog(LOG_INFO, "Encryption active for device: %s", device_id_.c_str());
        return true;
    }
    
    /**
     * Encrypt a packet
     * Input: plaintext bytes
     * Output: ciphertext bytes
     * Returns empty vector on failure
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
        if (state_ != State::ACTIVE || !session_) {
            syslog(LOG_WARNING, "encrypt called but encryption not active for device %s", 
                   device_id_.c_str());
            return std::vector<uint8_t>(); // Return empty on error
        }
        
        return session_->encrypt_packet(plaintext.data(), plaintext.size());
    }
    
    /**
     * Encrypt a packet (pointer + size variant)
     */
    std::vector<uint8_t> encrypt(const uint8_t* data, size_t len) {
        if (state_ != State::ACTIVE || !session_) {
            syslog(LOG_WARNING, "encrypt called but encryption not active for device %s", 
                   device_id_.c_str());
            return std::vector<uint8_t>();
        }
        
        return session_->encrypt_packet(data, len);
    }
    
    /**
     * Decrypt a packet
     * Input: ciphertext bytes
     * Output: plaintext written to output buffer
     * Returns true on success
     */
    bool decrypt(const std::vector<uint8_t>& ciphertext,
                 std::vector<uint8_t>& plaintext) {
        if (state_ != State::ACTIVE || !session_) {
            syslog(LOG_WARNING, "decrypt called but encryption not active for device %s", 
                   device_id_.c_str());
            return false;
        }
        
        plaintext.resize(ciphertext.size() + 32); // Extra space for potential padding
        size_t plain_len = plaintext.size();
        
        bool success = session_->decrypt_packet(
            ciphertext.data(), ciphertext.size(),
            plaintext.data(), &plain_len
        );
        
        if (success) {
            plaintext.resize(plain_len);
        } else {
            syslog(LOG_ERR, "Decryption failed for device %s", device_id_.c_str());
        }
        
        return success;
    }
    
    /**
     * Decrypt a packet (pointer + size variant)
     */
    bool decrypt(const uint8_t* ciphertext, size_t cipher_len,
                 std::vector<uint8_t>& plaintext) {
        if (state_ != State::ACTIVE || !session_) {
            syslog(LOG_WARNING, "decrypt called but encryption not active for device %s", 
                   device_id_.c_str());
            return false;
        }
        
        plaintext.resize(cipher_len + 32);
        size_t plain_len = plaintext.size();
        
        bool success = session_->decrypt_packet(
            ciphertext, cipher_len,
            plaintext.data(), &plain_len
        );
        
        if (success) {
            plaintext.resize(plain_len);
        }
        
        return success;
    }
    
    /**
     * Get current IV for synchronization
     * Used in ENCRYPTION_READY message
     */
    std::vector<uint8_t> get_iv() const {
        if (session_) {
            return session_->get_iv_vec();
        }
        return std::vector<uint8_t>();
    }
    
    /**
     * Clear all encryption state and keys
     * Called when device is released or error occurs
     */
    void clear() {
        if (dh_) {
            dh_.reset();
        }
        if (session_) {
            session_.reset();
        }
        state_ = State::DISABLED;
        syslog(LOG_INFO, "Encryption cleared for device: %s", device_id_.c_str());
    }
    
    // State queries
    State get_state() const { return state_; }
    bool is_active() const { return state_ == State::ACTIVE; }
    bool is_negotiating() const { return state_ == State::NEGOTIATING; }
    bool has_failed() const { return state_ == State::FAILED; }
    
    std::string get_device_id() const { return device_id_; }
    void set_device_id(const std::string& device_id) { device_id_ = device_id; }
};

/**
 * Protocol message builders for encryption handshake
 * These build NoteBytes::Object messages - caller sends them via socket
 */
class Messages {
public:
    /**
     * Build ENCRYPTION_OFFER message
     * Sent by server to offer encryption to client
     * 
     * Format:
     * {
     *   "type": TYPE_ENCRYPTION_OFFER,
     *   "sequence": <8-byte sequence>,
     *   "cipher": "aes-256-gcm",
     *   "public_key": <server DH public key>
     * }
     */
    static NoteBytes::Object build_encryption_offer(
        const std::vector<uint8_t>& server_public_key,
        const std::string& cipher = "aes-256-gcm"
    ) {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ENCRYPTION_OFFER);
        msg.add(NoteMessaging::Keys::SEQUENCE,AtomicSequence64::get_next());
        msg.add(NoteMessaging::Keys::CIPHER, cipher);
        msg.add(NoteMessaging::Keys::PUBLIC_KEY, 
               NoteBytes::Value(server_public_key.data(), 
                              server_public_key.size(), 
                              NoteBytes::Type::RAW_BYTES));
        
        return msg;
    }
    
    /**
     * Parse ENCRYPTION_ACCEPT message from client
     * 
     * Expected format:
     * {
     *   "type": TYPE_ENCRYPTION_ACCEPT,
     *   "sequence": <sequence>,
     *   "public_key": <client DH public key>
     * }
     */
    static bool parse_encryption_accept(const NoteBytes::Object& msg,
                                       std::vector<uint8_t>& client_public_key) {
        // Use constant from Keys
        auto key_value = msg.get(NoteMessaging::Keys::PUBLIC_KEY);
        if (!key_value || key_value->type() != NoteBytes::Type::RAW_BYTES) {
            syslog(LOG_ERR, "parse_encryption_accept: missing or invalid public_key");
            return false;
        }
        
        client_public_key = key_value->data();
        
        if (client_public_key.empty()) {
            syslog(LOG_ERR, "parse_encryption_accept: empty public key");
            return false;
        }
        
        return true;
    }
    
    /**
     * Build ENCRYPTION_READY message
     * Confirms encryption is now active and provides IV
     * 
     * Format:
     * {
     *   "type": TYPE_ENCRYPTION_READY,
     *   "sequence": <sequence>,
     *   "iv": <initialization vector>,
     *   "status": "active"
     * }
     */
    static NoteBytes::Object build_encryption_ready(
        const std::vector<uint8_t>& iv
    ) {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ENCRYPTION_READY);
        msg.add(NoteMessaging::Keys::SEQUENCE, AtomicSequence64::get_next());
        
        msg.add(NoteMessaging::Keys::IV, 
               NoteBytes::Value(iv.data(), iv.size(), NoteBytes::Type::RAW_BYTES));
        msg.add(NoteMessaging::Keys::STATUS, NoteMessaging::Status::ACTIVE);
        
        return msg;
    }
    
    /**
     * Build ENCRYPTION_DECLINE message
     * Client declines encryption offer
     * 
     * Format:
     * {
     *   "type": TYPE_ENCRYPTION_DECLINE,
     *   "sequence": <sequence>,
     *   "reason": <string>
     * }
     */
    static NoteBytes::Object build_encryption_decline(const std::string& reason) {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ENCRYPTION_DECLINE);
        msg.add(NoteMessaging::Keys::SEQUENCE, AtomicSequence64::get_next());
        msg.add(NoteMessaging::Keys::MSG, reason);
        
        return msg;
    }
    
    /**
     * Build ENCRYPTION_ERROR message
     * Sent when encryption setup fails
     * 
     * Format:
     * {
     *   "type": TYPE_ERROR,
     *   "sequence": <sequence>,
     *   "error_code": ERROR_ENCRYPTION_FAILED,
     *   "message": <error description>
     * }
     */
    static NoteBytes::Object build_encryption_error(const std::string& reason) {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ERROR);
        msg.add(NoteMessaging::Keys::SEQUENCE, AtomicSequence64::get_next());
        msg.add(NoteMessaging::Keys::ERROR_CODE,NoteMessaging::ErrorCodes::ENCRYPTION_FAILED);
        msg.add(NoteMessaging::Keys::MSG, reason);
        
        return msg;
    }
};

} // namespace EncryptionProtocol

#endif // ENCRYPTION_PROTOCOL_H