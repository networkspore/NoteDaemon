// include/encryption_protocol.h
// Protocol integration for encryption handshake and message wrapping

#ifndef ENCRYPTION_PROTOCOL_H
#define ENCRYPTION_PROTOCOL_H

#include "encryption.h"
#include "note_messaging.h"
#include "notebytes.h"
#include "event_bytes.h"
#include "input_packet.h"
#include <memory>
#include <syslog.h>
#include <unistd.h>

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
 * Handles DH key exchange via protocol messages
 */
class EncryptionHandshake {
private:
    std::unique_ptr<Encryption::DHKeyExchange> dh_;
    std::unique_ptr<Encryption::EncryptedSession> session_;
    State state_ = State::DISABLED;
    int client_fd_;
    
public:
    EncryptionHandshake(int client_fd) 
        : client_fd_(client_fd) {}
    
    /**
     * Check if encryption is available
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
     * Returns public key to send to client
     */
    bool start_negotiation() {
        if (!is_available()) {
            syslog(LOG_WARNING, "Encryption requested but OpenSSL not available");
            state_ = State::FAILED;
            return false;
        }
        
        syslog(LOG_INFO, "Starting encryption negotiation");
        
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
     * Get our public key to send to client
     */
    std::vector<uint8_t> get_public_key() {
        if (!dh_) {
            return std::vector<uint8_t>();
        }
        return dh_->get_public_key_vec();
    }
    
    /**
     * Receive client's public key and finalize encryption
     */
    bool finalize(const std::vector<uint8_t>& client_public_key) {
        if (state_ != State::NEGOTIATING || !dh_) {
            syslog(LOG_ERR, "finalize: Invalid state");
            return false;
        }
        
        // Set peer's public key
        if (!dh_->set_peer_public_key(client_public_key)) {
            syslog(LOG_ERR, "finalize: Failed to set peer public key");
            state_ = State::FAILED;
            return false;
        }
        
        // Derive shared secret
        if (!dh_->derive_shared_secret()) {
            syslog(LOG_ERR, "finalize: Failed to derive shared secret");
            state_ = State::FAILED;
            return false;
        }
        
        // Initialize encrypted session
        session_ = std::make_unique<Encryption::EncryptedSession>();
        if (!session_->init(dh_->get_shared_secret())) {
            syslog(LOG_ERR, "finalize: Failed to initialize session");
            state_ = State::FAILED;
            return false;
        }
        
        state_ = State::ACTIVE;
        syslog(LOG_INFO, "Encryption active");
        return true;
    }
    
    /**
     * Encrypt a message
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
        if (state_ != State::ACTIVE || !session_) {
            return plaintext; // Pass through if not active
        }
        
        return session_->encrypt_packet(plaintext.data(), plaintext.size());
    }
    
    /**
     * Decrypt a message
     */
    bool decrypt(const std::vector<uint8_t>& ciphertext,
                 std::vector<uint8_t>& plaintext) {
        if (state_ != State::ACTIVE || !session_) {
            plaintext = ciphertext; // Pass through if not active
            return true;
        }
        
        plaintext.resize(ciphertext.size());
        size_t plain_len = plaintext.size();
        
        bool success = session_->decrypt_packet(
            ciphertext.data(), ciphertext.size(),
            plaintext.data(), &plain_len
        );
        
        if (success) {
            plaintext.resize(plain_len);
        }
        
        return success;
    }
    
    State get_state() const { return state_; }
    bool is_active() const { return state_ == State::ACTIVE; }
    
    /**
     * Get current IV for synchronization
     */
    std::vector<uint8_t> get_iv() const {
        if (session_) {
            return session_->get_iv_vec();
        }
        return std::vector<uint8_t>();
    }
};

/**
 * Protocol message builders for encryption handshake
 */
class Messages {
public:
    /**
     * Build ENCRYPTION_OFFER message
     * Sent by server to offer encryption to client
     */
    static NoteBytes::Object build_encryption_offer(
        const std::vector<uint8_t>& server_public_key,
        const std::string& cipher = "aes-256-gcm"
    ) {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ENCRYPTION_OFFER);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        msg.add(NoteMessaging::Keys::SEQUENCE, 
               NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        
        msg.add(NoteMessaging::Keys::CIPHER, cipher);
        msg.add(NoteMessaging::Keys::PUBLIC_KEY, 
               NoteBytes::Value(server_public_key.data(), 
                              server_public_key.size(), 
                              NoteBytes::Type::RAW_BYTES));
        
        return msg;
    }
    
    /**
     * Parse ENCRYPTION_ACCEPT message from client
     */
    static bool parse_encryption_accept(const NoteBytes::Object& msg,
                                       std::vector<uint8_t>& client_public_key) {
        auto key_value = msg.get("client_public_key");
        if (key_value->type() != NoteBytes::Type::RAW_BYTES) {
            syslog(LOG_ERR, "parse_encryption_accept: missing or invalid client_public_key");
            return false;
        }
        
        client_public_key = key_value->data();
        return true;
    }
    
    /**
     * Build ENCRYPTION_READY message
     * Confirms encryption is now active
     */
    static NoteBytes::Object build_encryption_ready(
        const std::vector<uint8_t>& iv
    ) {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ENCRYPTION_READY);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        msg.add(NoteMessaging::Keys::SEQUENCE,
               NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        
        msg.add("iv", NoteBytes::Value(iv.data(), iv.size(), 
                                      NoteBytes::Type::RAW_BYTES));
        msg.add(NoteMessaging::Keys::STATUS, "encryption_active");
        
        return msg;
    }
    
    /**
     * Build ENCRYPTION_ERROR message
     */
    static NoteBytes::Object build_encryption_error(const std::string& reason) {
        NoteBytes::Object msg;
        msg.add(NoteMessaging::Keys::TYPE, EventBytes::TYPE_ERROR);
        
        uint8_t seq[6];
        AtomicSequence::get_next(seq);
        msg.add(NoteMessaging::Keys::SEQUENCE,
               NoteBytes::Value(seq, 6, NoteBytes::Type::RAW_BYTES));
        
        msg.add(NoteMessaging::Keys::ERROR_CODE, 
               NoteMessaging::ErrorCodes::ENCRYPTION_FAILED);
        msg.add(NoteMessaging::Keys::MSG, reason);
        
        return msg;
    }
};

/**
 * Encrypted message wrapper
 * Handles encryption of routed messages at the NoteBytes level
 */
class EncryptedMessageWrapper {
private:
    EncryptionHandshake& handshake_;
    
public:
    EncryptedMessageWrapper(EncryptionHandshake& handshake)
        : handshake_(handshake) {}
    
    /**
     * Send non-routed control message (never encrypted)
     * Format: [OBJECT type][length][pairs...]
     */
    bool send_control_message(int client_fd, const NoteBytes::Object& msg) {
        auto packet = msg.serialize_with_header();
        return InputPacket::write_packet(client_fd, packet);
    }
    
    /**
     * Send routed device message (optionally encrypted)
     * Format: [INTEGER type][0x00000004][sourceId][OBJECT or ENCRYPTED][length][data...]
     */
    bool send_routed_message(int client_fd, int32_t source_id,
                            const NoteBytes::Object& event,
                            bool encrypt = false) {
        std::vector<uint8_t> packet;
        
        // 1. Write sourceId prefix
        NoteBytes::Value sid(source_id);
        size_t offset = 0;
        packet.resize(sid.serialized_size());
        sid.write_to(packet.data(), offset);
        
        // 2. Write event (encrypted or not)
        if (encrypt && handshake_.is_active()) {
            // Serialize event with header: [0x0C][length][data]
            auto event_packet = event.serialize_with_header();
            
            // Encrypt entire packet (type + length + data)
            auto ciphertext = handshake_.encrypt(event_packet);
            
            // Write as ENCRYPTED type
            size_t base = packet.size();
            packet.resize(base + 5 + ciphertext.size());
            packet[base] = NoteBytes::Type::ENCRYPTED;
            write_uint32_be(packet.data() + base + 1, ciphertext.size());
            memcpy(packet.data() + base + 5, ciphertext.data(), ciphertext.size());
        } else {
            // Write as normal OBJECT
            auto event_packet = event.serialize_with_header();
            packet.insert(packet.end(), event_packet.begin(), event_packet.end());
        }
        
        return InputPacket::write_packet(client_fd, packet);
    }

    /**
     * Send a pre-serialized event packet (with 5-byte NoteBytes header) as a routed message.
     * This avoids re-parsing/re-serializing when the caller already has the packet bytes.
     */
    bool send_routed_serialized(int client_fd, int32_t source_id,
                                const std::vector<uint8_t>& event_packet,
                                bool encrypt = false) {
        // Write sourceId prefix first (no extra copy)
        NoteBytes::Value sid(source_id);
        uint8_t sid_buf[64]; // sufficient for one integer value
        size_t sid_off = 0;
        sid.write_to(sid_buf, sid_off);

        // Write sid
        ssize_t w = ::write(client_fd, sid_buf, sid_off);
        if (w != static_cast<ssize_t>(sid_off)) {
            return false;
        }

        if (encrypt && handshake_.is_active()) {
            // Encrypt entire event packet (including its header)
            auto ciphertext = handshake_.encrypt(event_packet);

            // Build encrypted header
            uint8_t header[5];
            header[0] = NoteBytes::Type::ENCRYPTED;
            write_uint32_be(header + 1, static_cast<uint32_t>(ciphertext.size()));

            if (::write(client_fd, header, 5) != 5) {
                // zero out ciphertext before returning
                std::fill(ciphertext.begin(), ciphertext.end(), 0);
                return false;
            }

            if (::write(client_fd, ciphertext.data(), ciphertext.size()) != static_cast<ssize_t>(ciphertext.size())) {
                std::fill(ciphertext.begin(), ciphertext.end(), 0);
                return false;
            }

            // Zero out ciphertext buffer
            std::fill(ciphertext.begin(), ciphertext.end(), 0);
            return true;
        } else {
            // Write the pre-serialized object packet directly
            if (::write(client_fd, event_packet.data(), event_packet.size()) != static_cast<ssize_t>(event_packet.size())) {
                return false;
            }
            return true;
        }
    }
    
    /**
     * Receive and route message
     * Returns: {is_routed, source_id, message_object}
     */
    struct RoutedMessage {
        bool is_routed;
        int32_t source_id;
        NoteBytes::Object message;
    };
    
    RoutedMessage receive_message(int client_fd, std::vector<uint8_t>& buffer) {
        RoutedMessage result;
        
        if (!InputPacket::read_packet(client_fd, buffer)) {
            throw std::runtime_error("Failed to read packet");
        }
        
        uint8_t first_byte = buffer[0];
        
        if (first_byte == NoteBytes::Type::INTEGER) {
            // Routed message
            result.is_routed = true;
            size_t offset = 0;
            
            // Read sourceId
            NoteBytes::Value source_id_val = NoteBytes::Value::read_from(
                buffer.data(), offset
            );
            result.source_id = source_id_val.as_int();
            
            // Read event (OBJECT or ENCRYPTED)
            uint8_t event_type = buffer[offset];
            
            if (event_type == NoteBytes::Type::ENCRYPTED) {
                // Read encrypted value
                NoteBytes::Value encrypted = NoteBytes::Value::read_from(
                    buffer.data(), offset
                );
                
                // Decrypt
                std::vector<uint8_t> decrypted;
                if (!handshake_.decrypt(encrypted.data(), decrypted)) {
                    throw std::runtime_error("Decryption failed");
                }
                
                // Parse decrypted packet (contains [0x0C][length][data])
                result.message = NoteBytes::Object::deserialize_from_packet(
                    decrypted.data()
                );
                
            } else if (event_type == NoteBytes::Type::OBJECT) {
                // Unencrypted object
                NoteBytes::Value event_val = NoteBytes::Value::read_from(
                    buffer.data(), offset
                );
                
                result.message = NoteBytes::Object::deserialize(
                    event_val.data().data(),
                    event_val.size()
                );
            } else {
                throw std::runtime_error("Invalid event type after sourceId");
            }
            
        } else if (first_byte == NoteBytes::Type::OBJECT) {
            // Non-routed control message
            result.is_routed = false;
            result.source_id = 0;
            result.message = NoteBytes::Object::deserialize_from_packet(
                buffer.data()
            );
            
        } else {
            throw std::runtime_error("Invalid packet type");
        }
        
        return result;
    }
    
private:
    static void write_uint32_be(uint8_t* buffer, uint32_t value) {
        buffer[0] = (value >> 24) & 0xFF;
        buffer[1] = (value >> 16) & 0xFF;
        buffer[2] = (value >> 8) & 0xFF;
        buffer[3] = value & 0xFF;
    }
};


} // namespace EncryptionProtocol

#endif // ENCRYPTION_PROTOCOL_H