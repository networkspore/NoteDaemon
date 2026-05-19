// include/module_framework/encryption_api.h
// Core encryption API available to all modules
//
// Per-device symmetric encryption (AES-256-GCM).
// For USB devices, DH key exchange is handled by the module
// (e.g. UsbEncryptionProvider) which derives the 256-bit key
// and passes it to init_device().

#ifndef ENCRYPTION_API_H
#define ENCRYPTION_API_H

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include "error.h"

// DHKeyExchange / EncryptedSession from the prior encryption module.
// These are used internally by the providers for DH key exchange
// and AES-256-GCM authenticated encryption.
#include "encryption.h"

namespace NoteDaemon {

/**
 * Encryption provider - provides per-device encryption for modules.
 *
 * This is a core service that modules can use for encrypting/decrypting
 * device-specific data.  No handshake/negotiation at this level —
 * the key is expected to be derived externally (e.g. via DH key
 * exchange in the USB module).
 *
 * For USB devices the provider is typically UsbEncryptionProvider
 * (in the NoteUSB module) which handles the full DH handshake.
 * The DefaultEncryptionProvider is a fallback that accepts a
 * pre-derived 256-bit key directly.
 */
class IEncryptionProvider {
public:
    virtual ~IEncryptionProvider() = default;

    // ── Symmetric encryption ──────────────────────────────────────────────

    /**
     * Initialize encryption for a specific device.
     *
     * @param device_id Unique identifier for the device.
     * @param key       Encryption key (32 raw bytes for AES-256).
     *                  For USB devices this is the DH-derived shared secret.
     * @return Error::success() on success.
     */
    virtual Error init_device(std::string_view device_id,
                              const std::vector<uint8_t>& key) = 0;

    /**
     * Check if a device has active encryption.
     */
    virtual bool is_encrypted(std::string_view device_id) const = 0;

    /**
     * Encrypt data for a specific device.
     * Output format: [ciphertext][16-byte auth tag]  (AES-256-GCM).
     */
    virtual bool encrypt(std::string_view device_id,
                        const std::vector<uint8_t>& plaintext,
                        std::vector<uint8_t>& ciphertext) = 0;

    /**
     * Decrypt data from a specific device.
     * Input format: [ciphertext][16-byte auth tag].
     */
    virtual bool decrypt(std::string_view device_id,
                        const std::vector<uint8_t>& ciphertext,
                        std::vector<uint8_t>& plaintext) = 0;

    /**
     * Remove encryption context for a device.
     */
    virtual void remove_device(std::string_view device_id) = 0;

    /**
     * Remove all device encryption contexts.
     */
    virtual void clear_all() = 0;

    // ── DH key exchange (USB-specific, default no-op) ─────────────────────
    // These are optional; DefaultEncryptionProvider ignores them.
    // UsbEncryptionProvider overrides them for USB devices.

    /**
     * Start DH key exchange negotiation for a device.
     * Generates a 2048-bit DH key pair.
     * @return true if negotiation started successfully.
     */
    virtual bool start_negotiation(std::string_view device_id) {
        (void)device_id;
        return false;
    }

    /**
     * Get our DH public key for the given device.
     * Returns empty vector if negotiation not started.
     */
    virtual std::vector<uint8_t> get_public_key(
        std::string_view device_id) const {
        (void)device_id;
        return {};
    }

    /**
     * Set the peer's DH public key.
     * @return true if key was accepted.
     */
    virtual bool set_peer_public_key(
        std::string_view device_id,
        const std::vector<uint8_t>& peer_key) {
        (void)device_id; (void)peer_key;
        return false;
    }

    /**
     * Finalize DH key exchange: derive shared secret and
     * initialize symmetric encryption with it.
     * @return true if finalization succeeded.
     */
    virtual bool finalize(std::string_view device_id) {
        (void)device_id;
        return false;
    }

    /**
     * Get the current IV for a device (for ENCRYPTION_READY).
     * Returns empty vector if not available.
     */
    virtual std::vector<uint8_t> get_iv(
        std::string_view device_id) const {
        (void)device_id;
        return {};
    }
};

/**
 * Default encryption provider implementation.
 * Uses AES-256-GCM for authenticated encryption.
 *
 * Accepts a pre-derived 256-bit key (e.g. from DH key exchange).
 * Maintains an EncryptedSession per device for IV statefulness.
 */
class DefaultEncryptionProvider : public IEncryptionProvider {
public:
    DefaultEncryptionProvider();
    ~DefaultEncryptionProvider() override;

    Error init_device(std::string_view device_id,
                      const std::vector<uint8_t>& key) override;

    bool is_encrypted(std::string_view device_id) const override;

    bool encrypt(std::string_view device_id,
                const std::vector<uint8_t>& plaintext,
                std::vector<uint8_t>& ciphertext) override;

    bool decrypt(std::string_view device_id,
                const std::vector<uint8_t>& ciphertext,
                std::vector<uint8_t>& plaintext) override;

    void remove_device(std::string_view device_id) override;

    void clear_all() override;

private:
    /**
     * Per-device context: 32-byte AES key + GCM session (maintains IV).
     */
    struct DeviceContext {
        std::vector<uint8_t> key;                               // 32 bytes
        std::unique_ptr<Encryption::EncryptedSession> session;  // GCM state
    };

    DeviceContext* get_device_context(std::string_view device_id) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<DeviceContext>> devices_;
};

// ── Global provider access ────────────────────────────────────────────────

/**
 * Get the global encryption provider instance.
 * Modules call this to get encryption services.
 *
 * Usage:
 *   auto& enc = get_encryption_provider();
 *   enc.init_device("1:2", key_bytes);
 *   enc.encrypt("1:2", plaintext, ciphertext);
 */
IEncryptionProvider& get_encryption_provider();

/**
 * Set a custom encryption provider (e.g. UsbEncryptionProvider
 * from the NoteUSB module).  Called once during daemon startup.
 */
void set_encryption_provider(std::unique_ptr<IEncryptionProvider> provider);

// ── Encryption error helpers ─────────────────────────────────────────────

inline Error make_encryption_init_error(std::string_view device_id,
                                      const std::string& reason) {
    return Error::from_code(ErrorCodes::ENCRYPTION_INIT_FAILED,
                            "Failed to init encryption for device " +
                            std::string(device_id) + ": " + reason,
                            "encryption_api");
}

inline Error make_encryption_device_not_found_error(
    std::string_view device_id) {
    return Error::from_code(ErrorCodes::ENCRYPTION_DEVICE_NOT_FOUND,
                            "Device not found: " + std::string(device_id),
                            "encryption_api");
}

inline Error make_encryption_failed_error(const std::string& reason) {
    return Error::from_code(ErrorCodes::ENCRYPTION_FAILED,
                            "Encryption operation failed: " + reason,
                            "encryption_api");
}

} // namespace NoteDaemon

#endif // ENCRYPTION_API_H
