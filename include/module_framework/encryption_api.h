// include/module_framework/encryption_api.h
// Core encryption API available to all modules

#ifndef ENCRYPTION_API_H
#define ENCRYPTION_API_H

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include "error.h"

namespace NoteDaemon {

/**
 * Encryption provider - provides per-device encryption for modules
 * 
 * This is a core service that modules can use for encrypting/decrypting
 * device-specific data. No handshake/negotiation - simple symmetric encryption.
 */
class IEncryptionProvider {
public:
    virtual ~IEncryptionProvider() = default;
    
    /**
     * Initialize encryption for a specific device
     * 
     * @param device_id Unique identifier for the device
     * @param key Encryption key (raw bytes)
     * @return Error::success() on success
     */
    virtual Error init_device(std::string_view device_id,
                              const std::vector<uint8_t>& key) = 0;
    
    /**
     * Check if a device has active encryption
     * 
     * @param device_id Device identifier
     * @return true if encryption is active for device
     */
    virtual bool is_encrypted(std::string_view device_id) const = 0;
    
    /**
     * Encrypt data for a specific device
     * 
     * @param device_id Device identifier
     * @param plaintext Data to encrypt
     * @param ciphertext Output buffer for encrypted data
     * @return true on success
     */
    virtual bool encrypt(std::string_view device_id,
                        const std::vector<uint8_t>& plaintext,
                        std::vector<uint8_t>& ciphertext) = 0;
    
    /**
     * Decrypt data from a specific device
     * 
     * @param device_id Device identifier
     * @param ciphertext Data to decrypt
     * @param plaintext Output buffer for decrypted data
     * @return true on success
     */
    virtual bool decrypt(std::string_view device_id,
                        const std::vector<uint8_t>& ciphertext,
                        std::vector<uint8_t>& plaintext) = 0;
    
    /**
     * Remove encryption context for a device
     * 
     * @param device_id Device identifier
     */
    virtual void remove_device(std::string_view device_id) = 0;
    
    /**
     * Remove all device encryption contexts
     */
    virtual void clear_all() = 0;
};

/**
 * Default encryption provider implementation
 * Uses AES-256-GCM for authenticated encryption
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
    struct DeviceContext {
        std::vector<uint8_t> key;
        // In a real implementation, would store expanded key material
    };
    
    DeviceContext* get_device_context(std::string_view device_id) const;
    
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<DeviceContext>> devices_;
};

/**
 * Get the global encryption provider instance
 * Modules call this to get encryption services
 * 
 * Usage:
 *   auto& enc = get_encryption_provider();
 *   enc.init_device("1:2", key_bytes);
 *   enc.encrypt("1:2", plaintext, ciphertext);
 */
IEncryptionProvider& get_encryption_provider();

/**
 * Set a custom encryption provider
 * For testing or alternative implementations
 */
void set_encryption_provider(std::unique_ptr<IEncryptionProvider> provider);

/**
 * Encryption errors
 */
inline Error make_encryption_init_error(std::string_view device_id, const std::string& reason) {
    return Error::from_code(ErrorCodes::ENCRYPTION_INIT_FAILED,
                            "Failed to init encryption for device " + 
                            std::string(device_id) + ": " + reason,
                            "encryption_api");
}

inline Error make_encryption_device_not_found_error(std::string_view device_id) {
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