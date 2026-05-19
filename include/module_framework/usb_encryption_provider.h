// include/module_framework/usb_encryption_provider.h
// UsbEncryptionProvider - per-device encryption for USB HID devices.
//
// Implements IEncryptionProvider with full DH key exchange
// (2048-bit) and AES-256-GCM authenticated encryption.
//
// Usage:
//   auto provider = std::make_unique<UsbEncryptionProvider>();
//   set_encryption_provider(std::move(provider));

#ifndef USB_ENCRYPTION_PROVIDER_H
#define USB_ENCRYPTION_PROVIDER_H

#include "module_framework/encryption_api.h"
#include "encryption.h"

#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace NoteDaemon {

/**
 * USB-specific encryption provider.
 *
 * Manages per-device DH key exchange (2048-bit) and AES-256-GCM
 * authenticated encryption.  The provider follows this lifecycle
 * per device:
 *
 *   1. start_negotiation()  → generates DH key pair
 *   2. get_public_key()     → returns our public key (for handshake)
 *   3. set_peer_public_key() → receives peer's public key
 *   4. finalize()           → derives shared secret, initialises GCM
 *   5. encrypt() / decrypt() → AES-256-GCM operations
 *   6. remove_device()      → cleans up DH + GCM state
 */
class UsbEncryptionProvider : public IEncryptionProvider {
public:
    UsbEncryptionProvider() = default;
    ~UsbEncryptionProvider() override;

    // ── IEncryptionProvider ─────────────────────────────────────────────

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

    // ── DH key exchange (overrides base no-ops) ──────────────────────────

    bool start_negotiation(std::string_view device_id) override;

    std::vector<uint8_t> get_public_key(
        std::string_view device_id) const override;

    bool set_peer_public_key(
        std::string_view device_id,
        const std::vector<uint8_t>& peer_key) override;

    bool finalize(std::string_view device_id) override;

    std::vector<uint8_t> get_iv(
        std::string_view device_id) const override;

private:
    /**
     * Per-device context: DH key pair + GCM session.
     */
    struct DeviceContext {
        std::unique_ptr<Encryption::DHKeyExchange> dh;
        std::unique_ptr<Encryption::EncryptedSession> session;
        std::vector<uint8_t> key;   // Derived shared secret (32 bytes)
    };

    DeviceContext* get_device_context(
        std::string_view device_id) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<DeviceContext>>
        devices_;
};

} // namespace NoteDaemon

#endif // USB_ENCRYPTION_PROVIDER_H
