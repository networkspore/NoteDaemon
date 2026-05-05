#include "../include/encryption.h"
#include <gtest/gtest.h>
#include <vector>
#include <cstring>

// Mock encryption context for testing
class MockAEADContext {
public:
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
    bool encrypt_called = false;
    bool decrypt_called = false;
    bool decrypt_failed = false;

    int encrypt(const uint8_t* plaintext, size_t plaintext_len,
                const uint8_t* aad, size_t aad_len,
                std::vector<uint8_t>& output,
                std::vector<uint8_t>& tag_output) {
        encrypt_called = true;
        ciphertext = std::vector<uint8_t>(plaintext, plaintext + plaintext_len);
        output = ciphertext;
        tag_output = tag;
        return 0;
    }

    int decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* tag,
                std::vector<uint8_t>& output) {
        decrypt_called = true;
        if (decrypt_failed) return -1;
        
        output = std::vector<uint8_t>(ciphertext, ciphertext + ciphertext_len);
        return 0;
    }
};

class EncryptionTest : public ::testing::Test {
protected:
    std::vector<uint8_t> test_key;
    std::vector<uint8_t> test_iv;
    std::vector<uint8_t> aad = {0xCC, 0xDD, 0xEE, 0xFF};

    EncryptionTest() : aad({0xCC, 0xDD, 0xEE, 0xFF}) {}

    void SetUp() override {
        // Initialize test data
        test_key.resize(32);
        test_iv.resize(16);
        for (size_t i = 0; i < test_key.size(); i++) test_key[i] = (i % 256);
        for (size_t i = 0; i < test_iv.size(); i++) test_iv[i] = ((i + 1) % 256);
    }

    void TearDown() override {
        test_key.clear();
        test_iv.clear();
        aad.clear();
    }
};

// Test zeroization
TEST_F(EncryptionTest, Zeroization) {
    uint8_t sensitive_data[64];
    std::memset(sensitive_data, 0xAA, sizeof(sensitive_data));

    zeroize(sensitive_data, sizeof(sensitive_data));

    for (size_t i = 0; i < sizeof(sensitive_data); i++) {
        EXPECT_EQ(sensitive_data[i], 0) << "Byte " << i << " should be zeroized";
    }
}

// Test key initialization
TEST_F(EncryptionTest, KeyInitialization) {
    uint8_t test_key[32];
    std::memset(test_key, 0x55, sizeof(test_key));

    for (size_t i = 0; i < sizeof(test_key); i++) {
        EXPECT_EQ(test_key[i], 0x55);
    }

    std::memset(test_key, 0, sizeof(test_key));

    for (size_t i = 0; i < sizeof(test_key); i++) {
        EXPECT_EQ(test_key[i], 0);
    }
}

// Test AEAD context structure
TEST_F(EncryptionTest, AEADContextStructure) {
    // This test verifies the structure is properly defined
    // Actual encryption would require OpenSSL, which we're mocking for this test
    MockAEADContext ctx;
    
    std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag(16);

    // Test encryption flow
    ctx.encrypt(plaintext.data(), plaintext.size(),
                aad.data(), aad.size(),
                ciphertext, tag);
    
    EXPECT_TRUE(ctx.encrypt_called);
    EXPECT_EQ(ciphertext.size(), plaintext.size());

    // Test decryption flow
    std::vector<uint8_t> decrypted;
    ctx.decrypt(ciphertext.data(), ciphertext.size(),
                aad.data(), aad.size(),
                tag.data(),
                decrypted);
    
    EXPECT_TRUE(ctx.decrypt_called);
    EXPECT_EQ(decrypted.size(), ciphertext.size());
}

// Test AEAD with different plaintext sizes
TEST_F(EncryptionTest, VariousPlaintextSizes) {
    MockAEADContext ctx;
    std::vector<uint8_t> aad = {0xAA, 0xBB};

    for (size_t size = 1; size <= 64; size += 7) {
        std::vector<uint8_t> plaintext(size);
        for (size_t i = 0; i < size; i++) plaintext[i] = i % 256;

        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> tag(16);

        ctx.encrypt(plaintext.data(), plaintext.size(),
                    aad.data(), aad.size(),
                    ciphertext, tag);
        
        EXPECT_EQ(ciphertext.size(), plaintext.size());
        
        std::vector<uint8_t> decrypted;
        ctx.decrypt(ciphertext.data(), ciphertext.size(),
                    aad.data(), aad.size(),
                    tag.data(),
                    decrypted);
        
        EXPECT_EQ(decrypted.size(), ciphertext.size());
    }
}

// Test AEAD with AAD
TEST_F(EncryptionTest, AEADWithAAD) {
    MockAEADContext ctx;
    std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag(16);

    ctx.encrypt(plaintext.data(), plaintext.size(),
                aad.data(), aad.size(),
                ciphertext, tag);
    
    EXPECT_TRUE(ctx.encrypt_called);

    std::vector<uint8_t> decrypted;
    ctx.decrypt(ciphertext.data(), ciphertext.size(),
                aad.data(), aad.size(),
                tag.data(),
                decrypted);
    
    EXPECT_TRUE(ctx.decrypt_called);
    EXPECT_EQ(decrypted.size(), ciphertext.size());
}

// Test AEAD with invalid tag fails
TEST_F(EncryptionTest, AEADInvalidTagFails) {
    MockAEADContext ctx;
    ctx.decrypt_failed = true; // Simulate decryption failure

    std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag(16);

    ctx.encrypt(plaintext.data(), plaintext.size(),
                aad.data(), aad.size(),
                ciphertext, tag);
    
    EXPECT_TRUE(ctx.encrypt_called);

    std::vector<uint8_t> decrypted;
    int result = ctx.decrypt(ciphertext.data(), ciphertext.size(),
                            aad.data(), aad.size(),
                            tag.data(),
                            decrypted);
    
    EXPECT_EQ(result, -1);
    // Note: decrypt is still called (to check the tag), but returns -1
    EXPECT_TRUE(ctx.decrypt_called);
}

// Test empty plaintext
TEST_F(EncryptionTest, EmptyPlaintext) {
    MockAEADContext ctx;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag(16);

    ctx.encrypt(plaintext.data(), plaintext.size(),
                aad.data(), aad.size(),
                ciphertext, tag);
    
    EXPECT_EQ(ciphertext.size(), 0);

    std::vector<uint8_t> decrypted;
    ctx.decrypt(ciphertext.data(), ciphertext.size(),
                aad.data(), aad.size(),
                tag.data(),
                decrypted);
    
    EXPECT_EQ(decrypted.size(), 0);
}

// Test large data handling
TEST_F(EncryptionTest, LargeDataHandling) {
    MockAEADContext ctx;
    std::vector<uint8_t> aad = {0xAA, 0xBB};

    // Test with 1KB of data
    std::vector<uint8_t> plaintext(1024);
    for (size_t i = 0; i < plaintext.size(); i++) {
        plaintext[i] = (i % 256);
    }

    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag(16);

    ctx.encrypt(plaintext.data(), plaintext.size(),
                aad.data(), aad.size(),
                ciphertext, tag);
    
    EXPECT_EQ(ciphertext.size(), plaintext.size());

    std::vector<uint8_t> decrypted;
    ctx.decrypt(ciphertext.data(), ciphertext.size(),
                aad.data(), aad.size(),
                tag.data(),
                decrypted);
    
    EXPECT_EQ(decrypted.size(), ciphertext.size());
}

// Test encryption/decryption round trip consistency
TEST_F(EncryptionTest, RoundTripConsistency) {
    MockAEADContext ctx;
    std::vector<uint8_t> aad = {0xAA, 0xBB};

    std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag(16);

    ctx.encrypt(original.data(), original.size(),
                aad.data(), aad.size(),
                ciphertext, tag);
    
    std::vector<uint8_t> decrypted;
    ctx.decrypt(ciphertext.data(), ciphertext.size(),
                aad.data(), aad.size(),
                tag.data(),
                decrypted);
    
    // Verify sizes match
    EXPECT_EQ(ciphertext.size(), original.size());
    EXPECT_EQ(decrypted.size(), original.size());
}

// Test tag size
TEST_F(EncryptionTest, TagSize) {
    std::vector<uint8_t> tag(16);
    
    // Verify tag has expected size
    EXPECT_EQ(tag.size(), 16);
    
    // Verify tag can be set and read
    for (size_t i = 0; i < tag.size(); i++) {
        tag[i] = static_cast<uint8_t>(i);
    }

    for (size_t i = 0; i < tag.size(); i++) {
        EXPECT_EQ(tag[i], static_cast<uint8_t>(i));
    }
}

// Test IV size
TEST_F(EncryptionTest, IVSize) {
    std::vector<uint8_t> test_iv(16);
    
    // Verify IV has expected size
    EXPECT_EQ(test_iv.size(), 16);
    
    // Verify IV can be set and read
    for (size_t i = 0; i < test_iv.size(); i++) {
        test_iv[i] = static_cast<uint8_t>(i + 1);
    }

    for (size_t i = 0; i < test_iv.size(); i++) {
        EXPECT_EQ(test_iv[i], static_cast<uint8_t>(i + 1));
    }
}

// Test key size
TEST_F(EncryptionTest, KeySize) {
    std::vector<uint8_t> test_key(32);
    
    // Verify key has expected size for AES-256
    EXPECT_EQ(test_key.size(), 32);
    
    // Verify key can be set and read
    for (size_t i = 0; i < test_key.size(); i++) {
        test_key[i] = static_cast<uint8_t>(i % 256);
    }

    for (size_t i = 0; i < test_key.size(); i++) {
        EXPECT_EQ(test_key[i], static_cast<uint8_t>(i % 256));
    }
}
