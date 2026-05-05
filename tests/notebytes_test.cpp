#include "../include/notebytes.h"
#include <gtest/gtest.h>
#include <vector>
#include <cstring>

class NoteBytesTest : public ::testing::Test {
protected:
    std::vector<uint8_t> buffer;
    std::vector<uint8_t> key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                                 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
    std::vector<uint8_t> iv = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
                                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};

    void SetUp() override {
        buffer.resize(4096);
    }

    void TearDown() override {
        buffer.clear();
        key.clear();
        iv.clear();
    }
};

// Test zeroization
TEST_F(NoteBytesTest, Zeroization) {
    uint8_t data[64];
    std::memset(data, 0xAA, sizeof(data));

    zeroize(data, sizeof(data));

    for (size_t i = 0; i < sizeof(data); i++) {
        EXPECT_EQ(data[i], 0) << "Byte " << i << " should be zeroized";
    }
}

// Test message integrity
TEST_F(NoteBytesTest, MessageIntegrity) {
    std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    // Serialize
    std::vector<uint8_t> serialized;
    serialized.insert(serialized.end(), original.begin(), original.end());

    // Deserialize
    std::vector<uint8_t> deserialized;
    deserialized.insert(deserialized.end(), original.begin(), original.end());

    // Should be identical
    EXPECT_EQ(serialized, deserialized);
}

// Test NoteBytes::Value construction
TEST_F(NoteBytesTest, ValueConstruction) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    NoteBytes::Value value(data);
    
    EXPECT_EQ(value.type(), NoteBytes::Type::RAW_BYTES);
    EXPECT_EQ(value.size(), 4);
}

// Test NoteBytes::Value with string
TEST_F(NoteBytesTest, ValueWithString) {
    NoteBytes::Value value("hello");
    
    EXPECT_EQ(value.type(), NoteBytes::Type::STRING);
    EXPECT_EQ(value.size(), 5);
}

// Test NoteBytes::Value with integer
TEST_F(NoteBytesTest, ValueWithInteger) {
    NoteBytes::Value value(12345);
    
    EXPECT_EQ(value.type(), NoteBytes::Type::INTEGER);
    EXPECT_EQ(value.size(), 4);
}

// Test NoteBytes::Value with vector
TEST_F(NoteBytesTest, ValueWithVector) {
    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC, 0xDD};
    NoteBytes::Value value(data);
    
    EXPECT_EQ(value.type(), NoteBytes::Type::RAW_BYTES);
    EXPECT_EQ(value.size(), 4);
}

// Test NoteBytes::Value equality
TEST_F(NoteBytesTest, ValueEquality) {
    std::vector<uint8_t> data1 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> data2 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> data3 = {0x02, 0x02, 0x03, 0x04};
    
    NoteBytes::Value value1(data1);
    NoteBytes::Value value2(data2);
    NoteBytes::Value value3(data3);
    
    EXPECT_EQ(value1, value2);
    EXPECT_NE(value1, value3);
}

// Test NoteBytes::Value copy
TEST_F(NoteBytesTest, ValueCopy) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    NoteBytes::Value value1(data);
    NoteBytes::Value value2 = value1;
    
    EXPECT_EQ(value1.type(), value2.type());
    EXPECT_EQ(value1.size(), value2.size());
    EXPECT_EQ(value1.data(), value2.data());
}

// Test NoteBytes::Value move
TEST_F(NoteBytesTest, ValueMove) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    NoteBytes::Value value1(data);
    NoteBytes::Value value2 = std::move(value1);
    
    EXPECT_EQ(value2.type(), NoteBytes::Type::RAW_BYTES);
    EXPECT_EQ(value2.size(), 4);
}

// Test NoteBytes::Type enum
TEST_F(NoteBytesTest, TypeEnum) {
    EXPECT_EQ(NoteBytes::Type::RAW_BYTES, 0);
    EXPECT_EQ(NoteBytes::Type::BYTE, 1);
    EXPECT_EQ(NoteBytes::Type::SHORT, 2);
    EXPECT_EQ(NoteBytes::Type::INTEGER, 3);
    EXPECT_EQ(NoteBytes::Type::FLOAT, 4);
    EXPECT_EQ(NoteBytes::Type::DOUBLE, 5);
    EXPECT_EQ(NoteBytes::Type::LONG, 6);
    EXPECT_EQ(NoteBytes::Type::BOOLEAN, 7);
    EXPECT_EQ(NoteBytes::Type::STRING_UTF16, 8);
    EXPECT_EQ(NoteBytes::Type::STRING_ISO_8859_1, 9);
    EXPECT_EQ(NoteBytes::Type::STRING_US_ASCII, 10);
    EXPECT_EQ(NoteBytes::Type::STRING, 11);
    EXPECT_EQ(NoteBytes::Type::OBJECT, 12);
    EXPECT_EQ(NoteBytes::Type::ARRAY, 13);
    EXPECT_EQ(NoteBytes::Type::INTEGER_ARRAY, 14);
}

// Test NoteBytes::Value data access
TEST_F(NoteBytesTest, ValueDataAccess) {
    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC, 0xDD};
    NoteBytes::Value value(data);
    
    EXPECT_EQ(value.data().size(), 4);
    EXPECT_EQ(value.data()[0], 0xAA);
    EXPECT_EQ(value.data()[1], 0xBB);
    EXPECT_EQ(value.data()[2], 0xCC);
    EXPECT_EQ(value.data()[3], 0xDD);
}
