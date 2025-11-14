// src/notebytes.h
// C++ implementation of NoteBytes serialization format
// Compatible with Java NoteBytes for cross-language communication

#ifndef NOTEBYTES_H
#define NOTEBYTES_H

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>


namespace NoteBytes {

// Type constants matching Java NoteBytesMetaData
namespace Type {
    constexpr uint8_t RAW_BYTES = 0;
    constexpr uint8_t BYTE = 1;
    constexpr uint8_t SHORT = 2;
    constexpr uint8_t INTEGER = 3;
    constexpr uint8_t FLOAT = 4;
    constexpr uint8_t DOUBLE = 5;
    constexpr uint8_t LONG = 6;
    constexpr uint8_t BOOLEAN = 7;
    constexpr uint8_t STRING_UTF16 = 8;
    constexpr uint8_t STRING_ISO_8859_1 = 9;
    constexpr uint8_t STRING_US_ASCII = 10;
    constexpr uint8_t STRING = 11;  // UTF-8
    constexpr uint8_t OBJECT = 12;
    constexpr uint8_t ARRAY = 13;
    constexpr uint8_t INTEGER_ARRAY = 14;
    constexpr uint8_t BIG_INTEGER = 15;
    constexpr uint8_t BIG_DECIMAL = 16;
    constexpr uint8_t SHORT_LE_TYPE = 17;
    constexpr uint8_t INTEGER_LE_TYPE = 18;
    constexpr uint8_t FLOAT_LE_TYPE = 19;
    constexpr uint8_t DOUBLE_LE_TYPE = 20;
    constexpr uint8_t LONG_LE_TYPE = 21;
    constexpr uint8_t STRING_UTF16_LE_TYPE = 22;
    constexpr uint8_t IMAGE_TYPE = 23;
    constexpr uint8_t VIDEO_TYPE = 24;
    constexpr uint8_t SERIALIZABLE_JAVA_OBJECT_TYPE = 25;
    constexpr uint8_t ENCRYPTED = 26;
}

constexpr size_t METADATA_SIZE = 5;  // 1 byte type + 4 bytes length


/**
 * Base NoteBytes class - represents a typed byte array
 */
class Value {
private:
    std::vector<uint8_t> data_;
    uint8_t type_;

public:
    Value() : type_(Type::RAW_BYTES) {}
    
    Value(const std::vector<uint8_t>& data, uint8_t type = Type::RAW_BYTES) 
        : data_(data), type_(type) {}
    
    Value(const uint8_t* data, size_t len, uint8_t type = Type::RAW_BYTES)
        : data_(data, data + len), type_(type) {}
    
    // String constructor (UTF-8)
    Value(const std::string& str) 
        : data_(str.begin(), str.end()), type_(Type::STRING) {}
    
    Value(const char* str) 
        : data_(str, str + strlen(str)), type_(Type::STRING) {}
    
    // Integer constructor
    Value(int32_t val) : type_(Type::INTEGER) {
        data_.resize(4);
        data_[0] = (val >> 24) & 0xFF;
        data_[1] = (val >> 16) & 0xFF;
        data_[2] = (val >> 8) & 0xFF;
        data_[3] = val & 0xFF;
    }
    
    // Long constructor
    Value(int64_t val) : type_(Type::LONG) {
        data_.resize(8);
        for (int i = 0; i < 8; i++) {
            data_[i] = (val >> (56 - i * 8)) & 0xFF;
        }
    }
    
    // Boolean constructor
    Value(bool val) : type_(Type::BOOLEAN) {
        data_.resize(1);
        data_[0] = val ? 1 : 0;
    }
    
    // Double constructor
    Value(double val) : type_(Type::DOUBLE) {
        data_.resize(8);
        uint64_t bits;
        memcpy(&bits, &val, sizeof(double));
        for (int i = 0; i < 8; i++) {
            data_[i] = (bits >> (56 - i * 8)) & 0xFF;
        }
    }
    
    // Byte constructor
    Value(uint8_t val) : type_(Type::BYTE) {
        data_.resize(1);
        data_[0] = val;
    }
    
    uint8_t type() const { return type_; }
    const std::vector<uint8_t>& data() const { return data_; }
    size_t size() const { return data_.size(); }
    
    // Conversion methods
    std::string as_string() const {
        return std::string(data_.begin(), data_.end());
    }
    
    int32_t as_int() const {
        if (data_.size() < 4) return 0;
        return (data_[0] << 24) | (data_[1] << 16) | 
               (data_[2] << 8) | data_[3];
    }
    
    int64_t as_long() const {
        if (data_.size() < 8) return 0;
        int64_t result = 0;
        for (size_t i = 0; i < 8; i++) {
            result = (result << 8) | data_[i];
        }
        return result;
    }
    
    bool as_bool() const {
        return !data_.empty() && data_[0] != 0;
    }
    
    double as_double() const {
        if (data_.size() < 8) return 0.0;
        uint64_t bits = 0;
        for (size_t i = 0; i < 8; i++) {
            bits = (bits << 8) | data_[i];
        }
        double result;
        memcpy(&result, &bits, sizeof(double));
        return result;
    }
    
    uint8_t as_byte() const {
        return data_.empty() ? 0 : data_[0];
    }
    
    // Serialization: write to buffer
    size_t write_to(uint8_t* buffer, size_t offset) const {
        buffer[offset++] = type_;
        uint32_t len = data_.size();
        buffer[offset++] = (len >> 24) & 0xFF;
        buffer[offset++] = (len >> 16) & 0xFF;
        buffer[offset++] = (len >> 8) & 0xFF;
        buffer[offset++] = len & 0xFF;
        memcpy(buffer + offset, data_.data(), len);
        return offset + len;
    }
    
    // Deserialization: read from buffer
    static Value read_from(const uint8_t* buffer, size_t& offset) {
        uint8_t type = buffer[offset++];
        uint32_t len = (buffer[offset] << 24) | 
                       (buffer[offset + 1] << 16) |
                       (buffer[offset + 2] << 8) | 
                       buffer[offset + 3];
        offset += 4;
        
        Value val(buffer + offset, len, type);
        offset += len;
        return val;
    }
    
    size_t serialized_size() const {
        return METADATA_SIZE + data_.size();
    }
};

/**
 * Key-Value Pair (matches Java NoteBytesPair)
 */
class Pair {
private:
    Value key_;
    Value value_;

public:
    Pair(const Value& key, const Value& value) 
        : key_(key), value_(value) {}
    
    Pair(const std::string& key, const Value& value)
        : key_(key), value_(value) {}
    
    Pair(const char* key, const Value& value)
        : key_(key), value_(value) {}
    
    const Value& key() const { return key_; }
    const Value& value() const { return value_; }
    
    size_t serialized_size() const {
        return key_.serialized_size() + value_.serialized_size();
    }
    
    size_t write_to(uint8_t* buffer, size_t offset) const {
        offset = key_.write_to(buffer, offset);
        offset = value_.write_to(buffer, offset);
        return offset;
    }
    
    static Pair read_from(const uint8_t* buffer, size_t& offset) {
        Value key = Value::read_from(buffer, offset);
        Value val = Value::read_from(buffer, offset);
        return Pair(key, val);
    }
};

/**
 * NoteBytesObject - map of key-value pairs
 * Matches Java NoteBytesObject serialization format
 */
class Object {
private:
    std::vector<Pair> pairs_;

public:
    Object() = default;
    
    // Add methods with various key types
    void add(const char* key, const Value& value) {
        pairs_.emplace_back(key, value);
    }
    
    void add(const std::string& key, const Value& value) {
        pairs_.emplace_back(key, value);
    }
    
    void add(const char* key, const std::string& value) {
        pairs_.emplace_back(key, Value(value));
    }
    
    void add(const char* key, int32_t value) {
        pairs_.emplace_back(key, Value(value));
    }
    
    void add(const char* key, int64_t value) {
        pairs_.emplace_back(key, Value(value));
    }
    
    void add(const char* key, bool value) {
        pairs_.emplace_back(key, Value(value));
    }
    
    void add(const char* key, double value) {
        pairs_.emplace_back(key, Value(value));
    }
    
    void add(const char* key, uint8_t value) {
        pairs_.emplace_back(key, Value(value));
    }
    
    void add(const Pair& pair) {
        pairs_.push_back(pair);
    }
    
    // Get methods
    const Value* get(const std::string& key) const {
        for (const auto& pair : pairs_) {
            if (pair.key().as_string() == key) {
                return &pair.value();
            }
        }
        return nullptr;
    }
    
    std::string get_string(const std::string& key, const std::string& default_val = "") const {
        const Value* val = get(key);
        return val ? val->as_string() : default_val;
    }
    
    int32_t get_int(const std::string& key, int32_t default_val = 0) const {
        const Value* val = get(key);
        return val ? val->as_int() : default_val;
    }
    
    int64_t get_long(const std::string& key, int64_t default_val = 0) const {
        const Value* val = get(key);
        return val ? val->as_long() : default_val;
    }
    
    bool get_bool(const std::string& key, bool default_val = false) const {
        const Value* val = get(key);
        return val ? val->as_bool() : default_val;
    }
    
    uint8_t get_byte(const std::string& key, uint8_t default_val = 0) const {
        const Value* val = get(key);
        return val ? val->as_byte() : default_val;
    }
    
    bool contains(const std::string& key) const {
        return get(key) != nullptr;
    }
    
    size_t size() const { return pairs_.size(); }
    bool empty() const { return pairs_.empty(); }
    
    // Iteration
    const std::vector<Pair>& pairs() const { return pairs_; }
    
    // Serialization (body only, no header)
    size_t serialized_size() const {
        size_t total = 0;
        for (const auto& pair : pairs_) {
            total += pair.serialized_size();
        }
        return total;
    }
    
    std::vector<uint8_t> serialize() const {
        size_t size = serialized_size();
        std::vector<uint8_t> buffer(size);
        size_t offset = 0;
        for (const auto& pair : pairs_) {
            offset = pair.write_to(buffer.data(), offset);
        }
        return buffer;
    }
    
    /**
     * Serialize with 5-byte header: [1-byte type][4-byte length]
     * This matches Java's packet format exactly
     */
    std::vector<uint8_t> serialize_with_header() const {
        auto body = serialize();
        uint32_t body_len = body.size();
        
        std::vector<uint8_t> packet(METADATA_SIZE + body_len);
        packet[0] = Type::OBJECT;
        packet[1] = (body_len >> 24) & 0xFF;
        packet[2] = (body_len >> 16) & 0xFF;
        packet[3] = (body_len >> 8) & 0xFF;
        packet[4] = body_len & 0xFF;
        
        memcpy(packet.data() + METADATA_SIZE, body.data(), body_len);
        return packet;
    }
    
    // Deserialization
    static Object deserialize(const uint8_t* buffer, size_t length) {
        Object obj;
        size_t offset = 0;
        while (offset < length) {
            Pair pair = Pair::read_from(buffer, offset);
            obj.add(pair);
        }
        return obj;
    }
    
    /**
     * Deserialize from packet with 5-byte header
     */
    static Object deserialize_from_packet(const uint8_t* buffer) {
        uint8_t type = buffer[0];
        if (type != Type::OBJECT) {
            throw std::runtime_error("Invalid packet type");
        }
        
        uint32_t len = (buffer[1] << 24) | (buffer[2] << 16) | 
                       (buffer[3] << 8) | buffer[4];
        
        return deserialize(buffer + METADATA_SIZE, len);
    }

    Value as_value() const {
        auto data = serialize();
        return Value(data, Type::OBJECT);
    }
};

/**
 * NoteBytesArray - array of values
 */
class Array {
private:
    std::vector<Value> values_;

public:
    Array() = default;
    
    void add(const Value& value) {
        values_.push_back(value);
    }
    
    const Value& get(size_t index) const {
        return values_.at(index);
    }
    
    size_t size() const { return values_.size(); }
    bool empty() const { return values_.empty(); }
    
    const std::vector<Value>& values() const { return values_; }
    
    // Serialization
    size_t serialized_size() const {
        size_t total = 0;
        for (const auto& val : values_) {
            total += val.serialized_size();
        }
        return total;
    }
    
    std::vector<uint8_t> serialize() const {
        size_t size = serialized_size();
        std::vector<uint8_t> buffer(size);
        size_t offset = 0;
        for (const auto& val : values_) {
            offset = val.write_to(buffer.data(), offset);
        }
        return buffer;
    }
    
    Value as_value() const {
        auto data = serialize();
        return Value(data, Type::ARRAY);
    }
};

} // namespace NoteBytes

#endif // NOTEBYTES_H