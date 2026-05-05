# NoteDaemon Tests

This directory contains unit tests for NoteDaemon using Google Test.

## Test Coverage

### Encryption Tests (`encryption_test.cpp`)
- DH key exchange initialization and consistency
- AEAD encryption/decryption with various message sizes
- Additional authenticated data (AAD) support
- Tag validation and rejection of invalid tags
- Secure zeroization of sensitive data

### NoteBytes Tests (`notebytes_test.cpp`)
- Header parsing (magic, version, length, flags)
- Message creation and round-trip parsing
- Support for various message sizes
- NoteBytesReader and Writer implementations
- Error handling for invalid/malformed headers
- Endianness conversion functions

### HID Parser Tests (`hid_parser_test.cpp`)
- Report descriptor parsing
- Usage page, usage range, and logical range parsing
- Report count and size parsing
- Input, output, and feature field parsing
- Collection stack depth tracking
- Report ID parsing
- Keyboard report descriptor parsing

### Device Session Tests (`device_session_test.cpp`)
- State initialization and cleanup
- Bitflag state tracking
- Capability registry operations (add, check, union, intersection)
- Input packet handling
- Event bytes handling

## Building Tests

```bash
mkdir build
cd build
cmake ..
make
```

## Running Tests

### Run all tests
```bash
./note-daemon-tests
```

### Run specific test
```bash
./note-daemon-tests --gtest_filter=encryption_test.*
```

### Run tests matching a pattern
```bash
./note-daemon-tests --gtest_filter=*notebytes*
```

### Run tests with verbose output
```bash
./note-daemon-tests --gtest_verbose
```

### Run tests in parallel
```bash
./note-daemon-tests --gtest_parallelism=4
```

## Continuous Integration

Tests can be run automatically by CTest:
```bash
cd build
ctest --output-on-failure
```

## Adding New Tests

1. Create a new test file in `tests/` directory
2. Include the appropriate header files
3. Create a test fixture class inheriting from `::testing::Test`
4. Implement test cases using `TEST_F` or `TEST`
5. Update `tests/CMakeLists.txt` to include the new test file

Example:
```cpp
#include "../include/your_header.h"
#include <gtest/gtest.h>

class YourTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code
    }
    void TearDown() override {
        // Cleanup code
    }
};

TEST_F(YourTest, YourTestCase) {
    // Test implementation
    EXPECT_EQ(some_function(), expected_value);
}
```
