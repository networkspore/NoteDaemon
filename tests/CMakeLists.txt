cmake_minimum_required(VERSION 3.16)

# Use new behavior for FetchContent / CMake compatibility
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
project(NoteDaemonTests)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)

# Google Test
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Test sources
set(TEST_SOURCES
    test_main.cpp
    ../src/keyboard_capture_lowlatency.cpp
    # Core framework sources needed for tests
    ../src/core/module_registry.cpp
    ../src/core/module_loader.cpp
    # All test files will be added here as they are created
)

# Add keyboard_capture_lowlatency test
list(APPEND TEST_SOURCES keyboard_capture_lowlatency_test.cpp)

# Add hid_device_streaming_thread test
list(APPEND TEST_SOURCES hid_device_streaming_thread_test.cpp)

# Add device_session test
list(APPEND TEST_SOURCES device_session_test.cpp)

# Add error_handling test
list(APPEND TEST_SOURCES error_handling_test.cpp)

# Add device_claim_release test (device claiming and releasing workflow)
list(APPEND TEST_SOURCES device_claim_release_test.cpp)

# Add encryption test
list(APPEND TEST_SOURCES encryption_test.cpp)

# Add hid_parser (key_code) test
list(APPEND TEST_SOURCES hid_parser_test.cpp)

# Add notebytes test
list(APPEND TEST_SOURCES notebytes_test.cpp)

# Create test executable
add_executable(note-daemon-tests ${TEST_SOURCES})

target_include_directories(note-daemon-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/dro
    ${CMAKE_SOURCE_DIR}/include/module_framework
    ${CMAKE_SOURCE_DIR}/src
    ${LIBUSB_INCLUDE_DIRS}
)

target_link_libraries(note-daemon-tests PRIVATE
    gtest
    gtest_main
    ${LIBUSB_LIBRARIES}
    pthread
    ssl
    crypto
)

# Add tests to CTest
include(CTest)
include(GoogleTest)
gtest_discover_tests(note-daemon-tests)

# Keep the demo as a separate executable (optional, for manual testing)
if(ENABLE_DEMO)
    add_executable(keyboard_capture_lowlatency_demo
        keyboard_capture_lowlatency_demo.cpp
    )

    target_include_directories(keyboard_capture_lowlatency_demo PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/dro
        ${LIBUSB_INCLUDE_DIRS}
    )

    target_link_libraries(keyboard_capture_lowlatency_demo PRIVATE
        ${LIBUSB_LIBRARIES}
        pthread
    )
endif()
