cmake_minimum_required(VERSION 3.16)
project(note-daemon-tests VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)

# Find PkgConfig
find_package(PkgConfig REQUIRED)

# Find LibUSB
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)

# Find Google Test
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Test executable
add_executable(note-daemon-tests
    tests_main.cpp
    hid_parser_test.cpp
    encryption_test.cpp
    notebytes_test.cpp
)

target_include_directories(note-daemon-tests PRIVATE
    ../include
)

target_link_libraries(note-daemon-tests PRIVATE
    GTest::gtest
    GTest::gtest_main
    pthread
)

enable_testing()
add_test(NAME hid_parser_tests COMMAND note-daemon-tests --gtest_filter=hid_parser_test.*)
add_test(NAME encryption_tests COMMAND note-daemon-tests --gtest_filter=encryption_test.*)
add_test(NAME notebytes_tests COMMAND note-daemon-tests --gtest_filter=notebytes_test.*)

# Diagnose keyboard clean (working low-latency version)
add_executable(diagnose_keyboard_clean
    diagnose_keyboard_clean.cpp
)

target_include_directories(diagnose_keyboard_clean PRIVATE
    ../include
)

target_link_libraries(diagnose_keyboard_clean PRIVATE
    ${LIBUSB_LIBRARIES}
    pthread
)

target_compile_options(diagnose_keyboard_clean PRIVATE
    -Wall -Wextra -pedantic
)

# Low-latency keyboard capture module
add_library(keyboard_capture_lowlatency
    keyboard_capture_lowlatency.cpp
)

target_include_directories(keyboard_capture_lowlatency PUBLIC
    ../include
    ${LIBUSB_INCLUDE_DIRS}
)

target_link_libraries(keyboard_capture_lowlatency PUBLIC
    ${LIBUSB_LIBRARIES}
    pthread
)

target_compile_options(keyboard_capture_lowlatency PRIVATE
    -Wall -Wextra -pedantic
)

# Low-latency keyboard capture demo
add_executable(keyboard_capture_lowlatency_demo
    keyboard_capture_lowlatency_demo.cpp
)

target_include_directories(keyboard_capture_lowlatency_demo PRIVATE
    ../include
)

target_link_libraries(keyboard_capture_lowlatency_demo PRIVATE
    keyboard_capture_lowlatency
)

target_compile_options(keyboard_capture_lowlatency_demo PRIVATE
    -Wall -Wextra -pedantic
)

# Parse keyboard log file
add_executable(parse_keyboard_log
    parse_keyboard_log.cpp
)

target_include_directories(parse_keyboard_log PRIVATE
    ../include
)

target_link_libraries(parse_keyboard_log PRIVATE
    pthread
)

target_compile_options(parse_keyboard_log PRIVATE
    -Wall -Wextra -pedantic
)
