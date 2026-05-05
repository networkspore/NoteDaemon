cmake_minimum_required(VERSION 3.16)
project(note-daemon-tests VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)

# Find Google Test
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)

# For Windows: Prevent overriding parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

# Add test executable
add_executable(note-daemon-tests
    tests_main.cpp
    hid_parser_test.cpp
    encryption_test.cpp
    notebytes_test.cpp
    device_session_test.cpp
)

# Include directories
target_include_directories(note-daemon-tests PRIVATE
    ../include
)

# Link libraries
target_link_libraries(note-daemon-tests PRIVATE
    GTest::gtest
    GTest::gtest_main
    pthread
)

# Enable testing
enable_testing()

# Add tests
add_test(NAME hid_parser_tests COMMAND note-daemon-tests --gtest_filter=hid_parser_test.*)
add_test(NAME encryption_tests COMMAND note-daemon-tests --gtest_filter=encryption_test.*)
add_test(NAME notebytes_tests COMMAND note-daemon-tests --gtest_filter=notebytes_test.*)
add_test(NAME device_session_tests COMMAND note-daemon-tests --gtest_filter=device_session_test.*)
