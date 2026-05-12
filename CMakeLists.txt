cmake_minimum_required(VERSION 3.16)
project(note-daemon VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)

# Source files - main daemon (excluding core which is built differently for now)
file(GLOB SOURCES 
    src/main.cpp
    src/device_session.cpp
    src/device_registry.cpp
    src/keyboard_capture_lowlatency.cpp
)

# Core framework sources
set(CORE_SOURCES
    src/core/module_loader.cpp
    src/core/module_registry.cpp
    src/core/error_collector.cpp
    src/core/config_manager.cpp
    src/core/encryption_api.cpp
)

# Combine all sources
set(ALL_SOURCES ${SOURCES} ${CORE_SOURCES})

# Executable
add_executable(note-daemon ${ALL_SOURCES})

# Include directories
target_include_directories(note-daemon PRIVATE
    include
    include/module_framework
    src
    ${LIBUSB_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(note-daemon PRIVATE
    ${LIBUSB_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
    dl
)

# Export all symbols so dynamically loaded modules can access them
# This is needed for modules to call functions from the main executable
set_target_properties(note-daemon PROPERTIES LINK_FLAGS "-rdynamic")

# Compiler options
target_compile_options(note-daemon PRIVATE
    -Wall -Wextra -Werror -pedantic -O2
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Install rules
install(TARGETS note-daemon
    RUNTIME DESTINATION /usr/local/bin
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                GROUP_READ GROUP_EXECUTE
                WORLD_READ WORLD_EXECUTE
)
install(FILES note-daemon.service DESTINATION /etc/systemd/system)
install(FILES 99-netnotes.rules DESTINATION /etc/udev/rules.d)

# Build info
message(STATUS "note-daemon Version: ${PROJECT_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "LibUSB Version: ${LIBUSB_VERSION}")
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")

# Add tests subdirectory
add_subdirectory(tests)

# Add process-monitor subdirectory
add_subdirectory(process-monitor)

# Create module directory for installed modules
install(DIRECTORY DESTINATION /etc/netnotes/modules)