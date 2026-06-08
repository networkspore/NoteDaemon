cmake_minimum_required(VERSION 3.16)
project(note-daemon VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)

find_package(PkgConfig REQUIRED)

# LibUSB is optional — only needed for NoteUSB module support
# (device_session, keyboard_capture, libusb probe in main)
option(WITH_LIBUSB "Enable libusb support (required for NoteUSB module)" ON)
if(WITH_LIBUSB)
    pkg_check_modules(LIBUSB REQUIRED libusb-1.0)
endif()

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)

# Source files - main daemon
file(GLOB SOURCES
    src/main.cpp
    src/device_registry.cpp
)

# USB-dependent sources (only compiled when libusb is available)
if(WITH_LIBUSB)
    list(APPEND SOURCES
        src/device_session.cpp
        src/keyboard_capture_lowlatency.cpp
    )
endif()

# Core framework sources
set(CORE_SOURCES
    src/core/module_loader.cpp
    src/core/module_registry.cpp
    src/core/error_collector.cpp
    src/core/config_manager.cpp
    src/core/encryption_api.cpp
    src/core/usb_encryption_provider.cpp
    src/core/path_resolver.cpp
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
    ${Boost_INCLUDE_DIRS}
)

if(WITH_LIBUSB)
    target_include_directories(note-daemon PRIVATE ${LIBUSB_INCLUDE_DIRS})
endif()

# Link libraries
target_link_libraries(note-daemon PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
    dl
    stdc++fs
)

if(WITH_LIBUSB)
    target_link_libraries(note-daemon PRIVATE ${LIBUSB_LIBRARIES})
endif()

# Export all symbols so dynamically loaded modules can access them
# This is needed for modules to call functions from the main executable
target_link_options(note-daemon PRIVATE -rdynamic)

if(WITH_LIBUSB)
    target_compile_definitions(note-daemon PRIVATE WITH_LIBUSB)
endif()

# Compiler options
target_compile_options(note-daemon PRIVATE
    -Wall -Wextra -Werror -pedantic
    -O2 -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Install rules
install(TARGETS note-daemon
    RUNTIME DESTINATION /etc/netnotes
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

install(FILES note-daemon.service DESTINATION /etc/systemd/system)
install(FILES 99-netnotes.rules DESTINATION /etc/udev/rules.d)

# Build info
message(STATUS "note-daemon Version: ${PROJECT_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "LibUSB: ${WITH_LIBUSB}")
if(WITH_LIBUSB)
    message(STATUS "LibUSB Version: ${LIBUSB_VERSION}")
endif()
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")

# Add tests subdirectory
if(WITH_LIBUSB)
add_subdirectory(tests)
endif()

# Add process-monitor subdirectory
if(WITH_LIBUSB)
add_subdirectory(process-monitor)
endif()

# Create module directory for installed modules
install(DIRECTORY DESTINATION /etc/netnotes/modules)
