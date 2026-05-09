cmake_minimum_required(VERSION 3.10)
project(process-monitor CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)

# Include directories - json.hpp is in the main project's include directory
include_directories(
    ${LIBUSB_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Source files - process_monitor.cpp plus the device_registry it needs
set(PROCESS_MONITOR_SOURCES
    src/process_monitor.cpp
    ../src/device_registry.cpp
)

# Create executable
add_executable(process-monitor ${PROCESS_MONITOR_SOURCES})

# Link libraries
target_link_libraries(process-monitor
    ${LIBUSB_LIBRARIES}
    pthread
)

# Install
install(TARGETS process-monitor DESTINATION bin)
