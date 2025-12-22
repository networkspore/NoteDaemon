#ifndef DEVICE_STREAMING_THREAD_H
#define DEVICE_STREAMING_THREAD_H

#include <thread>
#include <atomic>
#include <memory>

class DeviceStreamingThread {
public:
    DeviceStreamingThread() = default;
    virtual ~DeviceStreamingThread() = default;

    // Start the streaming thread
    virtual void start() = 0;

    // Stop the streaming thread
    virtual void stop() = 0;

    // Check if the thread is running
    virtual bool is_running() const = 0;
};

#endif // DEVICE_STREAMING_THREAD_H