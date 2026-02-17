#include "device_session.h"

// Lazy-init registry accessors: function-local statics ensure safe, ordered init
std::mutex& DeviceSession::sessions_mutex() {
    static std::mutex m;
    return m;
}

std::vector<DeviceSession*>& DeviceSession::active_sessions() {
    static std::vector<DeviceSession*> v;
    return v;
}