// src/utils.h
#ifndef NOTEDAEMON_UTILS_H
#define NOTEDAEMON_UTILS_H

#include <unistd.h>
#include <syslog.h>
#include <cerrno>
#include <cstring>

/**
 * Safe wrapper for write() that logs errors and prevents Wunused-result.
 */
inline bool safe_write(int fd, const void* buf, size_t len) {
    ssize_t n = write(fd, buf, len);
    if (n != (ssize_t)len) {
        syslog(LOG_WARNING, "Write failed (%zd/%zu): %s", n, len, strerror(errno));
        return false;
    }
    return true;
}

/**
 * Safe wrapper for close() that logs on error.
 * Returns true if successfully closed, false on failure.
 */
inline bool safe_close(int fd) {
    if (fd < 0) return false;
    int result = close(fd);
    if (result == -1) {
        syslog(LOG_WARNING, "Close failed (fd=%d): %s", fd, strerror(errno));
        return false;
    }
    return true;
}

#endif // NOTEDAEMON_UTILS_H
