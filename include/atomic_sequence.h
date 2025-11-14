#ifndef ATOMICSEQUENCE_H
#define ATOMICSEQUENCE_H

#include <atomic>
#include <cstdint>
#include <atomic>
#include <chrono>
#include <ctime>

/**
 * 48-bit Atomic Sequence Generator
 * Matches Java AtomicSequence.java
 * 
 * Format (48 bits / 6 bytes):
 * - Bits 47-46: aux flags (2 bits)
 * - Bits 45-37: day of year (9 bits, 1-366)
 * - Bits 36-32: hour of day (5 bits, 0-23)
 * - Bits 31-0:  sequence counter (32 bits)
 */

class AtomicSequence {
private:
    static std::atomic<uint32_t> sequence_;
    static std::atomic<uint32_t> packed_hour_;
    static std::atomic<int64_t> cached_day_millis_;
    static std::atomic<int32_t> cached_day_of_year_;
    
    static bool is_leap_year(int year) {
        return (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0);
    }
    
    static int calculate_day_of_year() {
        auto now = std::chrono::system_clock::now();
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        
        int64_t current_day_millis = millis / 86400000L;
        
        // Check cache
        int32_t cached_day = cached_day_of_year_.load(std::memory_order_relaxed);
        int64_t cached_millis = cached_day_millis_.load(std::memory_order_relaxed);
        
        if (current_day_millis == cached_millis && cached_day >= 0) {
            return cached_day;
        }
        
        // Calculate day of year
        int64_t days = current_day_millis;
        int year = 1970;
        
        while (true) {
            int days_in_year = is_leap_year(year) ? 366 : 365;
            if (days < days_in_year) {
                break;
            }
            days -= days_in_year;
            year++;
        }
        
        int day_of_year = ((int)days + 1) & 0x1FF;
        
        // Update cache
        cached_day_millis_.store(current_day_millis, std::memory_order_relaxed);
        cached_day_of_year_.store(day_of_year, std::memory_order_relaxed);
        
        return day_of_year;
    }
    
public:
    /**
     * Generate next 48-bit sequence with optional aux flags
     */
    static void get_next(uint8_t* buffer, bool aux0 = false, bool aux1 = false) {
        auto now = std::chrono::system_clock::now();
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        
        int day_of_year = calculate_day_of_year();
        int hour_of_day = (int)((millis / 3600000L) % 24) & 0x1F;
        uint32_t packed_hour = (day_of_year << 5) | hour_of_day;
        
        // Check for hour rollover
        uint32_t last_hour = packed_hour_.load(std::memory_order_acquire);
        if (packed_hour != last_hour) {
            if (packed_hour_.compare_exchange_strong(last_hour, packed_hour)) {
                sequence_.store(0, std::memory_order_release);
            }
        }
        
        uint32_t seq = sequence_.fetch_add(1, std::memory_order_acq_rel);
        
        // Pack all components
        uint32_t aux_bits = ((aux0 ? 1 : 0) << 1) | (aux1 ? 1 : 0);
        uint64_t packed = ((uint64_t)aux_bits << 46) |
                         ((uint64_t)day_of_year << 37) |
                         ((uint64_t)hour_of_day << 32) |
                         (seq & 0xFFFFFFFFUL);
        
        // Write to buffer (big-endian)
        buffer[0] = (packed >> 40) & 0xFF;
        buffer[1] = (packed >> 32) & 0xFF;
        buffer[2] = (packed >> 24) & 0xFF;
        buffer[3] = (packed >> 16) & 0xFF;
        buffer[4] = (packed >> 8) & 0xFF;
        buffer[5] = packed & 0xFF;
    }
    
    /**
     * Decode 48-bit sequence from buffer
     */
    static uint64_t decode(const uint8_t* buffer) {
        return ((uint64_t)(buffer[0] & 0xFF) << 40) |
               ((uint64_t)(buffer[1] & 0xFF) << 32) |
               ((uint64_t)(buffer[2] & 0xFF) << 24) |
               ((uint64_t)(buffer[3] & 0xFF) << 16) |
               ((uint64_t)(buffer[4] & 0xFF) << 8) |
               ((uint64_t)(buffer[5] & 0xFF));
    }
    
    static bool read_aux0(uint64_t seq48) { return (seq48 & 0x800000000000ULL) != 0; }
    static bool read_aux1(uint64_t seq48) { return (seq48 & 0x400000000000ULL) != 0; }
    static int read_day_of_year(uint64_t seq48) { return (seq48 >> 37) & 0x1FF; }
    static int read_hour_of_day(uint64_t seq48) { return (seq48 >> 32) & 0x1F; }
    static uint32_t read_sequence(uint64_t seq48) { return seq48 & 0xFFFFFFFFUL; }
};

// Initialize static members
inline std::atomic<uint32_t> AtomicSequence::sequence_{0};
inline std::atomic<uint32_t> AtomicSequence::packed_hour_{0};
inline std::atomic<int64_t> AtomicSequence::cached_day_millis_{-1};
inline std::atomic<int32_t> AtomicSequence::cached_day_of_year_{-1};

#endif // ATOMICSEQUENCE_H