#ifndef ATOMICSEQUENCE64_H
#define ATOMICSEQUENCE64_H

#include <atomic>
#include <chrono>
#include <cstdint>

class AtomicSequence64 {
private:
    static inline std::atomic<uint32_t> sequence_{0};
    static inline std::atomic<uint32_t> last_timestamp_block_{0};

    static inline std::atomic<int64_t> cached_day_millis_{-1};
    static inline std::atomic<int32_t> cached_day_of_year_{-1};
    static inline std::atomic<int32_t> cached_full_year_{-1};

    static bool is_leap_year(int year) {
        return (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0);
    }

    static void compute_day_year(int64_t current_day_millis,
                                 int& outDayOfYear,
                                 int& outYear)
    {
        int64_t cachedMillis = cached_day_millis_.load(std::memory_order_relaxed);
        int cachedDay = cached_day_of_year_.load(std::memory_order_relaxed);
        int cachedYear = cached_full_year_.load(std::memory_order_relaxed);

        if (current_day_millis == cachedMillis && cachedDay >= 0 && cachedYear > 0) {
            outDayOfYear = cachedDay;
            outYear = cachedYear;
            return;
        }

        // recompute
        int64_t days = current_day_millis;
        int year = 1970;
        while (true) {
            int daysInYear = is_leap_year(year) ? 366 : 365;
            if (days < daysInYear) break;
            days -= daysInYear;
            year++;
        }

        int dayOfYear = ((int)days + 1) & 0x1FF;

        cached_day_millis_.store(current_day_millis, std::memory_order_relaxed);
        cached_day_of_year_.store(dayOfYear, std::memory_order_relaxed);
        cached_full_year_.store(year, std::memory_order_relaxed);

        outDayOfYear = dayOfYear;
        outYear = year;
    }

public:
    /**
     * Generate next 64-bit sequence. Writes 8 bytes to buffer (big-endian).
     */
    static int64_t get_next()
    {
        using namespace std::chrono;

        auto now = system_clock::now();
        int64_t millis = duration_cast<milliseconds>(now.time_since_epoch()).count();

        // Day/year caching
        int64_t dayMillis = millis / 86400000LL;
        int dayOfYear = 0;
        int fullYear = 0;
        compute_day_year(dayMillis, dayOfYear, fullYear);

        // Extract hour/minute/second
        int64_t totalSeconds = millis / 1000;
        int secondOfDay = (int)(totalSeconds % 86400); // 0–86399

        // compress time = secondsSinceMidnight >> 4 (16s resolution)
        int compressedTime = (secondOfDay >> 4) & 0x1FFF; // 13 bits

        // Build timestamp block (upper 32 bits)
        // year (10 bits) << 22
        // day  (9 bits)  << 13
        // time (13 bits) << 0
        uint32_t timestampBlock =
            ((fullYear & 0x3FF)  << 22) |
            ((dayOfYear & 0x1FF) << 13) |
            (compressedTime & 0x1FFF);

        // Reset sequence if timestampBlock changed
        uint32_t last = last_timestamp_block_.load(std::memory_order_acquire);
        if (timestampBlock != last) {
            if (last_timestamp_block_.compare_exchange_strong(last, timestampBlock)) {
                sequence_.store(0, std::memory_order_release);
            }
        }

        uint32_t seq = sequence_.fetch_add(1, std::memory_order_acq_rel);

        // Construct full 64-bit value
        
        return (int64_t) (((uint64_t)timestampBlock << 32) |
            (uint64_t)(seq & 0xFFFFFFFFULL));

        
    }
};

#endif // ATOMICSEQUENCE64_H
