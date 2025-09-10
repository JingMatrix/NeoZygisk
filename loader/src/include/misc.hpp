#pragma once

#include <pthread.h>

#include <string_view>

// Constants for Android Isolated UID range.
// Reference:
// https://cs.android.com/android/platform/superproject/main/+/main:system/core/libcutils/include/private/android_filesystem_config.h
#define AID_ISOLATED_START 90000 /* start of uids for fully isolated sandboxed processes */
#define AID_ISOLATED_END 99999   /* end of uids for fully isolated sandboxed processes */

/**
 * @brief A basic RAII (Resource Acquisition Is Initialization) wrapper for a pthread_mutex_t.
 *
 * This class ensures that a pthread mutex is properly unlocked when the
 * guard goes out of scope.
 *
 * NOTE: For new C++ code, prefer using the standard library's std::mutex
 * and std::lock_guard (or std::unique_lock) from the <mutex> header. They
 * are more portable and integrate better with standard C++ features.
 */
class mutex_guard {
public:
    explicit mutex_guard(pthread_mutex_t& m) : mutex(&m) { pthread_mutex_lock(mutex); }

    ~mutex_guard() {
        if (mutex) {
            pthread_mutex_unlock(mutex);
        }
    }

    // This class manages a resource and should not be copied or moved.
    mutex_guard(const mutex_guard&) = delete;
    mutex_guard& operator=(const mutex_guard&) = delete;
    mutex_guard(mutex_guard&&) = delete;
    mutex_guard& operator=(mutex_guard&&) = delete;

    /**
     * @brief Manually unlocks the mutex before the guard is destroyed.
     * This prevents the mutex from being unlocked again in the destructor.
     */
    void unlock() {
        if (mutex) {
            pthread_mutex_unlock(mutex);
            mutex = nullptr;
        }
    }

private:
    pthread_mutex_t* mutex;
};

int parse_int(std::string_view s);
