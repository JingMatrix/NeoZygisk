#include "dl.hpp"

#include <android/dlext.h>

#include "logging.hpp"

/**
 * @brief Opens a shared library from a memory-backed file descriptor.
 *
 * This is useful for loading libraries directly from memory (e.g., a memfd)
 * without writing them to disk first.
 *
 * @param fd A file descriptor pointing to the start of the shared library data.
 * @param flags The flags to be passed to dlopen (e.g., RTLD_LAZY).
 * @return A handle to the opened library on success, or nullptr on failure.
 */
void* DlopenMem(int fd, int flags) {
    constexpr const char* JIT_CACHE_NAME = "/jit-cache-zygisk";

    android_dlextinfo info{.flags = ANDROID_DLEXT_USE_LIBRARY_FD,
                           .reserved_addr = nullptr,
                           .reserved_size = 0,
                           .relro_fd = 0,
                           .library_fd = fd,
                           .library_fd_offset = 0,
                           .library_namespace = nullptr};

    void* handle = android_dlopen_ext(JIT_CACHE_NAME, flags, &info);
    if (handle) {
        LOGV("dlopen_ext from fd %d succeeded: handle %p", fd, handle);
    } else {
        LOGE("dlopen_ext from fd %d failed: %s", fd, dlerror());
    }
    return handle;
}
