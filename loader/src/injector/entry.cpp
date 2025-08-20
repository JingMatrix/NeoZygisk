#include <dlfcn.h>

#include "daemon.hpp"
#include "logging.hpp"
#include "zygisk.hpp"

using namespace std;

extern "C" [[gnu::visibility("default")]]
void entry(void* addr, size_t size, const char* path) {
    LOGI("Zygisk library injected, version %s", ZKSU_VERSION);

    zygiskd::Init(path);

    if (!zygiskd::PingHeartbeat()) {
        LOGE("Zygisk daemon is not running");
        return;
    }

    LOGI("Start hooking");
    hook_entry(addr, size);
    send_seccomp_event_if_needed();
}

/**
 * @brief Intercepts calls to __cxa_atexit to prevent registration of exit handlers.
 *
 * This function serves as a local replacement for the __cxa_atexit provided by libc.
 * By providing our own version, the dynamic linker resolves any calls from within our
 * injector library (and its static dependencies) to this function instead of the real one.
 *
 * @param func The function pointer (destructor) to be registered.
 * @param arg  A pointer to the argument for the function (the 'this' pointer for an object).
 * @param dso  A handle to the shared object that is registering the handler.
 * @return int Always returns 0 to indicate success, tricking the caller into thinking
 *             the handler was registered while we have actually blocked it.
 */
extern "C" int __cxa_atexit(void (*func)(void*), void* arg, void* dso) {
    // Dl_info will be filled with information about the library
    // containing the function pointer 'func'.
    Dl_info info;

    // Use dladdr() to resolve the function pointer to a library and symbol.
    if (dladdr(reinterpret_cast<const void*>(func), &info)) {
        // Successfully resolved the address.
        const char* library_path = info.dli_fname ? info.dli_fname : "<unknown library>";
        const char* symbol_name = info.dli_sname ? info.dli_sname : "<unknown symbol>";

        LOGD("atexit registration BLOCKED [func, lib, sym, obj, dso]: [%p, %s, %s, %p, %p]", func,
             library_path, symbol_name, arg, dso);

    } else {
        // dladdr() failed. We can still log the raw pointer.
        LOGD("atexit registration BLOCKED for function at %p without library information).", func);
    }

    return 0;
}
