#include <dlfcn.h>

#include "daemon.hpp"
#include "logging.hpp"
#include "system_server.hpp"
#include "trace.hpp"
#include "zygisk.hpp"

using namespace std;

/// Returns whether this process came out of the call with hooks installed. The tracer hands
/// that on to the monitor, which cannot tell it from the outside: the library stays mapped
/// whatever the daemon answers, and a second injection over it is impossible.
extern "C" [[gnu::visibility("default")]]
int entry(void* addr, size_t size, const char* path, TraceMode mode) {
    LOGI("injector loaded in %s mode, version %s", name_of(mode), ZKSU_VERSION);

    zygiskd::Init(path);

    if (!zygiskd::PingHeartbeat()) {
        LOGE("no daemon answered, so this process is left with no hooks at all");
        return 0;
    }

    switch (mode) {
    case TraceMode::SYSTEM_SERVER:
        // No zygote hooks here: system_server never forks an app, and it is already
        // specialized, so the lifecycle is driven directly instead.
        trigger_system_server_hooks();
        break;
    case TraceMode::STANDALONE:
        hook_entry(addr, size);
        send_seccomp_event_if_needed();
        // A zygote caught at its entry point runs these itself on the way up. One that
        // was already running is past that point, so drive them here.
        trigger_zygote_hooks();
        break;
    default:
        hook_entry(addr, size);
        send_seccomp_event_if_needed();
        break;
    }
    return 1;
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

        LOGV("atexit registration BLOCKED [func, lib, sym, obj, dso]: [%p, %s, %s, %p, %p]", func,
             library_path, symbol_name, arg, dso);

    } else {
        // dladdr() failed. We can still log the raw pointer.
        LOGV("atexit registration BLOCKED for function at %p, no library information", func);
    }

    return 0;
}
