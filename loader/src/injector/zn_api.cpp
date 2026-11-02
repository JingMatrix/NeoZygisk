#include "zn_api.hpp"
#include "daemon.hpp"

#include "elf_util.h"
#include "logging.hpp"
#include "zn_hook.hpp"

#if defined(__riscv)
#include <dobby_compat.h>
#else
#include <dobby.h>
#endif
#include <lsplt.hpp>

#include <android/dlext.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>
#include <mutex>
#include <set>
#include <string_view>
#include <vector>

using namespace znn;

// Opaque symbol resolver in global scope matching zygisk_next_api.h
struct ZnSymbolResolver {
    znn::ElfImage* image = nullptr;
};

namespace zn {

namespace {

int api_pltHook(void* base, const char* symbol, void* hook, void** original) {
    if (!base || !symbol || !hook) return ZN_FAILED;
    return zn::hook::pltHook(base, symbol, hook, original) ? ZN_SUCCESS : ZN_FAILED;
}

int api_inlineHook(void* target, void* addr, void** original) {
    if (!target || !addr) return ZN_FAILED;
    return zn::hook::inlineHook(target, addr, original) ? ZN_SUCCESS : ZN_FAILED;
}

int api_inlineUnhook(void* target) {
    if (!target) return ZN_FAILED;
    return zn::hook::inlineUnhook(target) ? ZN_SUCCESS : ZN_FAILED;
}

ZnSymbolResolver* api_newSymbolResolver(const char* path, void* base) {
    if (!path) return nullptr;

    auto* resolver = new ZnSymbolResolver();
    resolver->image = new ElfImage(path, reinterpret_cast<uintptr_t>(base));
    if (!resolver->image->valid()) {
        LOGW("ZN newSymbolResolver %s: invalid", path);
        delete resolver->image;
        delete resolver;
        return nullptr;
    }
    return resolver;
}

void api_freeSymbolResolver(ZnSymbolResolver* resolver) {
    if (!resolver) return;
    delete resolver->image;
    delete resolver;
}

void* api_getBaseAddress(ZnSymbolResolver* resolver) {
    if (!resolver || !resolver->image) return nullptr;
    return reinterpret_cast<void*>(resolver->image->base());
}

void* api_symbolLookup(ZnSymbolResolver* resolver, const char* name, bool prefix, size_t* size) {
    if (!resolver || !resolver->image || !name) return nullptr;

    const SymbolInfo* s = resolver->image->lookup(name, prefix);
    if (s) {
        if (size) *size = s->size;
        return reinterpret_cast<void*>(s->addr);
    }

    if (!prefix) {
        uintptr_t a = resolver->image->runtimeLookup(name, size);
        if (a) {
            return reinterpret_cast<void*>(a);
        }
    }
    return nullptr;
}

void api_forEachSymbols(ZnSymbolResolver* resolver,
                        bool (*callback)(const char* name, void* addr, size_t size, void* data),
                        void* data) {
    if (!resolver || !resolver->image || !callback) return;
    resolver->image->forEach([&](const char* name, uintptr_t addr, size_t size) {
        return callback(name, reinterpret_cast<void*>(addr), size, data);
    });
}

int api_connectCompanion(void* handle) {
    auto* h = static_cast<ZnModuleHandle*>(handle);
    if (!h || !h->companion || h->target_api_version < 3 || h->lib_path.empty()) {
        return -1;
    }
    return zygiskd::ConnectZnCompanion(h->lib_path);
}

// Helper: Raw inline hook via Dobby
bool inlineHookRaw(void* target, void* addr, void** original) {
    if (!target || !addr) return false;
    return DobbyHook(target, reinterpret_cast<dobby_dummy_func_t>(addr),
                     reinterpret_cast<dobby_dummy_func_t*>(original)) == RT_SUCCESS;
}

// ZN API v4 Runtime: the HyperOS Rust Runtime (HYOS)
constexpr int kMaxHyosModules = 16;
bool g_hyos_runtime = false;
ZygiskNextHyosModule g_hyos_modules[kMaxHyosModules] = {};
int g_hyos_module_count = 0;
bool g_hyos_fired = false;
bool g_hyos_atfork_registered = false;
pid_t g_spawner_pid = 0;

// Raw syscall: bionic's cached getpid() is stale in children created by a raw clone(),
// and the spawner is not guaranteed to go through libc fork().
bool hyosInChild() {
    return g_spawner_pid != 0 && static_cast<pid_t>(syscall(__NR_getpid)) != g_spawner_pid;
}

typedef int (*HyosSetcontextFn)(uid_t uid, int is_system_server, const char* se_info,
                                const char* pkg_name);
typedef int (*HyosSetnameFn)(pthread_t thread, const char* name);
HyosSetcontextFn g_orig_setcontext = nullptr;
HyosSetnameFn g_orig_setname = nullptr;
bool g_hyos_warned = false;

dev_t g_spawner_dev = 0;
ino_t g_spawner_inode = 0;

char g_cap_process_name[256] = {};
bool g_cap_has_process_name = false;

bool readProcCmdline(char* out, size_t max_len) {
    if (!out || max_len == 0) return false;
    int fd;
    do {
        fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return false;

    size_t length = 0;
    bool complete = false;
    while (length + 1 < max_len) {
        char val = '\0';
        ssize_t r;
        do {
            r = read(fd, &val, sizeof(val));
        } while (r < 0 && errno == EINTR);
        if (r != sizeof(val)) break;
        if (val == '\0') {
            complete = (length != 0);
            break;
        }
        out[length++] = val;
    }
    close(fd);
    out[length] = '\0';
    return complete;
}

void hyosDeliverAppSpecialized(const char* pkg_name, const char* se_info) {
    if (!hyosInChild() || g_hyos_fired || g_hyos_module_count == 0) return;
    g_hyos_fired = true;

    char process_name[256] = {};
    char package_name[256] = {};
    char se_info_buf[64] = {};

    if (g_cap_has_process_name && g_cap_process_name[0] != '\0') {
        strlcpy(process_name, g_cap_process_name, sizeof(process_name));
    } else if (!readProcCmdline(process_name, sizeof(process_name)) || process_name[0] == '\0') {
        if (prctl(PR_GET_NAME, process_name, 0, 0, 0) != 0 || process_name[0] == '\0') {
            strlcpy(process_name, "hyos_app", sizeof(process_name));
        }
    }

    strlcpy(package_name, pkg_name ? pkg_name : "", sizeof(package_name));
    strlcpy(se_info_buf, se_info ? se_info : "", sizeof(se_info_buf));

    ZnHyosAppSpecializeArgs args = {process_name, package_name, se_info_buf};
    LOGI("HYOS app specialized: process=%s package=%s se_info=%s", process_name,
         package_name, se_info_buf);

    for (int i = 0; i < g_hyos_module_count; ++i) {
        if (g_hyos_modules[i].onAppSpecialized) {
            g_hyos_modules[i].onAppSpecialized(&args);
        }
    }
}

int hyosSetcontextHook(uid_t uid, int is_system_server, const char* se_info,
                       const char* pkg_name) {
    int ret = g_orig_setcontext ? g_orig_setcontext(uid, is_system_server, se_info, pkg_name)
                                : -1;
    if (ret == 0) {
        hyosDeliverAppSpecialized(pkg_name, se_info);
    } else if (!g_hyos_fired && hyosInChild()) {
        LOGW("HYOS: selinux_android_setcontext failed (%d)", ret);
    }
    return ret;
}

int hyosSetnameHook(pthread_t thread, const char* name) {
    int ret = g_orig_setname ? g_orig_setname(thread, name) : -1;
    if (ret == 0 && !g_cap_has_process_name && !g_hyos_fired && name && name[0] != '\0' &&
        pthread_equal(thread, pthread_self()) && hyosInChild()) {
        strlcpy(g_cap_process_name, name, sizeof(g_cap_process_name));
        g_cap_has_process_name = true;
        LOGI("HYOS: captured process name %s", g_cap_process_name);
    }
    return ret;
}

void hyosInstallHooks();

void hyosAtForkPrepare() {
    if (g_hyos_module_count > 0 && (!g_orig_setcontext || !g_orig_setname)) {
        hyosInstallHooks();
    }
}

void hyosInstallHooks() {
    // 1. Locate hyos_spawner main executable dev & inode for PLT hooking (YukiSU style)
    if (g_spawner_inode == 0) {
        auto maps = parseMaps("self");
        for (const auto& m : maps) {
            if (m.offset == 0 && m.inode != 0 &&
                (m.path == "/system_ext/bin/hyos_spawner" ||
                 m.path.ends_with("/hyos_spawner") ||
                 m.path.find("hyos_spawner") != std::string::npos)) {
                g_spawner_dev = m.dev;
                g_spawner_inode = m.inode;
                LOGI("HYOS: identified spawner main dev=%lu inode=%lu at %p",
                     (unsigned long)m.dev, (unsigned long)m.inode, reinterpret_cast<void*>(m.start));
                break;
            }
        }
    }

    // PLT hooks on the spawner image first: they need no execmem, which the spawner's
    // SELinux domain is unlikely to have.
    auto pltHookSpawner = [](const char* symbol, void* hook, void** orig) {
        if (g_spawner_inode == 0 || *orig) return;
        void* backup = nullptr;
        if (lsplt::RegisterHook(g_spawner_dev, g_spawner_inode, symbol, hook, &backup) &&
            lsplt::CommitHook() && backup) {
            *orig = backup;
            LOGI("HYOS: PLT hooked %s in hyos_spawner", symbol);
        } else {
            LOGW("HYOS: PLT hook of %s failed, falling back to inline hook", symbol);
        }
    };
    pltHookSpawner("selinux_android_setcontext", reinterpret_cast<void*>(hyosSetcontextHook),
                   reinterpret_cast<void**>(&g_orig_setcontext));
    pltHookSpawner("pthread_setname_np", reinterpret_cast<void*>(hyosSetnameHook),
                   reinterpret_cast<void**>(&g_orig_setname));

    // 2. Fallback Inline Hook (ZNN style)
    if (!g_orig_setcontext) {
        void* fn = dlsym(RTLD_DEFAULT, "selinux_android_setcontext");
        if (!fn) {
            void* h = dlopen("libselinux.so", RTLD_NOW);
            if (h) fn = dlsym(h, "selinux_android_setcontext");
        }
        if (fn && inlineHookRaw(fn, reinterpret_cast<void*>(hyosSetcontextHook),
                                reinterpret_cast<void**>(&g_orig_setcontext))) {
            LOGI("HYOS: inline hooked selinux_android_setcontext at %p", fn);
        }
    }
    if (!g_orig_setname) {
        void* fn = dlsym(RTLD_DEFAULT, "pthread_setname_np");
        if (!fn) {
            void* h = dlopen("libc.so", RTLD_NOW);
            if (h) fn = dlsym(h, "pthread_setname_np");
        }
        if (fn && inlineHookRaw(fn, reinterpret_cast<void*>(hyosSetnameHook),
                                reinterpret_cast<void**>(&g_orig_setname))) {
            LOGI("HYOS: inline hooked pthread_setname_np at %p", fn);
        }
    }
    if (!g_orig_setcontext && !g_hyos_warned) {
        g_hyos_warned = true;
        LOGW("HYOS: selinux_android_setcontext not available, onAppSpecialized will not fire");
    }
}

int api_hyos_registerModule(const void* module) {
    if (!module) return ZN_FAILED;
    const auto* m = static_cast<const ZygiskNextHyosModule*>(module);
    if (!m->onAppSpecialized) return ZN_FAILED;
    if (m->target_api_version > ZYGISK_NEXT_HYOS_API_VERSION) {
        LOGE("HYOS: module targets API version %d, only up to %d supported",
             m->target_api_version, ZYGISK_NEXT_HYOS_API_VERSION);
        return ZN_FAILED;
    }
    if (g_hyos_module_count >= kMaxHyosModules) {
        LOGE("HYOS: too many modules registered (max %d)", kMaxHyosModules);
        return ZN_FAILED;
    }
    g_hyos_modules[g_hyos_module_count++] = *m;

    if (!hyosInChild()) {
        if (!g_hyos_atfork_registered) {
            g_hyos_atfork_registered = true;
            pthread_atfork(hyosAtForkPrepare, nullptr, nullptr);
        }
        hyosInstallHooks();
    }
    LOGI("HYOS: module registered (%d)", g_hyos_module_count);
    return ZN_SUCCESS;
}

const ZygiskNextRuntime kHyosRuntime = {
    .type = ZN_RUNTIME_HYOS,
    .api_version = ZYGISK_NEXT_HYOS_API_VERSION,
    .registerModule = api_hyos_registerModule,
};

const ZygiskNextRuntime* api_getRuntime() {
    return g_hyos_runtime ? &kHyosRuntime : nullptr;
}

const ZygiskNextRuntime* api_getRuntimeUnavailable() {
    LOGW("ZN: Runtime API (HyperOS) not enabled");
    return nullptr;
}

// Stubs for API < 2
struct ZnSymbolResolver* api_symbolResolverUnavailable(const char*, void*) {
    LOGE("Symbol Resolver API requires module API version >= 2");
    return nullptr;
}
void api_freeSymbolResolverUnavailable(struct ZnSymbolResolver*) {
    LOGE("Symbol Resolver API requires module API version >= 2");
}
void* api_getBaseAddressUnavailable(struct ZnSymbolResolver*) {
    LOGE("Symbol Resolver API requires module API version >= 2");
    return nullptr;
}
void* api_symbolLookupUnavailable(struct ZnSymbolResolver*, const char*, bool, size_t*) {
    LOGE("Symbol Resolver API requires module API version >= 2");
    return nullptr;
}
void api_forEachSymbolsUnavailable(struct ZnSymbolResolver*, bool (*)(const char*, void*, size_t, void*), void*) {
    LOGE("Symbol Resolver API requires module API version >= 2");
}

const ZygiskNextAPI kApiV4 = {
    api_pltHook,           api_inlineHook,   api_inlineUnhook,
    api_newSymbolResolver, api_freeSymbolResolver, api_getBaseAddress,
    api_symbolLookup,      api_forEachSymbols,
    api_connectCompanion,
    api_getRuntime,
};

const ZygiskNextAPI kApiFull = {
    api_pltHook,           api_inlineHook,   api_inlineUnhook,
    api_newSymbolResolver, api_freeSymbolResolver, api_getBaseAddress,
    api_symbolLookup,      api_forEachSymbols,
    api_connectCompanion,
    api_getRuntimeUnavailable,
};

const ZygiskNextAPI kApiNoSymbolResolver = {
    api_pltHook,                   api_inlineHook,             api_inlineUnhook,
    api_symbolResolverUnavailable, api_freeSymbolResolverUnavailable,
    api_getBaseAddressUnavailable, api_symbolLookupUnavailable,
    api_forEachSymbolsUnavailable,
    api_connectCompanion,
    api_getRuntimeUnavailable,
};

}  // namespace

const ZygiskNextAPI* getApiForVersion(int target_api_version) {
    if (target_api_version >= 4) return &kApiV4;
    if (target_api_version >= 2) return &kApiFull;
    return &kApiNoSymbolResolver;
}

bool isHyosSpawner() {
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return false;
    buf[n] = '\0';
    std::string_view p(buf);
    if (p.ends_with(" (deleted)")) {
        p.remove_suffix(10);
    }
    return p == "/system_ext/bin/hyos_spawner" || p.ends_with("/hyos_spawner");
}

void initHyosRuntime() {
    g_hyos_runtime = true;
    g_spawner_pid = static_cast<pid_t>(syscall(__NR_getpid));
    LOGI("ZN: HyperOS Runtime enabled in pid %d", getpid());
}

bool isHyosRuntime() {
    return g_hyos_runtime;
}

}  // namespace zn
