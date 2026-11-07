#include "module.hpp"

#include <android/dlext.h>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <lsplt.hpp>
#include <algorithm>
#include <string_view>

#include "daemon.hpp"
#include "dl.hpp"
#include "files.hpp"
#include "logging.hpp"
#include "module_loader.hpp"
#include "solist.hpp"
#include "misc.hpp"
#include "zygisk.hpp"
#include "zn_api.hpp"

// Structure for the getdents64 syscall
struct linux_dirent64 {
    uint64_t         d_ino;
    int64_t          d_off;
    unsigned short   d_reclen;
    unsigned char    d_type;
    char             d_name[];
};

// Extremely fast inline string-to-int parser (avoids atoi overhead)
static inline int fast_atoi(const char* str) {
    int val = 0;
    while (*str >= '0' && *str <= '9') {
        val = val * 10 + (*str++ - '0');
    }
    return val;
}

using namespace std;

ZygiskModule::ZygiskModule(int id, void *handle, void *entry)
    : id(id), handle(handle), entry{entry}, api{}, mod{nullptr} {
    // Make sure all pointers are null
    memset(&api, 0, sizeof(api));
    api.base.impl = this;
    api.base.registerModule = &ZygiskModule::RegisterModuleImpl;
}

bool ZygiskModule::RegisterModuleImpl(ApiTable *api, long *module) {
    if (api == nullptr || module == nullptr) return false;

    long api_version = *module;
    // Unsupported version
    if (api_version > ZYGISK_API_VERSION) return false;

    // Set the actual module_abi*
    api->base.impl->mod = {module};

    // Fill in API accordingly with module API version
    if (api_version >= 1) {
        api->v1.hookJniNativeMethods = hookJniNativeMethods;
        api->v1.pltHookRegister = [](auto a, auto b, auto c, auto d) {
            if (g_ctx) g_ctx->plt_hook_register(a, b, c, d);
        };
        api->v1.pltHookExclude = [](auto a, auto b) {
            if (g_ctx) g_ctx->plt_hook_exclude(a, b);
        };
        api->v1.pltHookCommit = []() { return g_ctx && g_ctx->plt_hook_commit(); };
        api->v1.connectCompanion = [](ZygiskModule *m) { return m->connectCompanion(); };
        api->v1.setOption = [](ZygiskModule *m, auto opt) { m->setOption(opt); };
    }
    if (api_version >= 2) {
        api->v2.getModuleDir = [](ZygiskModule *m) { return m->getModuleDir(); };
        api->v2.getFlags = [](auto) { return ZygiskModule::getFlags(); };
    }
    if (api_version >= 4) {
        api->v4.pltHookCommit = []() { return lsplt::CommitHook(g_hook->cached_map_infos); };
        api->v4.pltHookRegister = [](dev_t dev, ino_t inode, const char *symbol, void *fn,
                                     void **backup) {
            if (dev == 0 || inode == 0 || symbol == nullptr || fn == nullptr) return;
            lsplt::RegisterHook(dev, inode, symbol, fn, backup);
        };
        api->v4.exemptFd = [](int fd) { return g_ctx && g_ctx->exempt_fd(fd); };
    }

    return true;
}

bool ZygiskModule::valid() const {
    if (mod.api_version == nullptr) return false;
    switch (*mod.api_version) {
    case 5:
    case 4:
    case 3:
    case 2:
    case 1:
        return mod.v1->impl && mod.v1->preAppSpecialize && mod.v1->postAppSpecialize &&
               mod.v1->preServerSpecialize && mod.v1->postServerSpecialize;
    default:
        return false;
    }
}

/* Zygisksu changed: Use own zygiskd */
int ZygiskModule::connectCompanion() const { return zygiskd::ConnectCompanion(id); }

/* Zygisksu changed: Use own zygiskd */
int ZygiskModule::getModuleDir() const { return zygiskd::GetModuleDir(id); }

void ZygiskModule::setOption(zygisk::Option opt) {
    if (g_ctx == nullptr) return;
    switch (opt) {
    case zygisk::FORCE_DENYLIST_UNMOUNT:
        g_ctx->flags |= DO_REVERT_UNMOUNT;
        break;
    case zygisk::DLCLOSE_MODULE_LIBRARY:
        unload = true;
        break;
    }
}

uint32_t ZygiskModule::getFlags() { return g_ctx ? (g_ctx->info_flags & ~PRIVATE_MASK) : 0; }

bool ZygiskModule::tryUnload() const { return unload && modloader::Dlclose(handle); }

bool ZygiskModule::loadedBySystem() const { return !modloader::IsCustom(handle); }

// -----------------------------------------------------------------

#define call_app(method)                                                                           \
    switch (*mod.api_version) {                                                                    \
    case 1:                                                                                        \
    case 2: {                                                                                      \
        AppSpecializeArgs_v1 a(args);                                                              \
        mod.v1->method(mod.v1->impl, &a);                                                          \
        break;                                                                                     \
    }                                                                                              \
    case 3:                                                                                        \
    case 4:                                                                                        \
    case 5:                                                                                        \
        mod.v1->method(mod.v1->impl, args);                                                        \
        break;                                                                                     \
    }

void ZygiskModule::preAppSpecialize(AppSpecializeArgs_v5 *args) const { call_app(preAppSpecialize) }

void ZygiskModule::postAppSpecialize(const AppSpecializeArgs_v5 *args) const {
    call_app(postAppSpecialize)
}

void ZygiskModule::preServerSpecialize(ServerSpecializeArgs_v1 *args) const {
    mod.v1->preServerSpecialize(mod.v1->impl, args);
}

void ZygiskModule::postServerSpecialize(const ServerSpecializeArgs_v1 *args) const {
    mod.v1->postServerSpecialize(mod.v1->impl, args);
}

// -----------------------------------------------------------------

void ZygiskContext::plt_hook_register(const char *regex, const char *symbol, void *fn,
                                      void **backup) {
    if (regex == nullptr || symbol == nullptr || fn == nullptr) return;
    regex_t re;
    if (regcomp(&re, regex, REG_NOSUB) != 0) return;
    mutex_guard lock(hook_info_lock);
    register_info.emplace_back(RegisterInfo{re, symbol, fn, backup});
}

void ZygiskContext::plt_hook_exclude(const char *regex, const char *symbol) {
    if (!regex) return;
    regex_t re;
    if (regcomp(&re, regex, REG_NOSUB) != 0) return;
    mutex_guard lock(hook_info_lock);
    ignore_info.emplace_back(IgnoreInfo{re, symbol ?: ""});
}

void ZygiskContext::plt_hook_process_regex() {
    if (register_info.empty()) return;
    for (auto &map : g_hook->cached_map_infos) {
        if (map.offset != 0 || !map.is_private || !(map.perms & PROT_READ)) continue;
        for (auto &reg : register_info) {
            if (regexec(&reg.regex, map.path.data(), 0, nullptr, 0) != 0) continue;
            bool ignored = false;
            for (auto &ign : ignore_info) {
                if (!ign.symbol.empty() && ign.symbol != reg.symbol) continue;
                if (regexec(&ign.regex, map.path.data(), 0, nullptr, 0) == 0) {
                    ignored = true;
                    break;
                }
            }
            if (!ignored) {
                lsplt::RegisterHook(map.dev, map.inode, reg.symbol, reg.callback, reg.backup);
            }
        }
    }
}

bool ZygiskContext::plt_hook_commit() {
    {
        mutex_guard lock(hook_info_lock);
        plt_hook_process_regex();
        register_info.clear();
        ignore_info.clear();
    }
    return lsplt::CommitHook(g_hook->cached_map_infos);
}

// -----------------------------------------------------------------

// Targets that a process forked from zygote is allowed to carry, in the order of
// the kPathAllowlist that AOSP's own descriptor check walks in
// frameworks/base/core/jni/fd_utils.cpp, so keeping the two in sync stays a
// plain diff. Its /dev/socket entries are left out: a socket reads back from
// /proc/self/fd as socket:[inode] rather than as a path, so no readlink can
// match one, and the framework replaces the sockets it allows with /dev/null in
// place rather than carrying them into the child.
//
// FileDescriptorAllowlist::IsAllowed() accepts more than this list through
// prefix and suffix rules: framework and APEX jars, resource overlays, their
// idmaps and ART's boot image memfd. Zygote opens those before our snapshot, so
// they never reach this check, and the list mirrors the static allowlist alone
// rather than growing a second copy of those rules.
static constexpr const char *kAllowedFdTargets[] = {
    "/dev/null",
    "/sys/kernel/debug/tracing/trace_marker",
    "/sys/kernel/tracing/trace_marker",
    "/system/framework/framework-res.apk",
    "/dev/urandom",
    "/dev/ion",
    "/dev/dri/renderD129",
    "/dev/stune/foreground/tasks",
    "/dev/blkio/tasks",
    "/metadata/aconfig/maps/system.package.map",
    "/metadata/aconfig/maps/system.flag.map",
    "/metadata/aconfig/boot/system.val",
};

static constexpr size_t kFdTargetMax = 256;

static bool is_allowed_fd_target(const char *target) {
    for (const char *allowed : kAllowedFdTargets) {
        if (strcmp(target, allowed) == 0) return true;
    }
    return false;
}

void ZygiskContext::sanitize_fds() {
    if (!is_child()) {
        return;
    }

    if (can_exempt_fd() && !exempted_fds.empty()) {
        auto update_fd_array = [&](int old_len) -> jintArray {
            jintArray array = env->NewIntArray(static_cast<int>(old_len + exempted_fds.size()));
            if (array == nullptr) return nullptr;

            env->SetIntArrayRegion(array, old_len, static_cast<int>(exempted_fds.size()),
                                   exempted_fds.data());
            for (int fd : exempted_fds) {
                if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size()) {
                    allowed_fds[fd] = true;
                }
            }
            *args.app->fds_to_ignore = array;
            return array;
        };

        if (jintArray fdsToIgnore = *args.app->fds_to_ignore) {
            int *arr = env->GetIntArrayElements(fdsToIgnore, nullptr);
            int len = env->GetArrayLength(fdsToIgnore);
            for (int i = 0; i < len; ++i) {
                int fd = arr[i];
                if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size()) {
                    allowed_fds[fd] = true;
                }
            }
            if (jintArray newFdList = update_fd_array(len)) {
                env->SetIntArrayRegion(newFdList, 0, len, arr);
            }
            env->ReleaseIntArrayElements(fdsToIgnore, arr, JNI_ABORT);
        } else {
            update_fd_array(0);
        }
    }

    // Close all forbidden fds using direct syscall
    int fd_dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    if (fd_dir >= 0) {
        char buf[4096];
        int nread;
        [[maybe_unused]] int closed = 0, kept = 0;
        while ((nread = syscall(__NR_getdents64, fd_dir, buf, sizeof(buf))) > 0) {
            for (int bpos = 0; bpos < nread;) {
                auto d = reinterpret_cast<struct linux_dirent64*>(buf + bpos);
                if (d->d_name[0] >= '0' && d->d_name[0] <= '9') {
                    int fd = fast_atoi(d->d_name);
                    if (fd >= 0 && fd != fd_dir && (static_cast<size_t>(fd) >= allowed_fds.size() || !allowed_fds[fd])) {
                        char target[kFdTargetMax] = "<unreadable>";
                        if (ssize_t len = readlinkat(fd_dir, d->d_name, target, sizeof(target) - 1); len >= 0) {
                            target[len] = '\0';
                        }
                        if (is_allowed_fd_target(target)) {
                            LOGD("keeping fd %d, opened after snapshot: %s", fd, target);
                            ++kept;
                        } else {
                            LOGD("closing fd %d: %s", fd, target);
                            close(fd);
                            ++closed;
                        }
                    }
                }
                bpos += d->d_reclen;
            }
        }
        close(fd_dir);
        LOGD("sanitized fds of [%s]: %d closed, %d kept", process ? process : "system_server", closed, kept);
    }
}

bool ZygiskContext::exempt_fd(int fd) {
    if ((flags & POST_SPECIALIZE) || (flags & SKIP_CLOSE_LOG_PIPE)) return true;
    if (!can_exempt_fd()) return false;
    exempted_fds.push_back(fd);
    LOGV("exempt fd %d", fd);
    return true;
}

bool ZygiskContext::can_exempt_fd() const {
    return (flags & APP_FORK_AND_SPECIALIZE) && args.app->fds_to_ignore;
}

static int sigmask(int how, int signum) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signum);
    return sigprocmask(how, &set, nullptr);
}

void ZygiskContext::fork_pre() {
    // Do our own fork before loading any 3rd party code
    // First block SIGCHLD, unblock after original fork is done
    sigmask(SIG_BLOCK, SIGCHLD);
    pid = old_fork();

    if (!is_child()) return;

    // Record all open fds using direct syscall to avoid heap allocations
    int fd_dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    if (fd_dir >= 0) {
        char buf[4096];
        int nread;
        while ((nread = syscall(__NR_getdents64, fd_dir, buf, sizeof(buf))) > 0) {
            for (int bpos = 0; bpos < nread;) {
                auto d = reinterpret_cast<struct linux_dirent64*>(buf + bpos);

                // Only parse if it starts with a number (valid FD)
                if (d->d_name[0] >= '0' && d->d_name[0] <= '9') {
                    int fd = fast_atoi(d->d_name);
                    if (fd >= 0 && static_cast<size_t>(fd) < allowed_fds.size()) {
                        allowed_fds[fd] = true;
                    } else if (fd != fd_dir) {
                        close(fd);
                    }
                }
                bpos += d->d_reclen;
            }
        }
        allowed_fds[fd_dir] = false;
        close(fd_dir);
    }
}

void ZygiskContext::fork_post() {
    // Unblock SIGCHLD in case the original method didn't
    sigmask(SIG_UNBLOCK, SIGCHLD);
}

/* Zygisksu changed: Load module fds */
void ZygiskContext::run_modules_pre() {
    auto ms = zygiskd::ReadModules();
    auto size = ms.size();
    for (size_t i = 0; i < size; i++) {
        auto &m = ms[i];
        bool via_system = false;
        if (void *handle = modloader::Dlopen(m.memfd, "zygisk-module", &via_system);
            void *entry = handle ? modloader::Dlsym(handle, "zygisk_module_entry") : nullptr) {
            modules.emplace_back(i, handle, entry);
        }
    }

    for (auto &m : modules) {
        m.onLoad(env);
        if (flags & APP_SPECIALIZE) {
            m.preAppSpecialize(args.app);
        } else if (flags & SERVER_FORK_AND_SPECIALIZE) {
            m.preServerSpecialize(args.server);
        }
    }
}

void ZygiskContext::run_modules_post() {
    flags |= POST_SPECIALIZE;

    size_t modules_unloaded = 0;
    for (const auto &m : modules) {
        if (flags & APP_SPECIALIZE) {
            m.postAppSpecialize(args.app);
        } else if (flags & SERVER_FORK_AND_SPECIALIZE) {
            m.postServerSpecialize(args.server);
        }
    }

    // Only modules that fell back to the system linker ended up in solist and
    // bumped g_module_load_counter; custom-linker modules leave no such trace,
    // so the scrub accounting must count only the system-loaded ones.
    size_t system_loaded = 0;
    size_t system_unloaded = 0;
    for (const auto &m : modules) {
        if (m.loadedBySystem()) system_loaded++;
    }

    // Reverse: the allocator is LIFO, so releasing back to front hands the blocks back
    // in ascending order and leaves the allocation sequence monotonic.
    for (auto it = modules.rbegin(); it != modules.rend(); ++it) {
        bool by_system = it->loadedBySystem();
        if (it->tryUnload()) {
            modules_unloaded++;
            if (by_system) system_unloaded++;
        }
    }

    if (modules.size() > 0 && g_hook != nullptr) {
        LOGV("modules unloaded: %zu/%zu (system-loaded: %zu)", modules_unloaded, modules.size(),
             system_loaded);
        if (modules.size() == modules_unloaded) clean_libc_trace();
        // "zygisk-module" is the memfd name (zygiskd.rs:264); b4d31ab fixed the same
        // stale needle in spoof_virtual_maps but missed this call site. Custom-linker
        // modules are not in solist, so only scrub when something went through fallback.
        if (system_loaded > 0) {
            clean_linker_trace("zygisk-module", system_loaded, system_unloaded, true);
        }
        g_hook->should_spoof_maps =
            (flags & APP_SPECIALIZE) && (modules.size() - modules_unloaded) > 0;
    }
}

void ZygiskContext::app_specialize_pre() {
    uid_t uid = args.app->uid;
    bool is_isolated_aid = uid >= AID_ISOLATED_START && uid <= AID_ISOLATED_END;
    if (is_isolated_aid && args.app->app_data_dir) {
        const char *data_dir = nullptr;
        data_dir = env->GetStringUTFChars(args.app->app_data_dir, nullptr);
        if (data_dir != nullptr) {
            struct stat st;
            if (stat(data_dir, &st) != -1) {
                // Correct uid for isolated services
                uid = st.st_uid;
            }
            LOGV("Found isolated process [uid:%d, data_dir:%s]", uid, data_dir);
            env->ReleaseStringUTFChars(args.app->app_data_dir, data_dir);
        }
    }

    bool skip_zygiskd = false;
    if (is_isolated_aid) {
        UniqueFd fd = zygiskd::Connect(1);
        if (fd == -1) {
            skip_zygiskd = true;
        }
    }

    if (!skip_zygiskd && info_flags == 0) info_flags = zygiskd::GetProcessFlags(uid);

    if ((info_flags & UNMOUNT_MASK) == UNMOUNT_MASK) {
        LOGV("[%s] is on the denylist", process);
        flags |= DO_REVERT_UNMOUNT;
    }

    // Treat the WebView app-zygote as if it were on the denylist so that the isolated
    // processes it forks share the same clean mount namespace as every other isolated
    // process. The app-zygote's sandboxed children inherit its namespace directly, so
    // routing it down the revert-unmount path is what keeps the mount view uniform
    // across all isolated processes.
    if (process != nullptr && strcmp(process, "webview_zygote") == 0) {
        flags |= DO_REVERT_UNMOUNT;
    }

    // User apps picked in the WebUI never load any module. The daemon only ever sets this
    // flag for regular app uids, so system_server and system apps are not affected.
    bool excluded = (info_flags & PROCESS_EXCLUDED) == PROCESS_EXCLUDED;
    if (excluded) {
        LOGV("[%s] is on the exclusion list, skip loading modules", process);
    }

    flags |= APP_SPECIALIZE;
    if (!skip_zygiskd && !excluded) run_modules_pre();
}

void ZygiskContext::app_specialize_post() {
    run_modules_post();

    if ((info_flags & PROCESS_IS_MANAGER) == PROCESS_IS_MANAGER) {
        LOGI("current uid %d is manager!", args.app->uid);
        setenv("ZYGISK_ENABLED", "1", 1);
    }

    // Cleanups
    env->ReleaseStringUTFChars(args.app->nice_name, process);
}

void ZygiskContext::server_specialize_pre() {
    run_modules_pre();
    zygiskd::SystemServerStarted();
}

void ZygiskContext::server_specialize_post() { run_modules_post(); }

// -----------------------------------------------------------------

void ZygiskContext::nativeSpecializeAppProcess_pre() {
    process = env->GetStringUTFChars(args.app->nice_name, nullptr);
    LOGV("pre specialize [%s]", process);
    g_hook->anonymous_memory_enabled = is_anonymous_memory_enabled();
    zn::initHookEngine();
    // App specialize does not check FD
    flags |= SKIP_CLOSE_LOG_PIPE;
    app_specialize_pre();
}

void ZygiskContext::nativeSpecializeAppProcess_post() {
    LOGV("post specialize [%s]", process);
    zygiskd::UnmapSharedMemory();
    app_specialize_post();
}

void ZygiskContext::nativeForkSystemServer_pre() {
    LOGV("pre forkSystemServer");
    flags |= SERVER_FORK_AND_SPECIALIZE;

    for (auto &map : g_hook->cached_map_infos) {
        if (map.dev == 0 && map.inode == 0 && map.offset == 0 && map.is_private &&
            map.path == "[anon:stack_and_tls:main]") {
            if ((map.perms & PROT_READ) == 0) {
                LOGV("Skipping non-readable stack map at %p", reinterpret_cast<void *>(map.start));
                continue;
            }
            auto search_from = reinterpret_cast<char *>(map.start);
            auto search_to = reinterpret_cast<char *>(map.end);
            spoof_zygote_fossil(search_from, search_to, "ref_profiles");
            break;
        }
    }

    fork_pre();
    if (is_child()) {
        server_specialize_pre();
        zygiskd::CacheMountNamespace(getpid());
    }
    sanitize_fds();
}

void ZygiskContext::nativeForkSystemServer_post() {
    if (is_child()) {
        LOGV("post forkSystemServer");
        zygiskd::UnmapSharedMemory();
        server_specialize_post();
    }
    fork_post();
}

bool abort_zygote_unmount(const std::vector<mount_info> &traces, uint32_t info_flags) {
    if (traces.empty()) {
        LOGV("abort unmounting zygote with an empty trace list");
        return true;
    }

    // Font overlay modules may mount files that the framework needs during early boot.
    // Detaching them from zygote can cause crashes; fall back to per-process setns instead.
    bool has_font_overlay = std::any_of(traces.begin(), traces.end(), [](const mount_info &trace) {
        return trace.target.find("/font") != std::string::npos;
    });
    if (has_font_overlay) {
        LOGV("abort unmounting zygote: font overlay detected");
        return true;
    }

    // Protect /product overlays from direct zygote unmount.
    // Only /product/bin is safe to unmount (system binaries, not resource overlays).
    bool is_magisk = info_flags & PROCESS_ROOT_IS_MAGISK;
    bool has_product_overlay = std::any_of(traces.begin(), traces.end(), [&](const mount_info &trace) {
        if (trace.target.rfind("/product", 0) != 0) return false;
        if (trace.target.rfind("/product/bin", 0) == 0) return false;
        if (!is_magisk && trace.target != "/product") return false;
        return true;
    });
    if (has_product_overlay) {
        LOGV("abort unmounting zygote: /product overlay detected");
        return true;
    }

    return false;
}

void ZygiskContext::nativeForkAndSpecialize_pre() {
    process = env->GetStringUTFChars(args.app->nice_name, nullptr);
    LOGV("pre forkAndSpecialize [%s]", process);
    g_hook->anonymous_memory_enabled = is_anonymous_memory_enabled();
    flags |= APP_FORK_AND_SPECIALIZE;

    if (g_hook->zygote_unmounted_times < 5 && g_hook->zygote_traces.size() == 0) {
        info_flags = zygiskd::GetProcessFlags(args.app->uid);

        g_hook->zygote_traces = check_zygote_traces(info_flags, g_hook->zygote_unmounted_times);

        if (!abort_zygote_unmount(g_hook->zygote_traces, info_flags)) {
            auto removal_predicate = [](const mount_info &trace) {
                LOGV("unmounting %s (mnt_id: %u)", trace.target.c_str(), trace.id);
                if (umount2(trace.target.c_str(), MNT_DETACH) == 0) {
                    return true;  // Success: Mark for removal.
                } else {
                    LOGE("failed to unmount %s: %s", trace.target.c_str(), strerror(errno));
                    return false;  // Failure: Keep this trace in the vector.
                }
            };

            auto new_end = std::remove_if(g_hook->zygote_traces.begin(),
                                          g_hook->zygote_traces.end(), removal_predicate);

            g_hook->zygote_traces.erase(new_end, g_hook->zygote_traces.end());
            g_hook->zygote_unmounted_times += 1;
        }
    }

    fork_pre();
    if (is_child()) {
        app_specialize_pre();
    }

    sanitize_fds();
}

void ZygiskContext::nativeForkAndSpecialize_post() {
    if (is_child()) {
        LOGV("post forkAndSpecialize [%s]", process);
        zygiskd::UnmapSharedMemory();
        app_specialize_post();
    }
    fork_post();
}

// -----------------------------------------------------------------

bool ZygiskContext::update_mount_namespace(zygiskd::MountNamespace namespace_type) {
    const char *type_str = (namespace_type == zygiskd::MountNamespace::Clean ? "Clean" : "Root");
    LOGV("updating mount namespace to type %s", type_str);

    int ns_fd = zygiskd::UpdateMountNamespace(namespace_type);

    // Check for failure (Not cached or error)
    if (ns_fd < 0) {
        LOGW("mount namespace [%s] not available/cached", type_str);
        return false;
    }

    // Apply the namespace
    // setns works directly with the FD received from the socket.
    int ret = setns(ns_fd, CLONE_NEWNS);
    if (ret != 0) {
        PLOGE("setns failed for type %s", type_str);
        close(ns_fd);
        return false;
    }

    close(ns_fd);
    return true;
}

