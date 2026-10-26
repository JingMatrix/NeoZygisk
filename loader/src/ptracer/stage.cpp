#include "stage.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

#include "daemon.hpp"
#include "logging.hpp"
#include "main.hpp"
#include "utils.hpp"

namespace {

constexpr uid_t AID_SYSTEM = 1000;
constexpr const char *kFileContext = "u:object_r:system_file:s0";
constexpr const char *kSocketContext = "u:object_r:zygisk_file:s0";
constexpr const char *kEnforcePath = "/sys/fs/selinux/enforce";
constexpr const char *kContextPath = "/sys/fs/selinux/context";

// The stage every line is tagged with: a late load runs three of them in turn.
const char *g_stage = "stage";

// A stage reports to stdout, where whoever triggered it is looking, and to logcat. The
// three differ only in the logcat level; on stdout a warning and an error read the same.
#define SAY(fmt, ...)                                                                              \
    do {                                                                                           \
        printf("- %s: " fmt "\n", g_stage __VA_OPT__(, ) __VA_ARGS__);                             \
        LOGI("%s: " fmt, g_stage __VA_OPT__(, ) __VA_ARGS__);                                      \
    } while (0)

#define WARN(fmt, ...)                                                                             \
    do {                                                                                           \
        printf("! %s: " fmt "\n", g_stage __VA_OPT__(, ) __VA_ARGS__);                             \
        LOGW("%s: " fmt, g_stage __VA_OPT__(, ) __VA_ARGS__);                                      \
    } while (0)

#define ERR(fmt, ...)                                                                              \
    do {                                                                                           \
        printf("! %s: " fmt "\n", g_stage __VA_OPT__(, ) __VA_ARGS__);                             \
        LOGE("%s: " fmt, g_stage __VA_OPT__(, ) __VA_ARGS__);                                      \
    } while (0)

// --- The situation -----------------------------------------------------------------------

enum class RootImpl { KernelSu, APatch, Magisk, None };

const char *name_of(RootImpl impl) {
    switch (impl) {
    case RootImpl::KernelSu:
        return "KernelSU";
    case RootImpl::APatch:
        return "APatch";
    case RootImpl::Magisk:
        return "Magisk";
    default:
        return "no root framework";
    }
}

bool on_path(const char *name) {
    const char *path = getenv("PATH");
    if (path == nullptr) path = "/system/bin:/system/xbin";

    std::string_view rest(path);
    while (true) {
        auto sep = rest.find(':');
        auto dir = rest.substr(0, sep);
        if (!dir.empty()) {
            std::string candidate = std::string(dir) + "/" + name;
            if (access(candidate.c_str(), X_OK) == 0) return true;
        }
        if (sep == std::string_view::npos) return false;
        rest.remove_prefix(sep + 1);
    }
}

/// ksud exports KSU and apd exports APATCH. Magisk exports nothing and puts its binary on
/// PATH only for the stages it runs itself, so a stage reached any other way has to look.
RootImpl root_impl() {
    if (getenv("KSU") != nullptr) return RootImpl::KernelSu;
    if (getenv("APATCH") != nullptr) return RootImpl::APatch;
    if (on_path("magisk") || access("/data/adb/magisk/magisk", X_OK) == 0) {
        return RootImpl::Magisk;
    }
    return RootImpl::None;
}

/// ksud and apd run every enabled module's boot scripts themselves. Magisk runs only those
/// of the modules it mounts, skipping Zygisk-only ones, and no framework runs none at all.
bool manager_runs_stages(RootImpl impl) {
    return impl == RootImpl::KernelSu || impl == RootImpl::APatch;
}

bool ignore_disable() {
    const char *value = getenv("ZYGISK_IGNORE_DISABLE");
    return value != nullptr && value[0] != '\0';
}

bool exists(const std::string &path) { return access(path.c_str(), F_OK) == 0; }

/// A mapping lasts a zygote's whole life, which answers the only question a disarm has: is
/// there one that a restart has to clear.
bool zygote_has_library() {
    for (auto pid : find_zygotes()) {
        if (has_library_mapped(pid, "libzygisk.so")) return true;
    }
    return false;
}

// --- SELinux ------------------------------------------------------------------------------

bool selinux_enforcing() {
    int fd = open(kEnforcePath, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return false;
    char value = '0';
    bool read_ok = read(fd, &value, 1) == 1;
    close(fd);
    return read_ok && value == '1';
}

/// The kernel resolves the context against the loaded policy. Without a trailing newline:
/// it counts as part of the string and invalidates even a good context.
bool selinux_knows(const char *context) {
    int fd = open(kContextPath, O_WRONLY | O_CLOEXEC);
    if (fd == -1) return false;
    bool written = write(fd, context, strlen(context)) >= 0;
    close(fd);
    return written;
}

bool set_permissive() {
    int fd = open(kEnforcePath, O_WRONLY | O_CLOEXEC);
    if (fd == -1) return false;
    bool written = write(fd, "0", 1) == 1;
    close(fd);
    return written;
}

/// Only our sepolicy.rule defines zygisk_file, and no framework loads it. The socket is
/// then unlabeled and zygote's write denied, so the heartbeat fails and the injector loads
/// nothing. Returns whether arming is worth attempting at all.
bool check_selinux(bool permissive) {
    if (!selinux_enforcing()) return true;

    // Writing the node needs `security check_context`, which not every su domain holds, so
    // prove the probe works against a type every policy defines before trusting a no.
    if (!selinux_knows(kFileContext)) return true;
    if (selinux_knows(kSocketContext)) return true;

    WARN("the loaded policy has no zygisk_file type: sepolicy.rule was never applied");
    if (permissive) {
        if (set_permissive()) {
            WARN("SELinux set permissive, which lasts until the next reboot");
            return true;
        }
        ERR("cannot write %s, SELinux stays enforcing", kEnforcePath);
    }

    // Arming would map the library into a zygote whose heartbeat this policy denies, and a
    // zygote carrying it unhooked is skipped by every later rearm until it restarts.
    ERR("zygote cannot reach the daemon under this policy, so nothing was armed");
    if (!permissive) WARN("pass --permissive to have this stage set SELinux permissive instead");
    return false;
}

// --- The work directory -------------------------------------------------------------------

bool set_sys_perm(const std::string &path, mode_t mode) {
    if (chmod(path.c_str(), mode) == -1) {
        PLOGE("chmod %s", path.c_str());
        return false;
    }
    if (lsetxattr(path.c_str(), "security.selinux", kFileContext, strlen(kFileContext) + 1, 0) ==
        -1) {
        PLOGE("label %s", path.c_str());
        return false;
    }
    if (chown(path.c_str(), AID_SYSTEM, AID_SYSTEM) == -1) {
        PLOGE("chown %s", path.c_str());
        return false;
    }
    return true;
}

/// Traversable by uid 1000: a late-injected system_server opens the library and the socket
/// as itself, a DAC check no SELinux setting relaxes. Root still writes here regardless.
bool make_sys_dir(const std::string &path) {
    if (mkdir(path.c_str(), 0555) == -1 && errno != EEXIST) {
        PLOGE("mkdir %s", path.c_str());
        return false;
    }
    return set_sys_perm(path, 0555);
}

bool copy_file(const std::string &src, const std::string &dst) {
    int in = open(src.c_str(), O_RDONLY | O_CLOEXEC);
    if (in == -1) {
        PLOGE("open %s", src.c_str());
        return false;
    }
    int out = open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (out == -1) {
        PLOGE("create %s", dst.c_str());
        close(in);
        return false;
    }

    char buf[1 << 16];
    ssize_t nread;
    bool ok = true;
    while ((nread = read(in, buf, sizeof(buf))) > 0) {
        for (ssize_t off = 0; off < nread;) {
            auto nwrite = write(out, buf + off, nread - off);
            if (nwrite <= 0) {
                PLOGE("write %s", dst.c_str());
                ok = false;
                break;
            }
            off += nwrite;
        }
        if (!ok) break;
    }
    if (nread < 0) {
        PLOGE("read %s", src.c_str());
        ok = false;
    }

    close(in);
    close(out);
    return ok;
}

/// Renaming over the old file publishes the new inode and leaves a running process on the
/// one it mapped; writing in place would fail with ETXTBSY or mutate a mapped file.
bool install_lib(const std::string &src, const std::string &dst) {
    // Only one ABI's library is installed on most devices.
    if (!exists(src)) return true;

    auto slash = dst.rfind('/');
    if (slash == std::string::npos || !make_sys_dir(dst.substr(0, slash))) return false;

    std::string staged = dst + ".new";
    if (!copy_file(src, staged) || !set_sys_perm(staged, 0644)) return false;
    if (rename(staged.c_str(), dst.c_str()) == -1) {
        PLOGE("rename %s", dst.c_str());
        return false;
    }
    return true;
}

bool stage_work_directory() {
    const std::string &work = zygiskd::GetTmpPath();
    if (!make_sys_dir(work)) return false;

    const std::string &module = get_module_dir();
    bool ok = install_lib(module + "/lib64/libzygisk.so", work + "/lib64/libzygisk.so");
    return install_lib(module + "/lib/libzygisk.so", work + "/lib/libzygisk.so") && ok;
}

// --- Actions ------------------------------------------------------------------------------

void detach_stdio() {
    setsid();
    int null = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null == -1) return;
    dup2(null, STDIN_FILENO);
    dup2(null, STDOUT_FILENO);
    dup2(null, STDERR_FILENO);
    if (null > STDERR_FILENO) close(null);
}

int run_wait(const char *path, const char *name) {
    pid_t pid = fork();
    if (pid < 0) {
        PLOGE("fork %s", path);
        return -1;
    }
    if (pid == 0) {
        execl(path, name, nullptr);
        PLOGE("exec %s", path);
        _exit(1);
    }
    int status = 0;
    waitpid(pid, &status, __WALL);
    return status;
}

/// Detached from our session and stdio because the monitor outlives the stage: a manager
/// reading the stage's pipe to EOF would otherwise wait out the whole session. Unconditional,
/// since a redundant monitor finds the control socket owned and steps aside by itself.
bool start_monitor() {
    char exe[PATH_MAX];
    auto len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len == -1) {
        PLOGE("readlink /proc/self/exe");
        return false;
    }
    exe[len] = '\0';

    int child = fork_dont_care();
    if (child == -1) return false;
    if (child == 0) {
        detach_stdio();
#ifdef ZYGISK_DEBUG
        // Inherited by the daemon the monitor forks, which is what reads it.
        setenv("RUST_BACKTRACE", "1", 0);
#endif
        char *name = basename(exe);
        execl(exe, name, "monitor", nullptr);
        PLOGE("exec %s", exe);
        _exit(1);
    }
    return true;
}

/// Only one process may trace init, and the old monitor's attachment outlives its control
/// socket, so wait for init to be untraced rather than for the socket to close.
bool stop_monitor() {
    if (!monitor_is_running()) {
        SAY("no monitor owns the control socket, nothing to stop");
        return true;
    }
    if (!send_control_command(EXIT)) return false;

    constexpr int kAttempts = 50;
    constexpr useconds_t kDelayUs = 200 * 1000;
    for (int attempt = 0; attempt < kAttempts; ++attempt) {
        if (get_tracer_pid(1) <= 0) {
            SAY("the previous monitor is gone");
            return true;
        }
        usleep(kDelayUs);
    }
    WARN("the previous monitor is still tracing init");
    return false;
}

/// Refreshes the daemon's module snapshot and attaches whatever is up and not yet hooked,
/// then waits for the verdict. Idempotent, and a no-op when no zygote is running.
RearmResult arm() { return send_rearm_command(); }

/// Hooks cannot be undone from outside a live zygote -- the restore runs on a forked child's
/// main thread, and a fork landing on a half-restored JNI table crash-loops -- and a mapped
/// library cannot be swapped either. Detached, so a framework going down spares the caller.
void restart_zygote() {
    if (fork_dont_care() == 0) {
        detach_stdio();
        run_wait("/system/bin/stop", "stop");
        execl("/system/bin/start", "start", nullptr);
        PLOGE("exec /system/bin/start");
        _exit(1);
    }
}

/// Runs a stage script for every Zygisk module, not waiting for them when \p async. Under
/// ZYGISK_IGNORE_DISABLE a disable flag reads as a manager that is not running.
void fan_out(const char *script, bool async) {
    char resolved[PATH_MAX];
    std::string parent = get_module_dir() + "/..";
    if (realpath(parent.c_str(), resolved) == nullptr) {
        PLOGE("resolve %s", parent.c_str());
        return;
    }
    std::string modules(resolved);

    auto *dir = opendir(modules.c_str());
    if (dir == nullptr) {
        PLOGE("opendir %s", modules.c_str());
        return;
    }

    bool load_disabled = ignore_disable();
    while (auto *entry = readdir(dir)) {
        if (entry->d_name[0] == '.') continue;

        std::string module = modules + "/" + entry->d_name;
        struct stat st{};
        if (stat((module + "/zygisk").c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        if (!load_disabled && exists(module + "/disable")) continue;

        std::string path = module + "/" + script;
        if (!exists(path)) continue;

        SAY("triggering %s for module %s", script, entry->d_name);
        pid_t child = async ? fork_dont_care() : fork();
        if (child == -1) continue;
        if (child == 0) {
            if (chdir(module.c_str()) == -1) PLOGE("chdir %s", module.c_str());
            execl("/system/bin/sh", "sh", path.c_str(), nullptr);
            PLOGE("exec %s", path.c_str());
            _exit(1);
        }
        if (!async) waitpid(child, nullptr, __WALL);
    }

    closedir(dir);
}

// --- The stages ---------------------------------------------------------------------------

int post_fs_data() {
    fan_out("post-fs-data.sh", false);
    if (!stage_work_directory()) return EXIT_FAILURE;
    return start_monitor() ? EXIT_SUCCESS : EXIT_FAILURE;
}

int post_mount() {
    // A normal boot reaches this long before zygote exists, where the monitor seized on init
    // catches it. Gated only to keep that boot's log quiet; a rearm then attaches nothing.
    if (find_zygotes().empty()) return EXIT_SUCCESS;

    SAY("system already running, arming NeoZygisk");
    switch (arm()) {
    case RearmResult::Armed:
        SAY("zygote injected, with the daemon answering for its hooks");
        return EXIT_SUCCESS;
    case RearmResult::AlreadyArmed:
        SAY("zygote is hooked already, nothing to arm");
        return EXIT_SUCCESS;
    case RearmResult::NoZygote:
        return EXIT_SUCCESS;
    case RearmResult::NeedsRestart:
        // The library is already mapped, so nothing can be injected over it: the zygote
        // carrying it has to go, and everything it forked with it.
        WARN("a zygote carries our library without hooks, which only a restart clears");
        SAY("restarting zygote");
        restart_zygote();
        return EXIT_SUCCESS;
    case RearmResult::Failed:
        ERR("the monitor did not arm NeoZygisk");
        return EXIT_FAILURE;
    }
    return EXIT_FAILURE;
}

int service() {
    fan_out("service.sh", true);
    return EXIT_SUCCESS;
}

/// KernelSU runs this after replacing the module directory, while the old monitor still
/// traces init through binaries that are gone. No boot stage re-runs, so nothing else
/// would start the new one.
int hot_install() {
    // Deliberately not fatal: a monitor that outlasts the wait finds the control socket
    // owned and stands down, which is the only sane answer left.
    stop_monitor();

    SAY("starting the new monitor");
    if (!stage_work_directory() || !start_monitor()) return EXIT_FAILURE;

    // A handshake, not a request to inject: the monitor binds its socket only after seizing
    // init, so an answer proves the restart below cannot be missed. Rearm also starts the
    // daemon.
    if (arm() == RearmResult::Failed) {
        ERR("the new monitor did not answer, NeoZygisk will start on the next boot");
        return EXIT_FAILURE;
    }

    SAY("restarting zygote to load the new injector");
    restart_zygote();
    return EXIT_SUCCESS;
}

int disarm() {
    bool mapped = zygote_has_library();
    stop_monitor();
    if (!mapped) {
        SAY("no zygote carries our library, so there is nothing to drop");
        return EXIT_SUCCESS;
    }
    SAY("restarting zygote to drop the hooks it still carries");
    restart_zygote();
    return EXIT_SUCCESS;
}

/// Arms a system that is already up: a KernelSU temp root, where ksud runs this instead of
/// post-fs-data, or a build with no root framework, where a root shell is the only trigger.
/// Processes already running stay uninjected, forked as they were from a bare zygote.
int late_load(const StageOptions &options) {
    if (options.stop) return disarm();

    if (!check_selinux(options.permissive)) return EXIT_FAILURE;
    if (exists(get_module_dir() + "/disable")) {
        WARN("NeoZygisk is marked disabled, arming it anyway because this stage was run");
    }

    SAY("bootstrapping NeoZygisk on a running system");
    if (int rc = post_fs_data(); rc != EXIT_SUCCESS) return rc;

    // Under ksud or apd the manager mounts the module set and runs the later stages itself,
    // and the rearm has to wait for that mount.
    auto impl = root_impl();
    if (manager_runs_stages(impl)) return EXIT_SUCCESS;

    SAY("nothing else runs the boot stages under %s, running them here", name_of(impl));
    int rc = post_mount();
    service();

    printf("\n");
    print_status();
    return rc;
}

}  // namespace

static const char *name_of(Stage stage) {
    switch (stage) {
    case Stage::PostFsData:
        return "post-fs-data";
    case Stage::PostMount:
        return "post-mount";
    case Stage::Service:
        return "service";
    case Stage::HotInstall:
        return "hotinstall";
    default:
        return "late-load";
    }
}

bool parse_stage(std::string_view name, Stage &out) {
    if (name == "post-fs-data") {
        out = Stage::PostFsData;
    } else if (name == "post-mount") {
        out = Stage::PostMount;
    } else if (name == "service") {
        out = Stage::Service;
    } else if (name == "hotinstall") {
        out = Stage::HotInstall;
    } else if (name == "late-load") {
        out = Stage::LateLoad;
    } else {
        return false;
    }
    return true;
}

int run_stage(Stage stage, const StageOptions &options) {
    g_stage = name_of(stage);

    // Magisk sets this for its module scripts when its own Zygisk is on, the one case to
    // stand down for. Our injector sets it too, in the manager app, and `su` passes a
    // caller's environment through -- so a hot install inherits it with no Magisk in sight.
    // Only Magisk has a built-in Zygisk, which is what the root check settles.
    if (getenv("ZYGISK_ENABLED") != nullptr && root_impl() == RootImpl::Magisk) {
        SAY("Magisk's own Zygisk is enabled, standing down");
        return EXIT_SUCCESS;
    }

    // Read by the monitor we start and the daemon it forks, which apply it to the module
    // snapshot as the fan-out below applies it to the boot scripts.
    if (options.ignore_disable) setenv("ZYGISK_IGNORE_DISABLE", "1", 1);

    switch (stage) {
    case Stage::PostFsData:
        return post_fs_data();
    case Stage::PostMount:
        return post_mount();
    case Stage::Service:
        return service();
    case Stage::HotInstall:
        return hot_install();
    case Stage::LateLoad:
        return late_load(options);
    }
    return EXIT_FAILURE;
}

int print_status() {
    std::string path = zygiskd::GetTmpPath() + "/module.prop";
    auto *file = fopen(path.c_str(), "re");
    if (file == nullptr) {
        fprintf(stderr, "error: no status at %s, NeoZygisk has not run on this boot\n",
                path.c_str());
        return EXIT_FAILURE;
    }

    printf("Status of NeoZygisk\n\n");
    char buf[1024];
    size_t nread;
    while ((nread = fread(buf, 1, sizeof(buf), file)) > 0) {
        fwrite(buf, 1, nread, stdout);
    }
    fclose(file);
    fflush(stdout);

    // ksud and apd close the action's output as soon as it exits, leaving no time to read
    // it. MMRL keeps its own log on screen and needs no pause.
    if (getenv("MMRL") == nullptr && manager_runs_stages(root_impl())) sleep(5);
    return EXIT_SUCCESS;
}
