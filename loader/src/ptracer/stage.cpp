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

/**
 * @brief Who calls a stage, in which order, and under what rules.
 *
 * Read from AOSP (system/core/init, system/core/rootdir, system/core/toolbox,
 * frameworks/base), KernelSU (kernel/, userspace/ksud/src/), APatch (apd/src/, KernelPatch
 * kernel/patch/) and Magisk (native/src/).
 *
 *
 * Case 1: an init bootstrap, driven by a framework
 *
 * All three add the same four init actions. KernelSU writes KERNEL_SU_RC from the kernel
 * (runtime/ksud_integration.c); Magisk writes inject_magisk_rc from its init
 * (init/rootdir.rs); KernelPatch copies the original rc -- one of /system/etc/init/hw/init.rc,
 * /init.rc, /vendor/etc/init/hw/init.target.rc -- to /dev/user_init.rc with its actions
 * appended and redirects init to read that (patch/android/userd.c). Its stage line is
 * `/system/bin/truncate <superkey> su -Z u:r:magisk:s0 exec /data/adb/apd -s <superkey>
 * <stage>`; it also hooks early-init, init and late-init for its own kernel events, and
 * removes /dev/user_init.rc at boot-completed.
 *
 * Each action is an `exec`, which init runs as a temporary oneshot service: ExecStart sets
 * is_exec_service_running_, and init's main loop stops calling am.ExecuteOneCommand() until
 * the process is reaped (init/init.cpp, init/service.cpp). None of the rc lines sets a
 * timeout. The commands run as root in u:r:ksu:s0 under KernelSU and in u:r:magisk:s0 under
 * Magisk and APatch. rootdir/init.rc reaches the triggers in this order:
 *
 *   post-fs-data          /data is mounted. The framework runs: common post-fs-data.d
 *                         scripts, every module's post-fs-data.sh, system.prop, the module
 *                         mount, and -- ksud and apd only -- every module's post-mount.sh.
 *                         magiskd loads system.prop while mounting. Magisk has no post-mount.
 *   zygote-start          wait_for_prop odsign.verification.done 1, start statsd, start
 *                         zygote, start zygote_secondary. No framework action is hooked here.
 *   nonencrypted          class_start main, class_start late_start, and the framework's
 *                         service command: common service.d scripts and every module's
 *                         service.sh, none waited for.
 *   sys.boot_completed=1  ActivityManagerService.finishBooting sets this and dev.bootcomplete.
 *                         ksud and apd run every module's boot-completed.sh; magiskd runs no
 *                         module script and resets its own zygisk state.
 *
 * All three hook the service command twice, under `on nonencrypted` and under
 * `on property:vold.decrypt=trigger_restart_framework`: the two rc actions that ran
 * `class_start late_start`, the second belonging to full-disk encryption, where /data stays
 * unreadable until the password is entered and vold then sets the property (vold/cryptfs.cpp,
 * "startup service classes main and late_start"). Magisk needed neither until 2023, when
 * dba5020e4 replaced its `class late_start` service -- which both paths start -- with the
 * explicit pair; KernelSU added the same pair in 00b1d753 and KernelPatch carries it in
 * userd.c. AOSP had already deleted those actions from init.rc and cryptfs from vold
 * (335cd1f4a3 and 0803ba09: "These triggers were specific to FDE, which is no longer
 * supported"), and init queues `nonencrypted` for file- and metadata-encrypted data as well
 * (init/builtins.cpp), so only the first action can fire on a current tree. What reaches us is
 * the shape: the service stage has two entry points, so running it twice must be harmless.
 *
 * ksud and apd skip every stage when Magisk is installed. In safe mode all three skip the
 * scripts, and each disables the modules on its post-fs-data path.
 *
 *
 * Case 2: a late load into a system that is already running
 *
 * KernelSU only: `ksud late-load` inserts kernelsu.ko at runtime, takes an allow_shell flag,
 * and its own comment calls this jailbreak mode, where the bundled flag is meaningless
 * because no boot image can be flashed (late_load.rs). KernelPatch has a loadable-module
 * delivery whose README lists the module loader, kstorage and the allowlist as unimplemented.
 *
 * After loading the module ksud installs itself, handles updated and removed modules, applies
 * sepolicy.rule and the root profiles and starts its features, then runs, in order: a
 * `late-load` stage, blocking against a 35 second deadline (BOOT_STAGE_TIMEOUT) shared with
 * what follows; system.prop; the module mount; a blocking `post-mount` stage; an unwaited
 * `service` stage; an unwaited `boot-completed` stage; a force-stop and restart of the manager
 * app. Every script in such a session also reads KSU_LATE_LOAD=1 and
 * KSU_RUNTIME_MODE=late-load. A root shell on such a system runs in the domain its root
 * profile names, which KernelSU defaults to u:r:ksu:s0 (kernel/policy/allowlist.c).
 *
 *
 * Case 3: a soft reboot simulated by the framework
 *
 * soft_reboot.rs clears sys.boot_completed, runs an `emulated-soft-reboot` stage against a 5
 * second deadline, runs `stop`, waits for the services to go down, replays the whole
 * post-fs-data path including the module mount and `post-mount`, then runs `start`, the
 * service stage and boot-completed. `ksud unload` (unload.rs) runs `stop`, then SIGKILL to
 * every process in u:r:ksu:s0 and to every holder of a [ksu_driver] or [ksu_fdwrapper] fd.
 *
 *
 * Case 4: a hot install
 *
 * A module asks for one from customize.sh with MODULE_HOT_INSTALL_REQUEST and
 * MODULE_HOT_RUN_SCRIPT. ksud moves the staged directory over the live one, applies its
 * sepolicy.rule, enters init's mount namespace, and runs the named script with a 30 second
 * deadline, stdin closed and SIGPIPE ignored. Its own comment records what does not happen:
 * partition mounts, system.prop and post-fs-data wait for the next boot (hot_install.rs).
 * installer.sh clears the live directory's `disable` and `remove` markers before the swap, so
 * an install re-enables a module the user had turned off, and the swapped-in directory carries
 * no marker of its own.
 *
 *
 * Case 5: a direct invocation of late-load.sh, with no framework present
 *
 * Nothing above runs. No framework sets KSU, APATCH or KSU_LATE_LOAD in the environment, no
 * module's boot scripts have run on that boot, and nothing will mount the module set or reach
 * a later stage. None of these sources says anything about the uid, domain or environment
 * such a shell has; they are whatever granted the root.
 *
 *
 * How a script is run
 *
 * All three exec `busybox sh <script>` from their own assets. ksud and apd set the working
 * directory to the script's own; magiskd sets none. Before the exec, ksud restores the
 * original signal mask, detaches the process group and switches cgroups; apd puts the script
 * in its own process group and switches cgroups; magiskd only sets the environment, and
 * double-forks its service scripts so init reparents them.
 *
 *   ksud     spawns, then waits for that child until the shared deadline; on timeout it warns
 *            and carries on without killing it, and once the deadline has passed later
 *            scripts are spawned with no wait (exec_script_with).
 *   apd      blocks with no deadline on post-fs-data and post-mount; does not wait for
 *            service or boot-completed.
 *   magiskd  shares one 35 second budget (POST_FS_DATA_SCRIPT_MAX_TIME) between
 *            post-fs-data.d and the modules' post-fs-data.sh, inside a forked child it waits
 *            for; when its timer wins, the rest run unwaited.
 *   action   ksud waits for action.sh forever, apd blocks. The KernelSU manager runs
 *            `ksud module action <id>` in a root shell, streams stdout into a screen, and
 *            closes that screen on completion only when it was launched from a shortcut.
 *
 *
 * What a script reads about its caller
 *
 * ksud: ASH_STANDALONE, KSU=true, KSU_VER, KSU_VER_CODE, KSU_KERNEL_VER_CODE, KSU_UAPI_VER,
 * KSU_MODULE=<id>, KSU_RUNTIME_MODE as built-in, lkm or late-load, KSU_LATE_LOAD=1 on a
 * late-loaded session, and its bin directory appended to PATH.
 *
 * apd: ASH_STANDALONE, APATCH=true, APATCH_VER, APATCH_VER_CODE, AP_MODULE=<id>, and its bin
 * directory appended to PATH. It sets no KSU.
 *
 * magiskd: ASH_STANDALONE, its tmp directory -- /debug_ramdisk or /sbin -- appended to PATH,
 * and ZYGISK_ENABLED=1 only when its own Zygisk is enabled. That Zygisk enters zygote through
 * the ro.dalvik.vm.native.bridge property and restores the property after three zygote
 * crashes (zygisk/daemon.rs). Nothing in its environment names Magisk.
 *
 *
 * Which modules a stage reaches
 *
 * ksud: every module directory with neither a `disable` nor a `remove` file, less the
 * metamodule, which it drives separately and which runs the module mount. apd: every module
 * without a `disable` file. magiskd: the list it collects once per boot -- a `disable` file
 * leaves a module out, a `remove` file has its uninstall.sh run and the directory deleted,
 * and when its own Zygisk is off every module holding a zygisk/ directory is dropped, so such
 * a module is neither mounted nor given a boot script.
 *
 *
 * Zygote, as init declares it
 *
 * init.zygote64.rc: `service zygote /system/bin/app_process64 -Xzygote /system/bin --zygote
 * --start-system-server`, `class main`, `critical window=${zygote.critical_window.minute:-off}
 * target=zygote-fatal`, and an onrestart list that restarts audioserver, cameraserver, media,
 * media.tuner if running, netd and wificond, takes a wake lock, and asks vdc to abort a fuse
 * volume.
 *
 * Magisk patches two more things into those files (init/rootdir.cpp): Samsung's
 * `on property:persist.sys.zygote.early=` trigger is renamed to one nothing sets, so zygote
 * cannot start before post-fs-data, and every `service zygote` gets an `onrestart exec ...
 * magisk --zygote-restart` line, which replaced the init.svc.zygote property triggers it
 * hooked until 42eb92805.
 *
 * `stop` and `start` with no argument are toolbox/start.cpp: ctl.stop or ctl.start for netd,
 * surfaceflinger, audioserver and zygote, plus zygote_secondary unless ro.zygote is zygote32
 * or zygote64, stopped in the reverse of that order.
 *
 * That `critical` line is conditional: ParseCritical returns before setting SVC_CRITICAL when
 * the window expands to "off", which is its default, so zygote is critical only where
 * zygote.critical_window.minute is set. Where it is, init/service.cpp reboots into the named
 * target on a fifth crash inside the window -- or a fifth before sys.boot_completed, where the
 * window is not applied -- throttled to once per 24 hours through
 * persist.init.svc.last_fatal_reboot_epoch.
 */

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

/// Whether the caller is running this stage for every module itself, which leaves us none to
/// trigger. ksud and apd each set their variable for every script they run; magiskd names
/// itself in nothing it sets, and neither does a root shell, and both of those leave us the
/// Zygisk modules. The same two carry on with the rest of their stage sequence after we
/// return, which is what a late load hands back to -- see cases 1 and 2 above.
bool caller_fans_out() { return getenv("KSU") != nullptr || getenv("APATCH") != nullptr; }

bool exists(const std::string &path) { return access(path.c_str(), F_OK) == 0; }

/// The marker a manager writes when the user turns NeoZygisk off. Every framework's own
/// fan-out leaves a module carrying it out of every stage.
bool module_disabled() { return exists(get_module_dir() + "/disable"); }

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

/// Traversable by uid 1000 and nobody else: a late-injected system_server opens the library
/// and the socket as itself, which no SELinux setting relaxes, while root overrides DAC
/// anyway.
bool make_sys_dir(const std::string &path) {
    if (mkdir(path.c_str(), 0550) == -1 && errno != EEXIST) {
        PLOGE("mkdir %s", path.c_str());
        return false;
    }
    return set_sys_perm(path, 0550);
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
RearmResult arm(bool ignore_disable) { return send_rearm_command(ignore_disable); }

/// Our workaround for a zygote we cannot fix in place: the unhook path runs on a forked
/// child's main thread, where a fork landing on a half-restored JNI table crash-loops, and
/// we neither unload nor re-enter a library that is already mapped. Detached, so a framework
/// going down spares the caller.
void restart_zygote() {
    if (fork_dont_care() == 0) {
        detach_stdio();
        run_wait("/system/bin/stop", "stop");
        execl("/system/bin/start", "start", nullptr);
        PLOGE("exec /system/bin/start");
        _exit(1);
    }
}

/// Runs one stage script for every Zygisk module, waiting for each unless async, which is
/// the boot contract: post-fs-data blocks the stage, service does not. With ignore_disable
/// the scripts of modules marked disabled run too.
void fan_out(const char *script, bool async, bool ignore_disable) {
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

    while (auto *entry = readdir(dir)) {
        if (entry->d_name[0] == '.') continue;

        std::string module = modules + "/" + entry->d_name;
        struct stat st{};
        if (stat((module + "/zygisk").c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        if (!ignore_disable && exists(module + "/disable")) continue;

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

/// Puts the injector where zygote can read it and starts the monitor, which seizes init and
/// catches every zygote it forks from then on.
bool install() { return stage_work_directory() && start_monitor(); }

/// Waits for a monitor to own the control socket. The monitor initialises its ptrace handler
/// before its socket handler, so an answer here also means init has been seized.
bool wait_for_monitor() {
    constexpr int kAttempts = 50;
    constexpr useconds_t kDelayUs = 200 * 1000;
    for (int attempt = 0; attempt < kAttempts; ++attempt) {
        if (monitor_is_running()) return true;
        usleep(kDelayUs);
    }
    return false;
}

/// init reaches zygote-start after post-fs-data, so there is normally no zygote to inject
/// here; a device that starts one earlier through persist.sys.zygote.early is armed by the
/// service stage instead. The whole init command queue waits on this stage -- apd waits with
/// no deadline at all -- so it does no more than install.
int post_fs_data(const StageOptions &options) {
    if (!caller_fans_out()) fan_out("post-fs-data.sh", false, options.ignore_disable);
    return install() ? EXIT_SUCCESS : EXIT_FAILURE;
}

/// Arms a system whose zygote is already up, and reports the verdict. A normal boot reaches
/// this before zygote exists, where the monitor seized on init does the work, so it is a
/// no-op that holds up neither the stage nor the boot.
int arm_running_system(const StageOptions &options) {
    if (find_zygotes().empty()) return EXIT_SUCCESS;

    SAY("system already running, arming NeoZygisk");
    switch (arm(options.ignore_disable)) {
    case RearmResult::Injected:
        SAY("zygote injected, with the daemon answering for its hooks");
        return EXIT_SUCCESS;
    case RearmResult::AlreadyHooked:
        SAY("zygote is hooked already, nothing to arm");
        return EXIT_SUCCESS;
    case RearmResult::Injecting:
        SAY("the monitor is injecting the zygote it caught on init, nothing to add");
        return EXIT_SUCCESS;
    case RearmResult::NoZygote:
        return EXIT_SUCCESS;
    case RearmResult::NeedsRestart:
        // We do not inject over a library that is already mapped, so the zygote carrying it
        // goes instead, and everything it forked with it.
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

/// Injecting zygote belongs to this stage: init started it one trigger earlier, so it is up
/// or coming up by now, and this stage is the first one no framework waits for. The module
/// daemons are forked first and not waited for either -- one that comes up before the
/// injection idles harmlessly, while an injected process that cannot find its daemon has
/// lost it until zygote restarts.
int service(const StageOptions &options) {
    if (!caller_fans_out()) fan_out("service.sh", true, options.ignore_disable);
    return arm_running_system(options);
}

/// ksud runs this after moving the new module directory over the live one, while the old
/// monitor still traces init through binaries that are gone, and runs no other stage. The
/// zygote in front of us carries the previous version of the injector, so it is replaced
/// rather than injected into.
int hot_install(const StageOptions &) {
    if (module_disabled()) {
        SAY("NeoZygisk is marked disabled, leaving this system as it is");
        return EXIT_SUCCESS;
    }

    // Deliberately not fatal: a monitor that outlasts the wait finds the control socket
    // owned and stands down, which is the only sane answer left.
    stop_monitor();

    SAY("starting the new monitor");
    if (!install()) return EXIT_FAILURE;

    // Waited for, so the restart below cannot land before the monitor can catch it. Together
    // with the wait above this is at most 20 seconds, inside ksud's 30 second budget.
    if (!wait_for_monitor()) {
        ERR("the new monitor did not take the control socket, NeoZygisk will start on the "
            "next boot");
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

/// Arms a system that is already up, whether a framework put it there or a root shell did.
/// Processes already running stay uninjected, forked as they were from a bare zygote.
int late_load(const StageOptions &options) {
    if (options.stop) return disarm();

    if (!check_selinux(options.permissive)) return EXIT_FAILURE;
    if (module_disabled()) {
        WARN("NeoZygisk is marked disabled, arming it anyway because this stage was run");
    }

    SAY("bootstrapping NeoZygisk on a running system");
    if (!install()) return EXIT_FAILURE;

    // ksud reaches its own module mount, post-mount and service stages once this returns, and
    // it does not wait for the service stage. Arming there costs nothing of its boot deadline
    // and has the module set mounted, so the rest of the work is left to our service.sh.
    if (caller_fans_out()) {
        SAY("the framework runs its remaining stages next, where NeoZygisk is armed");
        return EXIT_SUCCESS;
    }

    // The stages ksud reaches after its own late-load stage, in its order, for the case where
    // nothing else will: the module mount it performs there is a framework's business, but
    // post-mount.sh and service.sh are the modules' own. post-fs-data.sh is left out because
    // ksud leaves it out too -- that stage belongs to a boot where /data has just been
    // mounted and no zygote exists yet.
    SAY("nothing else runs the other modules' boot scripts here");
    fan_out("post-mount.sh", false, options.ignore_disable);
    int rc = service(options);

    printf("\n");
    print_status();
    return rc;
}

}  // namespace

static const char *name_of(Stage stage) {
    switch (stage) {
    case Stage::PostFsData:
        return "post-fs-data";
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
    // caller's environment through, so a hot install inherits it with no Magisk in sight.
    // Magisk's set_script_env puts the directory holding its binary on PATH in the same
    // breath as it sets this, so the two arrive together.
    if (getenv("ZYGISK_ENABLED") != nullptr && on_path("magisk")) {
        SAY("Magisk's own Zygisk is enabled, standing down");
        return EXIT_SUCCESS;
    }

    switch (stage) {
    case Stage::PostFsData:
        return post_fs_data(options);
    case Stage::Service:
        return service(options);
    case Stage::HotInstall:
        return hot_install(options);
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

    // ksud and apd are also the two whose managers run this behind an action button, which is
    // all we can detect here. The KernelSU manager keeps the output on screen once the action
    // ends, closing it only when launched from a shortcut, and MMRL keeps a log of its own;
    // APatch's manager we have not read, so the pause stays.
    if (getenv("MMRL") == nullptr && caller_fans_out()) sleep(5);
    return EXIT_SUCCESS;
}
