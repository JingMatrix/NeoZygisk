#include "zygote_abi.hpp"

#include <libgen.h>
#include <limits.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstring>
#include <vector>

#include "daemon.hpp"
#include "logging.hpp"
#include "monitor.hpp"
#include "utils.hpp"

namespace {

/**
 * @brief Resolves $MODDIR from /proc/self/exe ($MODDIR/bin/zygisk-ptrace64 -> $MODDIR).
 *
 * Pinned at construction so the helper paths survive the root manager replacing the
 * module directory underneath a running monitor, as a reinstall or hot install does.
 */
std::string resolve_module_dir() {
    char exe_path[PATH_MAX];
    auto len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        PLOGE("readlink /proc/self/exe");
        return ".";
    }
    exe_path[len] = '\0';
    // dirname() modifies in place: .../bin/zygisk-ptrace64 -> .../bin -> $MODDIR
    return dirname(dirname(exe_path));
}

// The daemon frames its status strings with a length that counts the terminator, so the
// payload carries a trailing NUL. Strip it here, where both senders converge, to keep the
// status file plain text.
std::string_view without_trailing_nuls(std::string_view text) {
    while (!text.empty() && text.back() == '\0') text.remove_suffix(1);
    return text;
}

}  // namespace

ZygoteAbiManager::ZygoteAbiManager(AppMonitor& monitor, bool is_64bit)
    : abi_name_(is_64bit ? "64" : "32"),
      program_path_(is_64bit ? "/system/bin/app_process64" : "/system/bin/app_process32"),
      tracer_path_(resolve_module_dir() +
                   (is_64bit ? "/bin/zygisk-ptrace64" : "/bin/zygisk-ptrace32")),
      daemon_path_(resolve_module_dir() + (is_64bit ? "/bin/zygiskd64" : "/bin/zygiskd32")),
      monitor_(monitor) {}

const Status& ZygoteAbiManager::get_status() const { return status_; }

void ZygoteAbiManager::notify_injected() { status_.zygote_injected = true; }

void ZygoteAbiManager::set_daemon_info(std::string_view info) {
    status_.daemon_info = without_trailing_nuls(info);
}

void ZygoteAbiManager::set_daemon_crashed(std::string_view error) {
    status_.daemon_running = false;
    status_.daemon_error_info = without_trailing_nuls(error);
}

bool ZygoteAbiManager::is_in_crash_loop() {
    struct timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - counter.last_start_time.tv_sec < ZygoteAbiManager::CRASH_LOOP_WINDOW_SECONDS) {
        counter.count++;
    } else {
        counter.count = 1;
    }
    counter.last_start_time = now;
    return counter.count >= ZygoteAbiManager::CRASH_LOOP_RETRY_COUNT;
}

bool ZygoteAbiManager::ensure_daemon_created() {
    status_.zygote_injected = false;
    if (status_.daemon_pid == -1) {
        auto pid = fork();
        if (pid < 0) {
            PLOGE("create daemon (abi=%s)", abi_name_);
            return false;
        }
        if (pid == 0) {
            // Bind the daemon's lifetime to this monitor. Once its monitor is gone a
            // daemon is unreachable -- a replacement cannot adopt it, and the next one
            // unlinks and rebinds the socket name from under it -- so it would hold a
            // retired session's module memfds and companion sockets indefinitely.
            //
            // The signal survives execve, being cleared only for a set-user-ID binary.
            // Re-checking the parent closes the race where the monitor exits inside this
            // window, before the signal was armed.
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            if (getppid() == 1) _exit(1);

            execl(daemon_path_.c_str(), daemon_path_.c_str(), "--workdir",
                  zygiskd::GetTmpPath().c_str(), nullptr);
            PLOGE("exec daemon %s", daemon_path_.c_str());
            exit(1);
        }
        status_.supported = true;
        status_.daemon_pid = pid;
        status_.daemon_running = true;
    }
    return status_.daemon_running;
}

const char* ZygoteAbiManager::check_and_prepare_injection() {
    if (is_in_crash_loop()) {
        monitor_.request_stop("zygote crashed");
        return nullptr;
    }
    if (!ensure_daemon_created()) {
        monitor_.request_stop("daemon not running");
        return nullptr;
    }
    return tracer_path_.c_str();
}

bool ZygoteAbiManager::handle_daemon_exit_if_match(int pid, int process_status) {
    if (status_.supported && pid == status_.daemon_pid) {
        auto status_str = parse_status(process_status);
        LOGW("ZygoteAbiManager: daemon%s (pid %d) exited: %s", abi_name_, pid, status_str.c_str());
        status_.daemon_running = false;
        // Clear the pid so ensure_daemon_created() can start a replacement. Losing the
        // daemon is routine under a temp root: `ksud unload` SIGKILLs every holder of a
        // [ksu_driver] fd, and zygiskd holds one for its whole life.
        status_.daemon_pid = -1;
        if (status_.daemon_error_info.empty()) {
            status_.daemon_error_info = status_str;
        }
        monitor_.update_status();
        return true;
    }
    return false;
}

void ZygoteAbiManager::attach_running(pid_t pid, const char* mode_flag, const char* what) {
    LOGI("rearm: attaching to running %s (pid %d)", what, pid);
    auto child = fork_dont_care();
    if (child == 0) {
        execl(tracer_path_.c_str(), basename(tracer_path_.c_str()), "trace",
              std::to_string(pid).c_str(), mode_flag, nullptr);
        PLOGE("exec injector for %s", what);
        // Never signal the target from this path: it is live and carrying the running
        // system, so losing injection for it is recoverable where killing it is not.
        _exit(1);
    } else if (child == -1) {
        PLOGE("fork injector for %s", what);
    }
}

bool ZygoteAbiManager::rearm() {
    if (!ensure_daemon_created()) {
        LOGE("rearm: daemon%s is not running", abi_name_);
        return false;
    }

    // A daemon that outlived a module refresh still holds the previous snapshot, so have
    // it rescan before anything is injected against it.
    if (!zygiskd::RefreshModules()) {
        LOGW("rearm: daemon%s could not refresh its module snapshot", abi_name_);
    }

    // Match on the executable, as the spawn path does, then narrow by parentage: every
    // app process is a forked zygote that never execs, so the whole running system reports
    // this same executable. A zygote is the one init started. system_server is the only
    // forked child that is a target in its own right, and the only one that renames
    // itself; an app or an app zygote like webview_zygote inherits the hooks of the zygote
    // it came from.
    //
    // comm cannot identify the zygote: it rewrites its cmdline, which is what pidof
    // matches, but never calls prctl(PR_SET_NAME), so it still reports "main".
    pid_t system_server_pid = -1;
    std::vector<pid_t> zygote_pids;
    for (auto pid : find_processes_by_exe(program_path_)) {
        if (get_ppid(pid) == 1) {
            zygote_pids.push_back(pid);
        } else if (get_comm(pid) == "system_server") {
            system_server_pid = pid;
        }
    }

    if (zygote_pids.empty()) {
        // A normal boot reaches this on every post-mount, long before zygote exists. The
        // monitor is already seized on init and will catch it the usual way.
        LOGI("rearm: no running zygote for %s, nothing to attach", program_path_.c_str());
        return true;
    }

    status_.supported = true;

    // libzygisk.so stays mapped in a zygote for its whole life -- the self-unmap only
    // happens in a specialized child -- so its presence is a reliable injected marker here
    // and makes a repeated rearm a no-op.
    bool any_zygote_was_bare = false;
    for (auto pid : zygote_pids) {
        if (has_library_mapped(pid, "libzygisk.so")) {
            LOGI("rearm: zygote (pid %d) is already injected, skipping", pid);
            status_.zygote_injected = true;
        } else {
            any_zygote_was_bare = true;
            attach_running(pid, "--standalone", "zygote");
        }
    }

    // system_server is only reachable this way: it is forked without an exec, so the
    // monitor never sees it, and a normal boot instead specializes it inside an
    // already-hooked zygote.
    //
    // Gate it on having found a zygote without our hooks. An injected zygote means the
    // system either booted normally or was already rearmed, and in both cases
    // system_server has run server_specialize once already -- firing it a second time
    // would re-enter every module's lifecycle. The library is not a usable marker for
    // this: a normally specialized system_server unmaps it on the way out, so its absence
    // cannot distinguish "never injected" from "injected and cleaned up".
    if (system_server_pid == -1) {
        LOGI("rearm: no running system_server");
    } else if (!any_zygote_was_bare) {
        LOGI("rearm: zygote was already injected, leaving system_server (pid %d) alone",
             system_server_pid);
    } else {
        attach_running(system_server_pid, "--system_server", "system_server");
    }

    monitor_.update_status();
    return true;
}
