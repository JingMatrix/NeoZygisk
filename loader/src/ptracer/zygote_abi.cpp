#include "zygote_abi.hpp"

#include <libgen.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <cstring>
#include <iterator>
#include <vector>

#include "daemon.hpp"
#include "logging.hpp"
#include "monitor.hpp"
#include "utils.hpp"

namespace {

// The daemon's length counts the terminator, so the payload carries a trailing NUL. Strip
// it where both senders converge, to keep the status file plain text.
std::string_view without_trailing_nuls(std::string_view text) {
    while (!text.empty() && text.back() == '\0') text.remove_suffix(1);
    return text;
}

/// How long one injection may take: an unanswered heartbeat costs the injector about five
/// seconds of retries, from inside the remote call.
constexpr int kAttachTimeoutMs = 20 * 1000;

/// Polls rather than blocks, so a wedged tracer cannot hold the monitor's only thread for
/// good. Returns the exit status, or -1 for a child that outlasted the wait and is left to
/// the SIGCHLD handler.
int wait_bounded(pid_t pid, int timeout_ms) {
    constexpr int kStepMs = 50;
    for (int waited = 0; waited < timeout_ms; waited += kStepMs) {
        int status = 0;
        pid_t done = waitpid(pid, &status, WNOHANG | __WALL);
        if (done == pid) return status;
        if (done == -1) {
            PLOGE("waitpid on injector %d", pid);
            return -1;
        }
        usleep(kStepMs * 1000);
    }
    LOGW("the injector for pid %d has not finished after %dms, leaving it to run", pid, timeout_ms);
    return -1;
}

/// A zygote the monitor caught at exec is parked in SIGSTOP until its injector seizes it,
/// and traced by that injector while it works. A second injector would fight the first, and
/// would fail with the library not yet mapped, which reads as a zygote needing a restart.
bool injection_in_flight(pid_t pid) {
    if (get_tracer_pid(pid) > 0) return true;
    char state = get_process_state(pid);
    return state == 'T' || state == 't';
}

}  // namespace

ZygoteAbiManager::ZygoteAbiManager(AppMonitor& monitor, bool is_64bit)
    : abi_name_(is_64bit ? "64" : "32"),
      program_path_(is_64bit ? "/system/bin/app_process64" : "/system/bin/app_process32"),
      monitor_(monitor) {
    const auto& module_dir = get_module_dir();
    tracer_path_ = module_dir + (is_64bit ? "/bin/zygisk-ptrace64" : "/bin/zygisk-ptrace32");
    daemon_path_ = module_dir + (is_64bit ? "/bin/zygiskd64" : "/bin/zygiskd32");
}

const Status& ZygoteAbiManager::get_status() const { return status_; }

void ZygoteAbiManager::notify_injected(pid_t pid) {
    if (pid > 0) hooked_.insert(pid);
    status_.zygote = ZygoteState::Injected;
}

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

bool ZygoteAbiManager::ensure_daemon_created(bool* started) {
    if (started) *started = false;
    if (status_.daemon_pid == -1) {
        // Nothing the previous daemon confirmed carries over: its socket, companions and
        // module memfds went with it. What still carries our library is rearm()'s to judge.
        hooked_.clear();
        status_.zygote = ZygoteState::NotInjected;
        auto pid = fork();
        if (pid < 0) {
            PLOGE("create daemon (abi=%s)", abi_name_);
            return false;
        }
        if (pid == 0) {
            // Bind the daemon's lifetime to this monitor: a daemon whose monitor is gone
            // is unreachable, since the next one rebinds the socket name from under it, and
            // would hold a retired session's memfds and companion sockets for good. The
            // signal survives execve; re-checking the parent closes the race where the
            // monitor exits before it was armed.
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
        if (started) *started = true;
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

bool ZygoteAbiManager::attach_running(pid_t pid, const char* mode_flag, const char* what) {
    LOGI("rearm: attaching to running %s (pid %d)", what, pid);
    auto child = fork();
    if (child == -1) {
        PLOGE("fork injector for %s", what);
        return false;
    }
    if (child == 0) {
        execl(tracer_path_.c_str(), basename(tracer_path_.c_str()), "trace",
              std::to_string(pid).c_str(), mode_flag, nullptr);
        PLOGE("exec injector for %s", what);
        // Never signal the target from this path: it is live and carrying the running
        // system, so losing injection for it is recoverable where killing it is not.
        _exit(TRACE_FAILED);
    }

    // Waited for, unlike the boot path, which has the ptrace event loop to get back to: the
    // heartbeat runs inside the remote call, so the exit status covers it, and this is the
    // last moment the answer can be used. Processes init forks sit in a ptrace stop until
    // this returns, the same cost the module refresh below already pays.
    int status = wait_bounded(child, kAttachTimeoutMs);
    if (status == -1) return false;
    if (!WIFEXITED(status)) {
        LOGE("rearm: the injector for %s (pid %d) died: %s", what, pid,
             parse_status(status).c_str());
        return false;
    }
    switch (WEXITSTATUS(status)) {
    case TRACE_HOOKED:
        hooked_.insert(pid);
        return true;
    case TRACE_MAPPED_ONLY:
        LOGE("rearm: %s (pid %d) took our library but got no hooks", what, pid);
        return false;
    default:
        LOGE("rearm: the injector for %s (pid %d) failed", what, pid);
        return false;
    }
}

RearmResult ZygoteAbiManager::rearm(bool ignore_disable) {
    // Every app process is a forked zygote that never execs, so the whole running system
    // reports this same executable: a zygote is one that init started and that argv says is
    // one. Parentage alone would also admit a daemon that backgrounded itself out of a boot
    // script, and the zygote hooks in a process that never forks an app. system_server is
    // the only forked child that is a target of its own, and the only one that renames
    // itself; an app zygote like webview_zygote inherits the hooks it was forked with.
    //
    // comm cannot identify the zygote: it rewrites its cmdline, which is what pidof
    // matches, but never calls prctl(PR_SET_NAME), so it still reports "main".
    pid_t system_server_pid = -1;
    std::vector<pid_t> zygote_pids;
    for (auto pid : find_processes_by_exe(program_path_)) {
        if (get_ppid(pid) == 1) {
            if (has_zygote_cmdline(pid)) {
                zygote_pids.push_back(pid);
            } else {
                LOGI("rearm: %s (pid %d) is not a zygote, skipping", program_path_.c_str(), pid);
            }
        } else if (get_comm(pid) == "system_server") {
            system_server_pid = pid;
        }
    }

    if (zygote_pids.empty()) {
        // A normal boot reaches this on every service stage, long before zygote exists. The
        // monitor is already seized on init and will catch it the usual way, with the daemon
        // it forks then, which is why nothing is started above.
        LOGI("rearm: no running zygote for %s, nothing to attach", program_path_.c_str());
        return RearmResult::NoZygote;
    }

    status_.supported = true;

    bool daemon_started = false;
    if (!ensure_daemon_created(&daemon_started)) {
        LOGE("rearm: daemon%s is not running", abi_name_);
        return RearmResult::Failed;
    }

    // A daemon that outlived a module change still holds the previous snapshot, so have it
    // rescan before anything is injected against it. One just forked needs none, and asking
    // it anyway would block this thread in Connect()'s retries until it binds its socket --
    // unless this rearm wants the disabled modules too, which its startup scan knew nothing
    // about.
    if ((!daemon_started || ignore_disable) && !zygiskd::RefreshModules(ignore_disable)) {
        LOGW("rearm: daemon%s could not refresh its module snapshot", abi_name_);
    }

    // A pid is handed out again once the kernel wraps around, so a confirmation is kept
    // only while the process it was given for is still one of the two that can earn one.
    for (auto it = hooked_.begin(); it != hooked_.end();) {
        bool live = *it == system_server_pid ||
                    std::find(zygote_pids.begin(), zygote_pids.end(), *it) != zygote_pids.end();
        it = live ? std::next(it) : hooked_.erase(it);
    }

    // The mapping lasts a zygote's whole life, so it tells a bare zygote from an injected
    // one. What it cannot tell is whether that injection reached the daemon -- and we do not
    // inject over a mapping that is already there, hooks or no hooks.
    bool armed_any = false, hooked_any = false, injecting_any = false;
    bool zygote_needs_restart = false;
    for (auto pid : zygote_pids) {
        if (injection_in_flight(pid)) {
            LOGI("rearm: zygote (pid %d) has an injector of its own on it, leaving it alone", pid);
            injecting_any = true;
        } else if (!has_library_mapped(pid, "libzygisk.so")) {
            if (attach_running(pid, "--standalone", "zygote")) {
                armed_any = true;
            } else {
                zygote_needs_restart = true;
            }
        } else if (hooked_.count(pid) > 0) {
            LOGI("rearm: zygote (pid %d) is hooked already, skipping", pid);
            hooked_any = true;
        } else {
            LOGW("rearm: zygote (pid %d) carries our library with no hooks to show for it", pid);
            zygote_needs_restart = true;
        }
    }

    status_.zygote = zygote_needs_restart        ? ZygoteState::NeedsRestart
                     : (armed_any || hooked_any) ? ZygoteState::Injected
                                                 : ZygoteState::NotInjected;
    LOGI("rearm: zygote%s is %s", abi_name_, name_of(status_.zygote));

    // system_server is only reachable this way, being forked without an exec, where a
    // normal boot specializes it inside an already-hooked zygote. It therefore comes after
    // zygote, never before. Gate it on a zygote this rearm hooked: one hooked earlier has
    // run server_specialize already, and firing it
    // twice re-enters every module's lifecycle, while one needing a restart takes
    // system_server with it. The library cannot answer this, since a normally specialized
    // system_server unmaps it on the way out.
    bool needs_restart = zygote_needs_restart;
    if (system_server_pid == -1) {
        LOGI("rearm: no running system_server");
    } else if (!armed_any) {
        LOGI("rearm: no zygote was armed here, leaving system_server (pid %d) alone",
             system_server_pid);
    } else if (!attach_running(system_server_pid, "--system_server", "system_server")) {
        // The same bind as a zygote with no hooks, and the same way out: a zygote restart
        // takes system_server with it.
        needs_restart = true;
    }

    monitor_.update_status();

    if (needs_restart) return RearmResult::NeedsRestart;
    if (armed_any) return RearmResult::Injected;
    return hooked_any || !injecting_any ? RearmResult::AlreadyHooked : RearmResult::Injecting;
}
