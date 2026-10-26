#pragma once

#include <sys/types.h>

#include <set>
#include <string>
#include <string_view>

#include "main.hpp"
#include "types.hpp"

class AppMonitor;

/**
 * @brief Manages all state and logic for a single target architecture (ABI).
 *
 * This class is responsible for tracking the status of Zygote and the helper
 * daemon for a specific ABI (e.g., 64-bit). It handles crash-loop detection,
 * daemon creation, and pre-injection safety checks.
 */
class ZygoteAbiManager {
public:
    static constexpr int CRASH_LOOP_RETRY_COUNT = 5;
    static constexpr int CRASH_LOOP_WINDOW_SECONDS = 30;

    ZygoteAbiManager(AppMonitor& monitor, bool is_64bit);

    bool handle_daemon_exit_if_match(int pid, int process_status);
    const char* check_and_prepare_injection();

    /// Live-attach to this ABI's zygote and to system_server if they are up and not yet
    /// hooked. Each attach is waited for, so the answer covers the heartbeat as well.
    RearmResult rearm();

    const Status& get_status() const;

    /// Records that \p pid answered the daemon's heartbeat, the only proof that a process
    /// carries working hooks.
    void notify_injected(pid_t pid);
    void set_daemon_info(std::string_view info);
    void set_daemon_crashed(std::string_view error);

    const char* const abi_name_;
    const std::string program_path_;

private:
    bool is_in_crash_loop();

    /// Starts this ABI's daemon if no live one is recorded. \p started reports whether this
    /// call forked one, whose module snapshot is new and needs no refresh.
    bool ensure_daemon_created(bool* started = nullptr);

    /// Runs `tracer trace <pid> <mode_flag>` for one running process and waits for it.
    /// Returns whether the injector reported hooks; the library stays mapped either way.
    bool attach_running(pid_t pid, const char* mode_flag, const char* what);

    Status status_;
    StartCounter counter;

    /// The processes whose hooks the current daemon confirmed, which is what tells a hooked
    /// zygote from one that merely has the library mapped. Dropped when a new daemon starts.
    std::set<pid_t> hooked_;

    /// Absolute paths, resolved once from /proc/self/exe. A hot install renames the live
    /// module directory into ksud's trash rather than deleting it, so a relative path would
    /// keep resolving and keep running the previous build until the next boot.
    std::string tracer_path_;
    std::string daemon_path_;
    AppMonitor& monitor_;
};
