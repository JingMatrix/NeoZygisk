#pragma once

#include <sys/types.h>

#include <string>
#include <string_view>

#include "types.hpp"

// Forward declaration to break circular dependency
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

    // Public Interface for event handling
    bool handle_daemon_exit_if_match(int pid, int process_status);
    const char* check_and_prepare_injection();

    /// Live-attach to this ABI's zygote and to system_server if they are already running
    /// and not yet injected. Returns false when the daemon could not be made ready, which
    /// is the only failure the caller can act on. A per-process attach happens in a
    /// detached child, so its outcome is not reported back: the process is resumed
    /// uninjected and the status file simply never shows it as injected.
    bool rearm();

    // Public methods for state modification
    const Status& get_status() const;
    void notify_injected();
    void set_daemon_info(std::string_view info);
    void set_daemon_crashed(std::string_view error);

    const char* const abi_name_;
    const std::string program_path_;

private:
    bool is_in_crash_loop();

    /// Starts this ABI's daemon if no live one is recorded. \p started, when given, reports
    /// whether this call forked one, which tells a caller that the daemon is still coming up
    /// and that its module snapshot is new.
    bool ensure_daemon_created(bool* started = nullptr);

    /// Fork off `tracer trace <pid> <mode_flag>` for one already-running process.
    void attach_running(pid_t pid, const char* mode_flag, const char* what);

    Status status_;
    StartCounter counter;

    /// Absolute paths, resolved once from /proc/self/exe. Relative ones would be read
    /// against a working directory that does not survive a reinstall, which is routine under
    /// a temp root. A hot install renames the live module directory into ksud's trash rather
    /// than deleting it, so the failure is not ENOENT but worse: every exec would keep
    /// succeeding and keep running the previous build, until the next boot clears the trash.
    std::string tracer_path_;
    std::string daemon_path_;
    AppMonitor& monitor_;
};
