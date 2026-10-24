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
    /// is the only failure the caller can act on; a per-process attach failure leaves that
    /// process running uninjected and is reported in the status file instead.
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
    bool ensure_daemon_created();

    /// Fork off `tracer trace <pid> <mode_flag>` for one already-running process.
    void attach_running(pid_t pid, const char* mode_flag, const char* what);

    Status status_;
    StartCounter counter;

    /// Absolute paths, resolved once from /proc/self/exe. Relative paths would break a
    /// monitor that outlives a replacement of its own module directory, which is routine
    /// under a temp root: every exec from the live monitor would then fail with ENOENT.
    const std::string tracer_path_;
    const std::string daemon_path_;
    AppMonitor& monitor_;
};
