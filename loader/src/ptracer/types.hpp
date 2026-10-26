#pragma once

#include <sys/types.h>

#include <string>

// Defines common data structures used across the monitor application.

enum TracingState { TRACING = 1, STOPPING, STOPPED, EXITING };

/// The name a state is logged under.
inline const char *name_of(TracingState state) {
    switch (state) {
    case TRACING:
        return "tracing";
    case STOPPING:
        return "stopping";
    case STOPPED:
        return "stopped";
    case EXITING:
        return "exiting";
    default:
        return "unknown";
    }
}

/// What is known about this ABI's zygote. A library mapped into a zygote whose heartbeat no
/// daemon ever answered is worth a state of its own: it cannot be injected a second time,
/// and the hooks it is missing arrive only with a fresh zygote.
enum class ZygoteState { NotInjected, Injected, NeedsRestart };

inline const char *name_of(ZygoteState state) {
    switch (state) {
    case ZygoteState::Injected:
        return "injected";
    case ZygoteState::NeedsRestart:
        return "needs restart";
    default:
        return "not injected";
    }
}

struct Status {
    bool supported = false;
    ZygoteState zygote = ZygoteState::NotInjected;
    bool daemon_running = false;
    pid_t daemon_pid = -1;
    std::string daemon_info;
    std::string daemon_error_info;
};

struct StartCounter {
    struct timespec last_start_time{.tv_sec = 0, .tv_nsec = 0};
    int count = 0;
};
