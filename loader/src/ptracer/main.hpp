#pragma once

#include <cstdint>

#include "trace.hpp"

void init_monitor();

/// Attaches to \p pid, maps the injector into it and calls its entry point. \p hooked, when
/// given, reports whether the injector answered that it installed its hooks: the heartbeat
/// it needs for that can fail on its own, and the library stays mapped either way.
bool trace_target(int pid, TraceMode mode, bool *hooked = nullptr);

/// The exit status of `tracer trace`, which is how the monitor learns what an injection it
/// forked achieved.
enum TraceExit { TRACE_HOOKED = 0, TRACE_FAILED = 1, TRACE_MAPPED_ONLY = 2 };

/// Reports whether a monitor is currently bound to the control socket. The socket file
/// outlives whoever bound it, so its presence proves nothing; connecting to it does.
bool monitor_is_running();

enum Command {
    START = 1,
    STOP = 2,
    EXIT = 3,
    // sent from daemon
    ZYGOTE_INJECTED = 4,
    DAEMON_SET_INFO = 5,
    DAEMON_SET_ERROR_INFO = 6,
    SYSTEM_SERVER_STARTED = 7,
    // Arm against an already-running system: refresh the daemon's module snapshot and
    // live-attach to whichever of zygote and system_server are up but not yet injected.
    // This is the single late-start entry point, whether it arrives from a KernelSU
    // late-load stage script or from a root shell on a build with no root solution.
    REARM = 8
};

/// The name a command is logged under. Values off the socket may be none of them.
inline const char *name_of(Command cmd) {
    switch (cmd) {
    case START:
        return "start";
    case STOP:
        return "stop";
    case EXIT:
        return "exit";
    case ZYGOTE_INJECTED:
        return "zygote_injected";
    case DAEMON_SET_INFO:
        return "daemon_set_info";
    case DAEMON_SET_ERROR_INFO:
        return "daemon_set_error_info";
    case SYSTEM_SERVER_STARTED:
        return "system_server_started";
    case REARM:
        return "rearm";
    default:
        return "unknown";
    }
}

/// What a rearm achieved, as the monitor reports it to whoever asked for one. Sent over the
/// control socket as a single byte, so the values are part of that protocol.
enum class RearmResult : uint8_t {
    Failed = 0,
    /// Nothing is up yet. The monitor is seized on init and will catch zygote at exec.
    NoZygote,
    /// A bare zygote was injected and the daemon answered its heartbeat.
    Armed,
    /// Every zygote already carries hooks this monitor's daemon confirmed.
    AlreadyArmed,
    /// A zygote carries our library with no hooks to show for it. Nothing can be injected
    /// over that, so only a zygote restart clears it.
    NeedsRestart,
};

inline const char *name_of(RearmResult result) {
    switch (result) {
    case RearmResult::NoZygote:
        return "no zygote";
    case RearmResult::Armed:
        return "armed";
    case RearmResult::AlreadyArmed:
        return "already armed";
    case RearmResult::NeedsRestart:
        return "needs restart";
    default:
        return "failed";
    }
}

/// Sends one command to the running monitor, retrying briefly. Returns false when no
/// monitor could be reached.
bool send_control_command(Command cmd);

/// Sends `rearm` and waits for the monitor's answer, which it sends once the rearm is done.
/// Returns RearmResult::Failed when no monitor could be reached or none answered in time.
RearmResult send_rearm_command();
