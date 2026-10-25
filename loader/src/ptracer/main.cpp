#include "main.hpp"

#include <err.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>

#include "daemon.hpp"  // For GetTmpPath
#include "logging.hpp"
#include "monitor.hpp"

// Use string_view literals for efficient, allocation-free string comparisons.
using namespace std::string_view_literals;

const char *const kWorkDirectory = WORK_DIRECTORY;

// Fills in the address of the monitor's control socket.
static void control_socket_addr(struct sockaddr_un &addr, socklen_t &socklen) {
    addr.sun_family = AF_UNIX;
    memset(addr.sun_path, 0, sizeof(addr.sun_path));
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", zygiskd::GetTmpPath().c_str(),
             AppMonitor::SOCKET_NAME);
    socklen = sizeof(sa_family_t) + strlen(addr.sun_path);
}

/**
 * @brief Reports whether a monitor is currently bound to the control socket.
 *
 * The socket file outlives whoever bound it, so its presence proves nothing. Connecting a
 * datagram socket to the path does: it succeeds only while a process holds the name, and
 * fails with ECONNREFUSED once that process is gone. This is what keeps the single-owner
 * invariant in the monitor rather than in each caller -- every entry point may simply try
 * to start one, and a redundant monitor steps aside instead of fighting over init.
 */
static bool monitor_is_running() {
    int sockfd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd == -1) return false;

    struct sockaddr_un addr{};
    socklen_t socklen;
    control_socket_addr(addr, socklen);

    bool alive = connect(sockfd, (sockaddr *) &addr, socklen) == 0;
    close(sockfd);
    return alive;
}

// The main entry point for the monitoring process.
void init_monitor() {
    LOGI("NeoZygisk %s", ZKSU_VERSION);

    // Exactly one monitor may exist: two would both seize init and race over the same
    // control socket and status file. Checking here, before prepare_environment(), keeps
    // a redundant monitor from rewriting the status file on its way out. Every bootstrap
    // path can therefore just start one unconditionally.
    if (monitor_is_running()) {
        LOGI("another monitor already owns the control socket, exiting");
        return;
    }

    // All logic is now encapsulated in an AppMonitor instance.
    AppMonitor monitor;
    if (!monitor.prepare_environment()) {
        exit(1);
    }
    monitor.run();

    LOGI("exit");
}

// The entry point for the command-line control utility. Returns false if no monitor could
// be reached within the retry budget.
bool send_control_command(Command cmd) {
    // A caller may arrive while the monitor it depends on is still starting: on the
    // late-load path the bootstrap stage backgrounds the monitor and a later stage sends
    // `rearm`, with only the mount step in between. Retry rather than make every caller
    // implement its own wait, but keep the budget short so a genuinely absent monitor is
    // reported promptly.
    constexpr int kRetries = 10;
    constexpr useconds_t kRetryDelayUs = 200 * 1000;

    struct sockaddr_un addr{};
    socklen_t socklen;
    control_socket_addr(addr, socklen);

    for (int attempt = 0; attempt < kRetries; ++attempt) {
        if (attempt > 0) usleep(kRetryDelayUs);

        int sockfd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (sockfd == -1) {
            warn("socket");
            continue;
        }

        auto nsend = sendto(sockfd, (void *) &cmd, sizeof(cmd), 0, (sockaddr *) &addr, socklen);
        int saved_errno = errno;
        close(sockfd);

        if (nsend == static_cast<ssize_t>(sizeof(cmd))) {
            printf("command sent\n");
            return true;
        }
        if (nsend != -1) {
            fprintf(stderr, "send %zd != %zu\n", nsend, sizeof(cmd));
            return false;
        }
        // ENOENT: the work directory has no socket yet. ECONNREFUSED: the file is there
        // but unbound, so the previous owner is gone. Both are worth waiting out.
        if (saved_errno != ENOENT && saved_errno != ECONNREFUSED) {
            errno = saved_errno;
            warn("send");
            return false;
        }
    }

    fprintf(stderr, "error: no monitor is listening on the control socket\n");
    return false;
}

// --- Command Handler Declarations ---

static void print_usage(const char *tool_name);
static int handle_monitor();
static int handle_trace(int argc, char **argv);
static int handle_ctl(int argc, char **argv);
static int handle_version();

// Global variable so our signal handler knows which PID to rescue. sig_atomic_t because
// the handler runs asynchronously with the assignments below.
static volatile sig_atomic_t g_traced_pid = 0;

/**
 * @brief Signal handler to safely detach and resume Zygote if the user
 *        interrupts the standalone tracer (e.g., Ctrl+C).
 */
static void handle_interrupt(int sig) {
    if (g_traced_pid > 0) {
        printf("\n[!] received signal %d, safely detaching from PID %d to prevent crash...\n", sig,
               (int) g_traced_pid);

        // PTRACE_DETACH with SIGCONT ensures the process resumes execution
        ptrace(PTRACE_DETACH, (pid_t) g_traced_pid, 0, SIGCONT);
    }
    _exit(EXIT_FAILURE);
}

/**
 * @brief Main entry point for the NeoZygisk command-line interface.
 *
 * This function acts as a dispatcher, parsing the first command-line argument
 * to determine the desired mode of operation (e.g., monitor, trace, ctl)
 * and delegating the work to a corresponding handler function.
 */
int main(int argc, char **argv) {
    // This initialization is for the daemon's internal logic, not for CLI output.
    zygiskd::Init(kWorkDirectory);

    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Delegate to the appropriate handler based on the command.
    const auto command = std::string_view(argv[1]);
    if (command == "monitor"sv) {
        return handle_monitor();
    } else if (command == "trace"sv) {
        return handle_trace(argc, argv);
    } else if (command == "ctl"sv) {
        return handle_ctl(argc, argv);
    } else if (command == "version"sv) {
        return handle_version();
    } else {
        fprintf(stderr, "error: unknown command '%s'\n", argv[1]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
}

/**
 * @brief Prints the tool's version and usage information to standard error.
 *        Usage is typically printed in response to an error.
 * @param tool_name The name of the executable, typically argv[0].
 */
static void print_usage(const char *tool_name) {
    fprintf(stderr, "NeoZygisk Tracer %s\n", ZKSU_VERSION);
    fprintf(stderr,
            "usage: %s monitor | trace <pid> [--spawn | --standalone | --system_server] | ctl "
            "<start|stop|exit|rearm> | version\n",
            tool_name);
}

/**
 * @brief Handles the 'monitor' command.
 *
 * Initializes the Zygote monitoring daemon.
 */
static int handle_monitor() {
    printf("starting monitor mode...\n");
    init_monitor();
    // This function is long-running and typically won't return here.
    return EXIT_SUCCESS;
}

/**
 * @brief Handles the 'trace' command.
 *
 * Parses the PID and optional flags, then initiates the ptrace injection.
 */
static int handle_trace(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "error: trace command requires a PID\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // --- Robust PID Parsing ---
    char *end_ptr;
    errno = 0;  // Reset errno before the call
    long pid_val = strtol(argv[2], &end_ptr, 10);

    // Validate the conversion
    if (*end_ptr != '\0' || errno != 0 || pid_val <= 0) {
        fprintf(stderr, "error: invalid PID specified: '%s'\n", argv[2]);
        return EXIT_FAILURE;
    }
    pid_t pid = static_cast<pid_t>(pid_val);
    printf("preparing to trace PID: %d\n", pid);

    // --- Flag Parsing ---
    TraceMode mode = TraceMode::UNKNOWN;

    if (argc >= 4) {
        const auto flag = std::string_view(argv[3]);
        if (flag == "--spawn"sv) {
            mode = TraceMode::SPAWN;
        } else if (flag == "--standalone"sv) {
            mode = TraceMode::STANDALONE;
        } else if (flag == "--system_server"sv) {
            mode = TraceMode::SYSTEM_SERVER;
        } else {
            fprintf(stderr, "error: unknown flag: '%s'\n", argv[3]);
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    // --- Signal Handling for safe exit ---
    g_traced_pid = pid;
    signal(SIGINT, handle_interrupt);
    signal(SIGTERM, handle_interrupt);

    // --- Flag Execution ---
    const char *target = "zygote";
    if (mode == TraceMode::SPAWN) {
        printf("reporting zygote restart...\n");
        zygiskd::ZygoteRestart();
    } else if (mode == TraceMode::STANDALONE) {
        printf("standalone mode: injecting into the running zygote...\n");
        // No daemon is started here. Every mode now runs under a monitor that already owns
        // the control socket and zygiskd, and `ctl rearm` is what drives this mode, so the
        // tracer is a plain injector in all three cases. Running this by hand therefore
        // needs a monitor first -- which is exactly what `ctl rearm` asks for.
    } else if (mode == TraceMode::SYSTEM_SERVER) {
        target = "system_server";
        printf("injecting into system_server\n");
    }

    // Note on the heartbeat race: the tracee may reach zygiskd::PingHeartbeat() before the
    // monitor's zygiskd has bound the control socket. This is covered by the retry budget
    // in zygiskd::Connect() -- PingHeartbeat uses Connect(5), i.e. four one-second retries
    // -- which comfortably outlasts a fork+exec of zygiskd. The retries run inside the
    // ptrace-stopped tracee, so the only cost of losing the race is a short stall.
    if (!trace_target(pid, mode)) {
        // Resume the target uninjected rather than killing it, in every mode. A SPAWN
        // target is parked in SIGSTOP by the monitor, so it must be released or the boot
        // hangs; killing it instead feeds a zygote restart loop, which Android's
        // RescueParty answers by rebooting into the "wipe data" prompt. One boot without
        // modules is a far better outcome. The redundant kill() covers a trace_target()
        // that failed before it ever attached, where the ptrace request cannot deliver the
        // signal.
        fprintf(stderr, "error: failed to trace %s, resuming process %d uninjected\n", target, pid);
        ptrace(PTRACE_DETACH, pid, 0, SIGCONT);
        kill(pid, SIGCONT);
        return EXIT_FAILURE;
    }

    // Success, reset the global PID so we don't accidentally send signals on exit
    g_traced_pid = 0;
    printf("successfully attached and injected into PID: %d\n", pid);
    return EXIT_SUCCESS;
}

/**
 * @brief Handles the 'ctl' (control) command.
 *
 * Sends a control command to a running daemon instance.
 */
static int handle_ctl(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "error: ctl command requires an action (start|stop|exit|rearm)\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const auto action = std::string_view(argv[2]);
    printf("sending control command: '%s'\n", argv[2]);

    Command cmd;
    if (action == "start"sv) {
        cmd = START;
    } else if (action == "stop"sv) {
        cmd = STOP;
    } else if (action == "exit"sv) {
        cmd = EXIT;
    } else if (action == "rearm"sv) {
        cmd = REARM;
    } else {
        fprintf(stderr, "error: unknown ctl action: '%s'\n", argv[2]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Report delivery, so a stage script can tell "the monitor acted on this" from "there
    // was no monitor to tell". The command itself is fire-and-forget past this point.
    return send_control_command(cmd) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * @brief Handles the 'version' command.
 *
 * Prints the tool's version number to standard output.
 */
static int handle_version() {
    printf("NeoZygisk Tracer %s\n", ZKSU_VERSION);
    return EXIT_SUCCESS;
}
