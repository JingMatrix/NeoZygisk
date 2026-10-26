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
#include "stage.hpp"
#include "utils.hpp"

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

// Connecting a datagram socket to the path succeeds only while a process holds the name,
// and fails with ECONNREFUSED once that process is gone. This keeps the single-owner rule
// in the monitor rather than in each caller: every entry point may just start one.
bool monitor_is_running() {
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
    LOGI("monitor starting, NeoZygisk %s", ZKSU_VERSION);

    // Two monitors would both seize init and race over the socket and status file.
    // Checked before prepare_environment(), so a redundant one rewrites nothing.
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

// A caller can arrive while the monitor it depends on is still starting: the late-load
// stage backgrounds it and the next stage sends `rearm`. Short budget, so a monitor that
// is genuinely absent is reported promptly.
static constexpr int kSendRetries = 10;
static constexpr useconds_t kSendRetryDelayUs = 200 * 1000;

// A rearm waits for each injection it makes, and an unanswered heartbeat costs five
// seconds of that. Worth waiting for: nothing outside the monitor knows what it achieved.
static constexpr int kAnswerTimeoutSec = 30;

/// Sends one command on \p sockfd, retrying while the monitor is still coming up. Returns
/// false when none could be reached within the budget.
static bool send_to_monitor(int sockfd, Command cmd) {
    struct sockaddr_un addr{};
    socklen_t socklen;
    control_socket_addr(addr, socklen);

    for (int attempt = 0; attempt < kSendRetries; ++attempt) {
        if (attempt > 0) usleep(kSendRetryDelayUs);

        auto nsend = sendto(sockfd, (void *) &cmd, sizeof(cmd), 0, (sockaddr *) &addr, socklen);
        if (nsend == static_cast<ssize_t>(sizeof(cmd))) return true;
        if (nsend != -1) {
            fprintf(stderr, "send %zd != %zu\n", nsend, sizeof(cmd));
            return false;
        }
        // ENOENT: the work directory has no socket yet. ECONNREFUSED: the file is there
        // but unbound, so the previous owner is gone. Both are worth waiting out.
        if (errno != ENOENT && errno != ECONNREFUSED) {
            warn("send");
            return false;
        }
    }

    return false;
}

// Returns false if no monitor could be reached within the retry budget.
bool send_control_command(Command cmd) {
    int sockfd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd == -1) {
        warn("socket");
        return false;
    }
    bool sent = send_to_monitor(sockfd, cmd);
    close(sockfd);
    return sent;
}

RearmResult send_rearm_command() {
    int sockfd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd == -1) {
        warn("socket");
        return RearmResult::Failed;
    }

    // An empty path has Linux assign an abstract name of its own. Unnamed, this socket has
    // no address for the monitor to answer at and the verdict would be dropped.
    struct sockaddr_un self{.sun_family = AF_UNIX, .sun_path = {0}};
    struct timeval timeout{.tv_sec = kAnswerTimeoutSec, .tv_usec = 0};
    auto result = RearmResult::Failed;
    if (bind(sockfd, (sockaddr *) &self, sizeof(sa_family_t)) == -1) {
        warn("bind reply socket");
    } else if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
        warn("set the reply timeout");
    } else if (send_to_monitor(sockfd, REARM)) {
        uint8_t answer = 0;
        auto nread = recv(sockfd, &answer, sizeof(answer), 0);
        if (nread == static_cast<ssize_t>(sizeof(answer)) &&
            answer <= static_cast<uint8_t>(RearmResult::NeedsRestart)) {
            result = static_cast<RearmResult>(answer);
        } else if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            fprintf(stderr, "error: the monitor took the rearm but did not answer in %ds\n",
                    kAnswerTimeoutSec);
        } else {
            fprintf(stderr, "error: unreadable answer to the rearm\n");
        }
    }

    close(sockfd);
    return result;
}

// --- Command Handler Declarations ---

static void print_usage(const char *tool_name);
static int handle_monitor();
static int handle_trace(int argc, char **argv);
static int handle_ctl(int argc, char **argv);
static int handle_stage(int argc, char **argv);
static int handle_version();

// Global variable so our signal handler knows which PID to rescue. sig_atomic_t because
// the handler runs asynchronously with the assignments below.
static volatile sig_atomic_t g_traced_pid = 0;

// Detach and resume the target if the tracer is interrupted, Ctrl+C above all.
static void handle_interrupt(int sig) {
    if (g_traced_pid > 0) {
        printf("\n[!] received %s, safely detaching from pid %d to prevent crash\n",
               sigabbrev_np(sig), (int) g_traced_pid);

        // PTRACE_DETACH with SIGCONT ensures the process resumes execution
        ptrace(PTRACE_DETACH, (pid_t) g_traced_pid, 0, SIGCONT);
    }
    _exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    // Read through a pipe, by a manager collecting a stage's output or by adb, where block
    // buffering would hold stdout back until exit and land it after everything on stderr.
    setvbuf(stdout, nullptr, _IOLBF, 0);

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
    } else if (command == "stage"sv) {
        return handle_stage(argc, argv);
    } else if (command == "status"sv) {
        return print_status();
    } else if (command == "help"sv || command == "-h"sv || command == "--help"sv) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    } else if (command == "version"sv) {
        return handle_version();
    } else {
        fprintf(stderr, "error: unknown command '%s'\n", argv[1]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
}

// To stderr, since it usually answers a mistake on the command line.
static void print_usage(const char *tool_name) {
    fprintf(stderr,
            "NeoZygisk Tracer %s\n"
            "\n"
            "usage: %s <command> [<args>]\n"
            "\n"
            "  stage <name> [<options>]     run a boot stage, which is what each of the\n"
            "                               module's shell entry points forwards to:\n"
            "                               post-fs-data, post-mount, service, hotinstall,\n"
            "                               late-load\n"
            "  status                       print what the monitor and the daemon report\n"
            "  monitor                      trace init and inject every zygote it forks\n"
            "  ctl <start|stop|exit|rearm>  send one command to the running monitor\n"
            "  trace <pid> [<mode>]         inject one running process, where mode is\n"
            "                               --spawn, --standalone or --system_server\n"
            "  version                      print the version\n"
            "  help                         print this text\n"
            "\n"
            "stage options, all of them late-load only except where noted:\n"
            "  -i, --ignore-disable         also load modules marked disabled, and run their\n"
            "                               boot scripts (any stage that fans out)\n"
            "  -p, --permissive             set SELinux permissive when the loaded policy is\n"
            "                               missing our rules\n"
            "  -s, --stop                   undo an arm: stop the monitor, and restart zygote\n"
            "                               if it still carries our library\n",
            ZKSU_VERSION, tool_name);
}

static int handle_monitor() {
    printf("starting monitor mode...\n");
    init_monitor();
    return EXIT_SUCCESS;
}

static int handle_trace(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "error: trace command requires a PID\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    char *end_ptr;
    errno = 0;  // Reset errno before the call
    long pid_val = strtol(argv[2], &end_ptr, 10);

    // Validate the conversion
    if (*end_ptr != '\0' || errno != 0 || pid_val <= 0) {
        fprintf(stderr, "error: invalid PID specified: '%s'\n", argv[2]);
        return EXIT_FAILURE;
    }
    pid_t pid = static_cast<pid_t>(pid_val);
    printf("preparing to trace pid %d\n", pid);

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

    g_traced_pid = pid;
    signal(SIGINT, handle_interrupt);
    signal(SIGTERM, handle_interrupt);

    const char *target = "zygote";
    if (mode == TraceMode::SPAWN) {
        printf("reporting zygote restart...\n");
        zygiskd::ZygoteRestart();
    } else if (mode == TraceMode::STANDALONE) {
        printf("standalone mode: injecting into the running zygote...\n");
        // No daemon is started here: every mode runs under a monitor that owns the socket
        // and zygiskd, which leaves the tracer a plain injector. Needs one running first.
    } else if (mode == TraceMode::SYSTEM_SERVER) {
        target = "system_server";
        printf("injecting into system_server\n");
    }

    // The tracee can reach PingHeartbeat() before the monitor's zygiskd has bound its
    // socket. Connect(5)'s four one-second retries outlast a fork+exec of it, and they run
    // inside the ptrace-stopped tracee, so losing that race costs only a stall.
    bool hooked = false;
    if (!trace_target(pid, mode, &hooked)) {
        // Resume the target uninjected rather than killing it, in every mode: a SPAWN
        // target is parked in SIGSTOP and hangs the boot unless released, and killing it
        // feeds a zygote restart loop, which RescueParty answers with the wipe-data
        // prompt. The kill() covers a failure that came before the attach.
        fprintf(stderr, "error: failed to trace %s, resuming process %d uninjected\n", target, pid);
        ptrace(PTRACE_DETACH, pid, 0, SIGCONT);
        kill(pid, SIGCONT);
        return TRACE_FAILED;
    }

    // Success, reset the global PID so we don't accidentally send signals on exit
    g_traced_pid = 0;
    if (!hooked) {
        // The library is in there and cannot be taken back out, so this is not a failure
        // that can be retried: whoever asked for the injection has to restart the target.
        fprintf(stderr,
                "error: pid %d took the library but no daemon answered its heartbeat, so it "
                "carries no hooks\n",
                pid);
        return TRACE_MAPPED_ONLY;
    }
    printf("successfully attached and injected into pid %d\n", pid);
    return TRACE_HOOKED;
}

static int handle_ctl(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "error: ctl command requires an action (start|stop|exit|rearm)\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const auto action = std::string_view(argv[2]);
    printf("sending control command: '%s'\n", argv[2]);

    // Rearm is the one command with something to report, and the monitor answers it once
    // the injection it asks for is done.
    if (action == "rearm"sv) {
        auto result = send_rearm_command();
        if (result == RearmResult::Failed) {
            fprintf(stderr, "error: the rearm was not carried out\n");
            return EXIT_FAILURE;
        }
        printf("rearm done: %s\n", name_of(result));
        return EXIT_SUCCESS;
    }

    Command cmd;
    if (action == "start"sv) {
        cmd = START;
    } else if (action == "stop"sv) {
        cmd = STOP;
    } else if (action == "exit"sv) {
        cmd = EXIT;
    } else {
        fprintf(stderr, "error: unknown ctl action: '%s'\n", argv[2]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (!send_control_command(cmd)) {
        fprintf(stderr, "error: no monitor is listening on the control socket\n");
        return EXIT_FAILURE;
    }
    printf("command sent\n");
    return EXIT_SUCCESS;
}

// The module ships a shell file per stage name, because that is how managers invoke them;
// each forwards here, so the rules live in one place.
static int handle_stage(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "error: stage command requires a name\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const auto name = std::string_view(argv[2]);
    Stage stage;
    if (!parse_stage(name, stage)) {
        fprintf(stderr, "error: unknown stage: '%s'\n", argv[2]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    StageOptions options;
    for (int i = 3; i < argc; ++i) {
        const auto flag = std::string_view(argv[i]);
        if (flag == "-i"sv || flag == "--ignore-disable"sv) {
            options.ignore_disable = true;
        } else if (flag == "-p"sv || flag == "--permissive"sv) {
            options.permissive = true;
        } else if (flag == "-s"sv || flag == "--stop"sv) {
            options.stop = true;
        } else if (flag == "-h"sv || flag == "--help"sv) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        } else {
            fprintf(stderr, "error: unknown stage option: '%s'\n", argv[i]);
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    // Refuse what a stage cannot honour rather than ignoring it: both of these only mean
    // something on the path that a root shell drives.
    if ((options.permissive || options.stop) && stage != Stage::LateLoad) {
        fprintf(stderr, "error: --permissive and --stop apply to the late-load stage only\n");
        return EXIT_FAILURE;
    }

    return run_stage(stage, options);
}

static int handle_version() {
    printf("NeoZygisk Tracer %s\n", ZKSU_VERSION);
    return EXIT_SUCCESS;
}
