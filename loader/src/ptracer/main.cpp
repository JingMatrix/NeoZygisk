#include "main.hpp"

#include <err.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string_view>

#include "daemon.hpp"  // For GetTmpPath
#include "logging.hpp"
#include "monitor.hpp"

// Use string_view literals for efficient, allocation-free string comparisons.
using namespace std::string_view_literals;

// The main entry point for the monitoring process.
void init_monitor() {
    LOGI("NeoZygisk %s", ZKSU_VERSION);
    LOGI("init monitor started");

    // All logic is now encapsulated in an AppMonitor instance.
    AppMonitor monitor;
    if (!monitor.prepare_environment()) {
        exit(1);
    }
    monitor.run();

    LOGI("exit");
}

// The entry point for the command-line control utility.
void send_control_command(Command cmd) {
    int sockfd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sockfd == -1) err(EXIT_FAILURE, "socket");

    struct sockaddr_un addr{
        .sun_family = AF_UNIX,
        .sun_path = {0},
    };
    sprintf(addr.sun_path, "%s/%s", zygiskd::GetTmpPath().c_str(), AppMonitor::SOCKET_NAME);
    socklen_t socklen = sizeof(sa_family_t) + strlen(addr.sun_path);

    auto nsend = sendto(sockfd, (void *) &cmd, sizeof(cmd), 0, (sockaddr *) &addr, socklen);
    if (nsend == -1) {
        err(EXIT_FAILURE, "send");
    } else if (nsend != sizeof(cmd)) {
        fprintf(stderr, "send %zu != %zu\n", nsend, sizeof(cmd));
        exit(1);
    }
    printf("command sent\n");
    close(sockfd);
}

// --- Command Handler Declarations ---

static void print_usage(const char *tool_name);
static int handle_monitor();
static int handle_trace(int argc, char **argv);
static int handle_ctl(int argc, char **argv);
static int handle_version();

/**
 * @brief Main entry point for the NeoZygisk command-line interface.
 *
 * This function acts as a dispatcher, parsing the first command-line argument
 * to determine the desired mode of operation (e.g., monitor, trace, ctl)
 * and delegating the work to a corresponding handler function.
 */
int main(int argc, char **argv) {
    // This initialization is for the daemon's internal logic, not for CLI output.
    zygiskd::Init(getenv("TMP_PATH"));

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
            "usage: %s monitor | trace <pid> [--restart] | ctl <start|stop|exit> | version\n",
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

    // Handle optional --restart flag.
    if (argc >= 4 && argv[3] == "--restart"sv) {
        printf("zygote restart requested...\n");
        zygiskd::ZygoteRestart();
    }

    if (!trace_zygote(pid)) {
        fprintf(stderr,
                "error: failed to trace zygote, killing process %d to prevent system instability\n",
                pid);
        kill(pid, SIGKILL);
        return EXIT_FAILURE;
    }

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
        fprintf(stderr, "error: ctl command requires an action (start|stop|exit)\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const auto action = std::string_view(argv[2]);
    printf("sending control command: '%s'\n", argv[2]);

    if (action == "start"sv) {
        send_control_command(START);
    } else if (action == "stop"sv) {
        send_control_command(STOP);
    } else if (action == "exit"sv) {
        send_control_command(EXIT);
    } else {
        fprintf(stderr, "error: unknown ctl action: '%s'\n", argv[2]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
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
