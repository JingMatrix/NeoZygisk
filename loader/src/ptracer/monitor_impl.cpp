#include <fcntl.h>
#include <linux/eventpoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <sstream>

#include "daemon.hpp"
#include "files.hpp"
#include "logging.hpp"
#include "monitor.hpp"
#include "utils.hpp"

// --- AppMonitor Method Implementations ---

AppMonitor::AppMonitor()
    : event_loop_(),
      socket_handler_(*this),
      ptrace_handler_(*this),
#if defined(__LP64__)
      zygote_(*this, true),
#else
      zygote_(*this, false),
#endif
      tracing_state_(TRACING) {
}

ZygoteAbiManager &AppMonitor::get_abi_manager() { return zygote_; }

TracingState AppMonitor::get_tracing_state() const { return tracing_state_; }

void AppMonitor::set_tracing_state(TracingState state) { tracing_state_ = state; }

void AppMonitor::write_abi_status_section(std::string &status_text, const Status &daemon_status) {
    auto abi_name = this->zygote_.abi_name_;
    if (daemon_status.supported) {
        status_text += "\tzygote";
        status_text += abi_name;
        status_text += ":";
        if (tracing_state_ != TRACING)
            status_text += "\t❓ unknown";
        else if (daemon_status.zygote_injected)
            status_text += "\t😋 injected";
        else
            status_text += "\t❌ not injected";
        status_text += "\n\tdaemon";
        status_text += abi_name;
        status_text += ":";
        if (daemon_status.daemon_running) {
            status_text += "\t😋 running";
            if (!daemon_status.daemon_info.empty()) {
                status_text += "\n";
                status_text += daemon_status.daemon_info;
            }
        } else {
            status_text += "\t❌ crashed";
            if (!daemon_status.daemon_error_info.empty()) {
                status_text += "(";
                status_text += daemon_status.daemon_error_info;
                status_text += ")";
            }
        }
    }
}

void AppMonitor::update_status() {
    auto prop_file = xopen_file(prop_path_.c_str(), "w");
    if (!prop_file) {
        PLOGE("open module.prop");
        return;
    }

    // Build the middle section of the status text.
    std::string status_text = "\tmonitor: \t";
    switch (tracing_state_) {
    case TRACING:
        status_text += "😋 tracing";
        break;
    case STOPPING:
        [[fallthrough]];
    case STOPPED:
        status_text += "❌ stopped";
        break;
    case EXITING:
        status_text += "❌ exited";
        break;
    }
    if (tracing_state_ != TRACING && !monitor_stop_reason_.empty()) {
        status_text += "(";
        status_text += monitor_stop_reason_;
        status_text += ")";
    }

    // Build the full content in a single stringstream for clarity.
    std::stringstream ss;
    ss << pre_section_ << "\n" << status_text << "\n\n";

    std::string abi_section;
    write_abi_status_section(abi_section, zygote_.get_status());

    ss << abi_section << "\n\n" << post_section_;

    std::string final_output = ss.str();
    fwrite(final_output.c_str(), 1, final_output.length(), prop_file.get());
}

bool AppMonitor::prepare_environment() {
    prop_path_ = zygiskd::GetTmpPath() + "/module.prop";
    close(open(prop_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644));
    auto orig_prop = xopen_file("./module.prop", "r");
    if (orig_prop == nullptr) {
        PLOGE("open original prop");
        return false;
    }
    bool post = false;
    file_readline(false, orig_prop.get(), [&](std::string_view line) -> bool {
        if (line.starts_with("updateJson=")) return true;
        if (line.starts_with("description=")) {
            post = true;
            post_section_ += line.substr(sizeof("description"));
        } else {
            (post ? post_section_ : pre_section_) += "\t";
            (post ? post_section_ : pre_section_) += line;
        }
        return true;
    });
    update_status();
    return true;
}

void AppMonitor::run() {
    socket_handler_.Init();
    ptrace_handler_.Init();
    event_loop_.Init();
    event_loop_.RegisterHandler(socket_handler_, EPOLLIN | EPOLLET);
    event_loop_.RegisterHandler(ptrace_handler_, EPOLLIN | EPOLLET);
    event_loop_.Loop();
}

void AppMonitor::request_start() {
    if (tracing_state_ == STOPPING)
        tracing_state_ = TRACING;
    else if (tracing_state_ == STOPPED) {
        ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK);
        LOGI("start tracing init");
        tracing_state_ = TRACING;
    }
    update_status();
}

void AppMonitor::request_stop(std::string reason) {
    if (tracing_state_ == TRACING) {
        LOGI("stop tracing requested");
        tracing_state_ = STOPPING;
        monitor_stop_reason_ = std::move(reason);
        ptrace(PTRACE_INTERRUPT, 1, 0, 0);
        update_status();
    }
}

void AppMonitor::request_exit() {
    LOGI("prepare for exit ...");
    tracing_state_ = EXITING;
    monitor_stop_reason_ = "user requested";
    update_status();
    event_loop_.Stop();
}

void AppMonitor::notify_init_detached() {
    tracing_state_ = STOPPED;
    LOGI("stop tracing init");
}

// --- SocketHandler Method Implementations ---

int AppMonitor::SocketHandler::GetFd() { return sock_fd_; }
AppMonitor::SocketHandler::~SocketHandler() {
    if (sock_fd_ >= 0) close(sock_fd_);
}

bool AppMonitor::SocketHandler::Init() {
    sock_fd_ = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (sock_fd_ == -1) {
        PLOGE("socket create");
        return false;
    }
    struct sockaddr_un addr{
        .sun_family = AF_UNIX,
        .sun_path = {0},
    };
    sprintf(addr.sun_path, "%s/%s", zygiskd::GetTmpPath().c_str(), AppMonitor::SOCKET_NAME);
    socklen_t socklen = sizeof(sa_family_t) + strlen(addr.sun_path);
    if (bind(sock_fd_, (struct sockaddr *) &addr, socklen) == -1) {
        PLOGE("bind socket");
        return false;
    }
    return true;
}

void AppMonitor::SocketHandler::HandleEvent([[maybe_unused]] EventLoop &loop, uint32_t) {
    for (;;) {
        buf_.resize(sizeof(MsgHead));
        MsgHead &msg_header = *reinterpret_cast<MsgHead *>(buf_.data());
        ssize_t nread = recv(sock_fd_, &msg_header, sizeof(MsgHead), MSG_PEEK | MSG_TRUNC);
        if (nread == -1) {
            if (errno == EAGAIN) break;
            PLOGE("SocketHandler: recv(peek)");
            continue;
        }
        ssize_t real_size;
        if (msg_header.cmd >= Command::DAEMON_SET_INFO &&
            msg_header.cmd != Command::SYSTEM_SERVER_STARTED) {
            if (static_cast<size_t>(nread) < sizeof(MsgHead)) {
                LOGE("SocketHandler: received incomplete header for cmd %d, size %zd",
                     msg_header.cmd, nread);
                recv(sock_fd_, buf_.data(), buf_.size(), 0);
                continue;
            }
            real_size = sizeof(MsgHead) + msg_header.length;
        } else {
            if (static_cast<size_t>(nread) != sizeof(Command)) {
                LOGE("SocketHandler: received invalid size for cmd %d, size %zd", msg_header.cmd,
                     nread);
                recv(sock_fd_, buf_.data(), buf_.size(), 0);
                continue;
            }
            real_size = sizeof(Command);
        }
        buf_.resize(real_size);
        MsgHead &full_msg = *reinterpret_cast<MsgHead *>(buf_.data());
        nread = recv(sock_fd_, &full_msg, real_size, 0);
        if (nread == -1) {
            PLOGE("recv(read)");
            continue;
        }
        if (nread != real_size) {
            LOGE("SocketHandler: expected %zd bytes, but received %zd", real_size, nread);
            continue;
        }

        switch (full_msg.cmd) {
        case START:
            monitor_.request_start();
            break;
        case STOP:
            monitor_.request_stop("user requested");
            break;
        case EXIT:
            monitor_.request_exit();
            break;
        case ZYGOTE_INJECTED:
            monitor_.get_abi_manager().notify_injected();
            monitor_.update_status();
            break;
        case DAEMON_SET_INFO:
            monitor_.get_abi_manager().set_daemon_info({full_msg.data, (size_t) full_msg.length});
            monitor_.update_status();
            break;
        case DAEMON_SET_ERROR_INFO:
            monitor_.get_abi_manager().set_daemon_crashed(
                {full_msg.data, (size_t) full_msg.length});
            monitor_.update_status();
            break;
        case SYSTEM_SERVER_STARTED:
            LOGV("system server started, module.prop updated");
            break;
        }
    }
}

// --- SigChldHandler Method Implementations ---

int AppMonitor::SigChldHandler::GetFd() { return signal_fd_; }
AppMonitor::SigChldHandler::~SigChldHandler() {
    if (signal_fd_ >= 0) close(signal_fd_);
}

bool AppMonitor::SigChldHandler::Init() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
        PLOGE("set sigprocmask");
        return false;
    }
    signal_fd_ = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_fd_ == -1) {
        PLOGE("create signalfd");
        return false;
    }
    ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK);
    return true;
}

/**
 * @brief The central dispatcher for process state changes and signal handling.
 *
 * This method is the primary entry point for the monitoring logic.
 * It is invoked by the `EventLoop` when the underlying `signalfd` becomes readable,
 * indicating that the kernel has delivered one or more `SIGCHLD` signals.
 *
 * Its responsibility is to consume the signal notification, reap all pending process
 * events using `waitpid`, and dispatch them according to the new hierarchical architecture.
 *
 * @section Architecture: Hierarchical Monitoring
 *
 * To support complex boot chains (e.g., `init -> stub -> zygote`), this handler implements
 * a recursive monitoring strategy rather than a flat list. It categorizes processes into
 * four distinct roles and processes them in strict priority order:
 *
 * 1.  Process Factories (Init & Stubs)
 *     - Criteria: PID is `1` (init) OR present in `stub_processes_`.
 *     - Role: These are parent nodes in the process tree.
 *     - Action: Delegated to `handleParentEvent()`. We monitor these processes
 *       primarily for `PTRACE_EVENT_FORK` to discover new children (potential Zygotes)
 *       or, in the case of stubs, for their termination.
 *
 * 2.  Helper Daemons
 *     - Criteria: PID matches a known `zygiskd` instance.
 *     - Role: Self-monitoring mechanism.
 *     - Action: Checks if the daemon has crashed or exited unexpectedly and
 *       updates the global status accordingly.
 *
 * 3.  Transitioning Candidates
 *     - Criteria: PID is present in the `process_` set.
 *     - Role: These are newly forked children whose identity is not yet established.
 *       They are being traced while waiting for an `execve` syscall.
 *     - Action: Delegated to `handleTracedProcess()`. This determines if the
 *       process has become a Zygote (triggering injection), an intermediate Stub
 *       (triggering promotion to a Process Factory), or an irrelevant process
 *       (triggering detachment).
 *
 * 4.  New Discoveries
 *     - Criteria: PID is unknown.
 *     - Role: Unexpected or previously unobserved children of a monitored parent.
 *     - Action: Delegated to `handleNewProcess()`. The monitor attaches via
 *       `ptrace` with `PTRACE_O_TRACEEXEC` and adds the PID to the candidate set
 *       (`process_`) to await its biological identity.
 */
void AppMonitor::SigChldHandler::HandleEvent(EventLoop &, uint32_t) {
    for (;;) {
        struct signalfd_siginfo fdsi;
        ssize_t s = read(signal_fd_, &fdsi, sizeof(fdsi));
        if (s == -1) {
            if (errno == EAGAIN) break;
            PLOGE("read signalfd");
            continue;
        }
        if (s != sizeof(fdsi) || fdsi.ssi_signo != SIGCHLD) {
            continue;
        }

        int pid;
        while ((pid = waitpid(-1, &status_, __WALL | WNOHANG)) > 0) {
            handleChildEvent(pid, status_);
        }
        if (pid == -1 && errno != ECHILD && monitor_.get_tracing_state() != STOPPED) {
            PLOGE("waitpid");
        }
    }
}

/**
 * @brief The primary dispatcher for child process state changes.
 *
 * This function routes signals caught by waitpid() to the appropriate specialized
 * handler based on the process's current role in our monitoring hierarchy.
 */
void AppMonitor::SigChldHandler::handleChildEvent(int pid, int &status) {
    // Role 1: Process Factories (Init and Stub Zygotes)
    // These processes are monitored for PTRACE_EVENT_FORK to discover new children.
    if (pid == 1 || stub_processes_.count(pid)) {
        handleParentEvent(pid, status);
        return;
    }

    // Role 2: Helper Daemons
    // Check if this is one of our own zygiskd daemon instances exiting.
    if (monitor_.get_abi_manager().handle_daemon_exit_if_match(pid, status)) {
        return;
    }

    // Role 3 & 4: Transitioning Candidates and New Discoveries
    // If the process is known to be in the pre-exec stage, evaluate its state.
    // Otherwise, treat it as a newly discovered process.
    if (process_.count(pid)) {
        handleTracedProcess(pid, status);
    } else {
        handleNewProcess(pid);
    }
}

/**
 * @brief Handles events for parent processes (Init and Stub Zygotes).
 *
 * This handler manages the discovery of new processes via fork() and acts as a
 * shield to protect fragile parent processes (like stub_zygote) from kernel
 * signals generated by our ptrace manipulation of their children.
 */
void AppMonitor::SigChldHandler::handleParentEvent(int pid, int &status) {
    // Case 1: The parent successfully forked a new child.
    if (stopped_with(status, SIGTRAP, PTRACE_EVENT_FORK)) {
        long child_pid;
        if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid) != -1) {
            LOGV("parent %d forked %ld", pid, child_pid);
        } else {
            PLOGE("geteventmsg on parent %d", pid);
        }
    }
    // Case 2: Init has paused in response to our PTRACE_INTERRUPT stop request.
    else if (pid == 1 && stopped_with(status, SIGTRAP, PTRACE_EVENT_STOP) &&
             monitor_.get_tracing_state() == STOPPING) {
        LOGI("init process safely paused, detaching");
        if (ptrace(PTRACE_DETACH, 1, 0, 0) == -1) PLOGE("detach init failed");
        monitor_.notify_init_detached();
        return;
    }
    // Case 3: An intermediate stub process died naturally or crashed.
    else if (pid != 1 && (WIFEXITED(status) || WIFSIGNALED(status))) {
        LOGI("stub process %d exited (status: %d)", pid, status);
        stub_processes_.erase(pid);
        return;
    }

    // Case 4: The parent was stopped by a standard POSIX signal.
    // We must act as a proxy: deciding whether to suppress the signal or inject it back.
    if (WIFSTOPPED(status)) {
        // WPTEVENT == 0 guarantees this is a standard signal, not a ptrace internal event.
        if (WPTEVENT(status) == 0) {
            int sig = WSTOPSIG(status);

            // Suppress job-control signals.
            // Injecting these back would physically freeze the parent process,
            // causing the entire boot chain to hang.
            if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
                LOGW("suppressing stop signal %s (%d) sent to parent %d", sigabbrev_np(sig), sig,
                     pid);
            }
            // Protect stub_zygote from SIGCHLD.
            // When we freeze/resume its child for injection, the kernel sends SIGCHLD to the stub.
            // By remaining attached and dropping the signal here, the stub remains safely ignorant.
            else if (pid != 1 && sig == SIGCHLD) {
                LOGV("shielding stub process %d from SIGCHLD to prevent native crash", pid);
            }
            // Pass all other signals (like SIGTERM, SIGUSR1) back to the process unaltered.
            else {
                LOGW("passing signal %s (%d) through to parent %d", sigabbrev_np(sig), sig, pid);
                ptrace(PTRACE_CONT, pid, 0, sig);
                return;
            }
        }

        // Resume the process for suppressed signals or any other benign ptrace stops.
        ptrace(PTRACE_CONT, pid, 0, 0);
    }
}

/**
 * @brief Registers and prepares a newly discovered process for execve tracking.
 */
void AppMonitor::SigChldHandler::handleNewProcess(int pid) {
    LOGV("new process %d discovered and attached", pid);
    process_.emplace(pid);

    // Instruct the kernel to stop this process and notify us when it calls execve().
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC) == -1) {
        PLOGE("set PTRACE_O_TRACEEXEC on new process %d", pid);
    }

    // Always resume the process.
    ptrace(PTRACE_CONT, pid, 0, 0);
}

/**
 * @brief Evaluates the state of processes waiting to execute a program.
 *
 * This handler manages the critical race condition window between a process
 * being forked and it calling execve().
 */
void AppMonitor::SigChldHandler::handleTracedProcess(int pid, int &status) {
    bool keep_attached = false;

    // The process has called execve(). We must now identify it.
    if (stopped_with(status, SIGTRAP, PTRACE_EVENT_EXEC)) {
        keep_attached = handleExecEvent(pid, status);
    }
    // The kernel auto-attaches the forked child and pauses it with PTRACE_EVENT_STOP.
    else if (stopped_with(status, SIGTRAP, PTRACE_EVENT_STOP)) {
        LOGV("process %d acknowledged auto-attach trap, configuring execve tracking", pid);

        // Safely apply the execve trap now that the process is guaranteed stopped and reaped.
        if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC) == -1) {
            PLOGE("set PTRACE_O_TRACEEXEC on process %d", pid);
        }

        ptrace(PTRACE_CONT, pid, 0, 0);
        keep_attached = true;
    }
    // Unexpected state during the pre-exec phase.
    else {
        LOGW("traced process %d stopped with unexpected status: %s", pid,
             parse_status(status).c_str());
    }

    // Determine lifecycle routing based on the handlers above.
    if (keep_attached) {
        // If handleExecEvent promoted it to a stub or initiated injection,
        // it no longer belongs in the pre-exec candidate pool.
        if (stopped_with(status, SIGTRAP, PTRACE_EVENT_EXEC)) {
            process_.erase(pid);
        }
        return;
    }

    // If the process is irrelevant (e.g., a random system daemon), clean up and detach.
    process_.erase(pid);
    if (WIFSTOPPED(status)) {
        LOGV("detaching irrelevant process %d", pid);
        ptrace(PTRACE_DETACH, pid, 0, 0);
    }
}

/**
 * @brief Identifies the biological identity of a process post-execve.
 *
 * @return true if the process was promoted (Stub) or handed off (Zygote).
 *         false if the process is irrelevant and should be detached.
 */
bool AppMonitor::SigChldHandler::handleExecEvent(int pid, int &status) {
    auto program = get_program(pid);
    LOGV("process %d executed program: %s", pid, program.c_str());

    bool handled = false;

    do {
        // --- Intermediate Stub Identification ---
        // If this program is a stub_zygote, we must promote it to a Process Factory.
        // It will remain attached forever so we can shield it from SIGCHLD.
        if (program.find("stub_zygote") != std::string::npos) {
            LOGI("detected stub zygote at %d, promoting to parent monitor", pid);
            stub_processes_.insert(pid);

            // Upgrade tracing options to catch when it forks the real zygote.
            ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC);
            ptrace(PTRACE_CONT, pid, 0, 0);

            handled = true;
            break;
        }

        // --- Zygote Target Validation ---
        if (monitor_.get_tracing_state() != TRACING) {
            LOGW("ignoring potential target %d because tracing state is STOPPED", pid);
            break;
        }

        if (program != monitor_.get_abi_manager().program_path_) {
            break;  // Irrelevant program, exit block and return false.
        }

        const char *tracer = monitor_.get_abi_manager().check_and_prepare_injection();
        if (tracer == nullptr) {
            LOGE("failed to prepare injector for target %d", pid);
            break;
        }

        // --- Zygote Handover Sequence ---
        LOGV("intercepted target zygote %d, halting for injector hand-off", pid);

        // Force the process into a standard SIGSTOP state.
        kill(pid, SIGSTOP);
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, __WALL);

        if (stopped_with(status, SIGSTOP, 0)) {
            LOGV("target %d halted, detaching monitor to allow injector seize", pid);

            // Detach, but leave the process frozen (SIGSTOP) for the injector daemon.
            if (ptrace(PTRACE_DETACH, pid, 0, SIGSTOP) == -1) {
                PLOGE("detach target %d", pid);
            }

            // Fork and execute the external injector daemon.
            auto p = fork_dont_care();
            if (p == 0) {
                execl(tracer, basename(tracer), "trace", std::to_string(pid).c_str(), "--restart",
                      nullptr);
                PLOGE("execute injector daemon");
                kill(pid, SIGKILL);
                _exit(1);
            } else if (p == -1) {
                PLOGE("fork injector daemon");
                kill(pid, SIGKILL);
            }

            handled = true;
        } else {
            LOGE("target %d failed to enter SIGSTOP, status: %s", pid,
                 parse_status(status).c_str());
        }

    } while (false);

    // Ensure state transitions (like zygote_injected flags) are flushed to disk.
    monitor_.update_status();
    return handled;
}
