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

void AppMonitor::SigChldHandler::handleChildEvent(int pid, int &status) {
    // Check if PID is Init (1) or a known intermediate stub (e.g., stub_zygote)
    if (pid == 1 || stub_processes_.count(pid)) {
        handleParentEvent(pid, status);
        return;
    }
    if (monitor_.get_abi_manager().handle_daemon_exit_if_match(pid, status)) return;
    if (process_.count(pid)) {
        handleTracedProcess(pid, status);
    } else {
        handleNewProcess(pid);
    }
}

void AppMonitor::SigChldHandler::handleParentEvent(int pid, int &status) {
    // Handle Fork Events (The primary goal of monitoring a parent)
    if (stopped_with(status, SIGTRAP, PTRACE_EVENT_FORK)) {
        long child_pid;
        if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid) != -1) {
            LOGV("parent %d forked %ld", pid, child_pid);
            handleNewProcess(static_cast<int>(child_pid));
        } else {
            PLOGE("ptrace geteventmsg");
        }
    }
    //  Handle Monitor Stop Request (Specific to Init)
    else if (pid == 1 && stopped_with(status, SIGTRAP, PTRACE_EVENT_STOP) &&
             monitor_.get_tracing_state() == STOPPING) {
        if (ptrace(PTRACE_DETACH, 1, 0, 0) == -1) PLOGE("detach init");
        monitor_.notify_init_detached();
        return;
    }
    // Handle Stub Exit (Stubs are temporary, unlike Init)
    else if (pid != 1 && (WIFEXITED(status) || WIFSIGNALED(status))) {
        LOGI("stub process %d exited", pid);
        stub_processes_.erase(pid);
        return;
    }

    // Resume the parent process
    if (WIFSTOPPED(status)) {
        // Logic to suppress signal injection into Init/Stubs if necessary
        if (WPTEVENT(status) == 0) {
            int sig = WSTOPSIG(status);
            if (sig != SIGSTOP && sig != SIGTSTP && sig != SIGTTIN && sig != SIGTTOU) {
                // Pass signals through
                ptrace(PTRACE_CONT, pid, 0, sig);
                return;
            }
        }
        ptrace(PTRACE_CONT, pid, 0, 0);
    }
}

void AppMonitor::SigChldHandler::handleNewProcess(int pid) {
    LOGV("new process %d attached", pid);
    process_.emplace(pid);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC);
    ptrace(PTRACE_CONT, pid, 0, 0);
}

void AppMonitor::SigChldHandler::handleTracedProcess(int pid, int &status) {
    bool keep_attached = false;

    if (stopped_with(status, SIGTRAP, PTRACE_EVENT_EXEC)) {
        // Check if this is a target (Zygote) or a bridge (Stub)
        keep_attached = handleExecEvent(pid, status);
    } else {
        LOGW("process %d received unknown status %s", pid, parse_status(status).c_str());
    }

    // If the process was promoted to a stub or injected, we don't detach normally.
    if (keep_attached) {
        process_.erase(pid);  // It is now either a 'stub' or dead.
        return;
    }

    // Cleanup for irrelevant processes
    process_.erase(pid);
    if (WIFSTOPPED(status)) {
        LOGV("detach process %d", pid);
        ptrace(PTRACE_DETACH, pid, 0, 0);
    }
}

/**
 * @brief Handles the execve event.
 *
 * Returns true if the process is "handled" (promoted to stub or injected/killed).
 * Returns false if the process is irrelevant and should be detached by the caller.
 */
bool AppMonitor::SigChldHandler::handleExecEvent(int pid, int &status) {
    auto program = get_program(pid);
    LOGV("%d program %s", pid, program.c_str());

    bool handled = false;

    do {
        // --- Stub Identification ---
        // If this is the intermediate stub, we promote it to a parent monitor.
        // We do NOT detach; we simply break out with handled=true.
        if (program.find("stub_zygote") != std::string::npos) {
            LOGI("detected stub zygote at %d, promoting", pid);
            stub_processes_.insert(pid);

            // Critical: We must now trace forks to catch the *next* child (the real zygote)
            ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC);
            ptrace(PTRACE_CONT, pid, 0, 0);

            handled = true;
            break;
        }

        // --- Injection Pre-checks ---
        if (monitor_.get_tracing_state() != TRACING) {
            LOGW("stop injecting %d because not tracing", pid);
            break;
        }

        // Check against the target ABI program path
        if (program != monitor_.get_abi_manager().program_path_) {
            break;
        }

        const char *tracer = monitor_.get_abi_manager().check_and_prepare_injection();
        if (tracer == nullptr) break;

        // --- Injection Logic ---
        LOGV("stopping %d for injection", pid);
        kill(pid, SIGSTOP);
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, __WALL);

        if (stopped_with(status, SIGSTOP, 0)) {
            LOGV("detaching %d", pid);

            // Detach with SIGSTOP so the injector (zygiskd) can attach
            ptrace(PTRACE_DETACH, pid, 0, SIGSTOP);

            // Execute the injector
            auto p = fork_dont_care();
            if (p == 0) {
                execl(tracer, basename(tracer), "trace", std::to_string(pid).c_str(), "--restart",
                      nullptr);
                PLOGE("exec injector");
                kill(pid, SIGKILL);
                _exit(1);
            } else if (p == -1) {
                PLOGE("fork injector");
                kill(pid, SIGKILL);
            }

            // The process is effectively dead/handed off to the injector
            handled = true;
        }

    } while (false);

    monitor_.update_status();
    return handled;
}
