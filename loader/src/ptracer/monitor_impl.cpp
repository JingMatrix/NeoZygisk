#include <fcntl.h>
#include <linux/eventpoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstring>

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
        status_text += "zygote_";
        status_text += abi_name;
        status_text += "_status=";
        if (tracing_state_ != TRACING)
            status_text += "unknown";
        else if (daemon_status.zygote_injected)
            status_text += "injected";
        else
            status_text += "not_injected";
        status_text += "\ndaemon_";
        status_text += abi_name;
        status_text += "_status=";
        if (daemon_status.daemon_running) {
            status_text += "running";
            if (!daemon_status.daemon_info.empty()) {
                status_text += "\n";
                status_text += daemon_status.daemon_info;
            }
        } else {
            status_text += "crashed";
            if (!daemon_status.daemon_error_info.empty()) {
                status_text += "\ndaemon_";
                status_text += abi_name;
                status_text += "_error=";
                status_text += daemon_status.daemon_error_info;
            }
        }
    }
}

// Helper for atomic file writing with proper durability guarantees
static bool atomic_write_file(const char *path, const std::string &content) {
    std::string tmp_path = std::string(path) + ".tmp";
    
    // Use a lambda for cleanup on failure
    auto cleanup_tmp = [&tmp_path]() {
        unlink(tmp_path.c_str());
    };

    auto file = xopen_file(tmp_path.c_str(), "w");
    if (!file) {
        PLOGE("open %s", tmp_path.c_str());
        return false;
    }

    if (fwrite(content.c_str(), 1, content.length(), file.get()) != content.length()) {
        PLOGE("write %s", tmp_path.c_str());
        file.reset();
        cleanup_tmp();
        return false;
    }

    if (fflush(file.get()) != 0) {
        PLOGE("fflush %s", tmp_path.c_str());
        file.reset();
        cleanup_tmp();
        return false;
    }

    if (fsync(fileno(file.get())) != 0) {
        PLOGE("fsync %s", tmp_path.c_str());
        file.reset();
        cleanup_tmp();
        return false;
    }

    // Close before rename to ensure all data is flushed and lock released
    file.reset();

    if (rename(tmp_path.c_str(), path) != 0) {
        PLOGE("rename %s to %s", tmp_path.c_str(), path);
        cleanup_tmp();
        return false;
    }

    // Sync parent directory to ensure rename is durable across power loss
    std::string dir_path(path);
    auto last_slash = dir_path.rfind('/');
    if (last_slash != std::string::npos) {
        dir_path.resize(last_slash);
        if (dir_path.empty()) dir_path = "/";
    } else {
        dir_path = ".";
    }
    
    int dir_fd = open(dir_path.c_str(), O_RDONLY | O_DIRECTORY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    return true;
}

void AppMonitor::update_status() {
    // Determine icons based on current state
    const char* monitor_icon = (tracing_state_ == TRACING) ? "\xE2\x9C\x85" : "\xE2\x9D\x8C";
    
    // For ABI status icon, rely on daemon_running and supported
    const auto& d_status = zygote_.get_status();
    bool abi_ok = d_status.supported && d_status.daemon_running && d_status.zygote_injected;
    const char* abi_icon = abi_ok ? "\xE2\x9C\x85" : "\xE2\x9D\x8C";

    // Map ABI name to user-friendly display
    const char* abi_pretty;
    if (strcmp(zygote_.abi_name_, "64") == 0) {
        abi_pretty = "64-bit";
    } else if (strcmp(zygote_.abi_name_, "32") == 0) {
        abi_pretty = "32-bit";
    } else {
        abi_pretty = zygote_.abi_name_;
    }

    // === Build runtime prop content (only description for /data/adb/neozygisk/module.prop) ===
    std::string runtime_status;
    runtime_status.reserve(256);
    
    // Build pre_section
    runtime_status += pre_section_;
    if (!pre_section_.empty() && pre_section_.back() != '\n') {
        runtime_status += '\n';
    }
    
    // Build description line
    runtime_status += "description=[Monitor: ";
    runtime_status += monitor_icon;
    runtime_status += ", NeoZygisk ";
    runtime_status += abi_pretty;
    runtime_status += ": ";
    runtime_status += abi_icon;
    runtime_status += "] ";
    runtime_status += post_section_;
    
    // Ensure newline after description/post section
    if (!post_section_.empty() && post_section_.back() != '\n') {
        runtime_status += '\n';
    } else if (post_section_.empty()) {
        runtime_status += '\n';
    }

    // === Build installed module prop content (full status for /data/adb/modules/zygisksu/module.prop) ===
    std::string installed_status;
    installed_status.reserve(512);
    
    // Start with the same content as runtime
    installed_status = runtime_status;

    // Add monitor status section
    installed_status += "monitor_status=";
    switch (tracing_state_) {
    case TRACING:
        installed_status += "tracing";
        break;
    case STOPPING:
        [[fallthrough]];
    case STOPPED:
        installed_status += "stopped";
        break;
    case EXITING:
        installed_status += "exited";
        break;
    }
    
    if (tracing_state_ != TRACING && !monitor_stop_reason_.empty()) {
        installed_status += "\nmonitor_stop_reason=";
        installed_status += monitor_stop_reason_;
    }
    installed_status += '\n';

    // Add ABI status section
    write_abi_status_section(installed_status, d_status);
    installed_status += '\n';

    // Skip writing if content hasn't changed (avoid redundant I/O)
    if (installed_status == last_written_status_) {
        return;
    }
    last_written_status_ = installed_status;

    // Write to runtime prop (full status for /data/adb/neozygisk/module.prop) with atomic guarantee
    if (!atomic_write_file(prop_path_.c_str(), installed_status)) {
        LOGE("Failed to write runtime module.prop: %s", prop_path_.c_str());
    }

    // Write to installed module.prop (only description for /data/adb/modules/zygisksu/module.prop) with atomic guarantee
    if (!atomic_write_file("./module.prop", runtime_status)) {
        LOGE("Failed to write installed module.prop: ./module.prop");
    }
}

bool AppMonitor::prepare_environment() {
    prop_path_ = zygiskd::GetTmpPath() + "/module.prop";
    int fd = open(prop_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        close(fd);
    } else {
        PLOGE("create runtime module.prop");
    }

    auto orig_prop = xopen_file("./module.prop", "r");
    if (orig_prop == nullptr) {
        PLOGE("open original prop");
        return false;
    }

    pre_section_ = "";
    post_section_ = "";
    bool post = false;

    // Keys generated by update_status that we must drop + other dynamic keys
    auto is_generated_key = [](std::string_view line) {
        return line.starts_with("monitor_status=") ||
               line.starts_with("monitor_stop_reason=") ||
               line.starts_with("zygote_") ||
               line.starts_with("daemon_");
    };

    file_readline(false, orig_prop.get(), [&](std::string_view line_view) -> bool {
        std::string line(line_view);
        // Strip trailing line breaks so we can control spacing manually
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
            line.pop_back();
        }
        
        // Skip blank/empty lines to prevent gap growth
        if (line.find_first_not_of(" \t") == std::string::npos) return true;

        // Skip previously generated status lines
        if (is_generated_key(line)) return true;

        if (line.starts_with("description=")) {
            // Only capture the first description found. Ignore subsequent ones (duplicates).
            if (post) return true;

            post = true;
            std::string desc_val = line.substr(12); // "description=" is exactly 12 chars

            // Clean up existing [Monitor: ...] prefix and any Garbage
            bool cleaning = true;
            while (cleaning) {
                cleaning = false;
                // Strip [Monitor: ...]
                if (desc_val.starts_with("[Monitor:")) {
                    auto closing_bracket = desc_val.find(']');
                    if (closing_bracket != std::string::npos) {
                        desc_val = desc_val.substr(closing_bracket + 1);
                        cleaning = true;
                    }
                }
                
                // Strip leading garbage like =, space, tab
                if (!desc_val.empty()) {
                    size_t first_valid = desc_val.find_first_not_of("= \t");
                    if (first_valid == std::string::npos) {
                        desc_val = ""; // string is all garbage
                    } else if (first_valid > 0) {
                        desc_val = desc_val.substr(first_valid);
                        cleaning = true; // potentially exposed another [Monitor:]
                    }
                }
            }

            if (!post_section_.empty()) post_section_ += "\n";
            post_section_ += desc_val;
        } else {
            if (post) {
                if (!post_section_.empty()) post_section_ += "\n";
                post_section_ += line;
            } else {
                if (!pre_section_.empty()) pre_section_ += "\n";
                pre_section_ += line;
            }
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
 * @brief The central event handler for all ptrace and child process events.
 *
 * This function is the heart of the monitoring logic. It is woken up by the
 * EventLoop whenever a SIGCHLD signal is received, indicating a state change
 * in one of init's descendants. Its primary responsibility is to determine what
 * happened and dispatch the event to the correct handler logic.
 *
 * The function enters a `while` loop to reap all pending child process state
 * changes reported by the kernel. For each reaped process (`pid`), it follows
 * a strict, ordered decision tree to determine the nature of the event.
 *
 * @section Event Processing Flow
 *
 * For each PID returned by `waitpid()`, the following checks are performed in order:
 *
 * 1.  **Is the PID `init` (pid == 1)?**
 *     - **Why:** This handles events directly affecting the `init` process itself.
 *       These are typically `PTRACE_EVENT_FORK` notifications (when `init` forks
 *       a new direct child) or `PTRACE_EVENT_STOP` (which confirms that our
 *       `PTRACE_INTERRUPT` command for a graceful stop has been received).
 *     - **Action:** If it matches, the event is passed to `handleInitEvent()`, and
 *       processing for this PID concludes.
 *
 * 2.  **Is the PID a known helper daemon?**
 *     - **Why:** The monitor spawns and tracks the PIDs of its `zygiskd64` and
 *       `zygiskd32` helper daemons. This check quickly determines if one of them
 *       has crashed or exited unexpectedly.
 *     - **Action:** If it's a daemon PID, `handle_daemon_exit_if_match()` is called
 *       to update the status, and processing for this PID concludes.
 *
 * 3.  **Is the PID a process we are actively tracing?**
 *     - **Why:** The monitor maintains a `process_` set containing the PIDs of
 *       newly forked children that it is specifically watching for an `execve` call.
 *       This check differentiates between a brand new process and one that is in
 *       the middle of our interception workflow.
 *     - **Action (if YES):** The event is passed to `handleTracedProcess()`. This
 *       function confirms the event is the `PTRACE_EVENT_EXEC` we were waiting for
 *       and then calls `handleExecEvent()` to perform the core injection logic.
 *       Afterward, the PID is removed from the `process_` set.
 *     - **Action (if NO):** This means the PID is a new child of `init` that we have
 *       never seen before. The event is passed to `handleNewProcess()`, which attaches
 *       `ptrace` with the `PTRACE_O_TRACEEXEC` option. This crucial step tells the
 *       kernel to stop the child and notify us again just before it executes a new
 *       program. The PID is then added to the `process_` set for tracking.
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
    if (pid == 1) {
        handleInitEvent(pid, status);
        return;
    }
    if (monitor_.get_abi_manager().handle_daemon_exit_if_match(pid, status)) return;
    if (process_.count(pid)) {
        handleTracedProcess(pid, status);
    } else {
        handleNewProcess(pid);
    }
}

void AppMonitor::SigChldHandler::handleInitEvent(int pid, int &status) {
    if (stopped_with(status, SIGTRAP, PTRACE_EVENT_FORK)) {
        long child_pid;
        ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid);
        LOGV("init forked %ld", child_pid);
    } else if (stopped_with(status, SIGTRAP, PTRACE_EVENT_STOP) &&
               monitor_.get_tracing_state() == STOPPING) {
        if (ptrace(PTRACE_DETACH, 1, 0, 0) == -1) PLOGE("detach init");
        monitor_.notify_init_detached();
        return;
    }
    if (WIFSTOPPED(status)) {
        if (WPTEVENT(status) == 0) {
            int sig = WSTOPSIG(status);
            if (sig != SIGSTOP && sig != SIGTSTP && sig != SIGTTIN && sig != SIGTTOU) {
                LOGW("inject signal sent to init: %s %d", sigabbrev_np(sig), sig);
                ptrace(PTRACE_CONT, pid, 0, sig);
                return;
            } else {
                LOGW("suppress stopping signal sent to init: %s %d", sigabbrev_np(sig), sig);
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
    if (stopped_with(status, SIGTRAP, PTRACE_EVENT_EXEC)) {
        handleExecEvent(pid, status);
    } else {
        LOGW("process %d received unknown status %s", pid, parse_status(status).c_str());
    }
    process_.erase(pid);
    if (WIFSTOPPED(status)) {
        LOGV("detach process %d", pid);
        ptrace(PTRACE_DETACH, pid, 0, 0);
    }
}

void AppMonitor::SigChldHandler::handleExecEvent(int pid, int &status) {
    auto program = get_program(pid);
    LOGV("%d program %s", pid, program.c_str());
    const char *tracer = nullptr;
    do {
        if (monitor_.get_tracing_state() != TRACING) {
            LOGW("stop injecting %d because not tracing", pid);
            break;
        }
        if (program == monitor_.get_abi_manager().program_path_) {
            tracer = monitor_.get_abi_manager().check_and_prepare_injection();
            if (tracer == nullptr) break;
        }
        if (tracer != nullptr) {
            LOGV("stopping %d", pid);
            kill(pid, SIGSTOP);
            ptrace(PTRACE_CONT, pid, 0, 0);
            waitpid(pid, &status, __WALL);
            if (stopped_with(status, SIGSTOP, 0)) {
                LOGV("detaching %d", pid);
                ptrace(PTRACE_DETACH, pid, 0, SIGSTOP);
                status = 0;
                auto p = fork_dont_care();
                if (p == 0) {
                    execl(tracer, basename(tracer), "trace", std::to_string(pid).c_str(),
                          "--restart", nullptr);
                    PLOGE("exec");
                    kill(pid, SIGKILL);
                    exit(1);
                } else if (p == -1) {
                    PLOGE("fork");
                    kill(pid, SIGKILL);
                }
            }
        }
    } while (false);
    monitor_.update_status();
}
