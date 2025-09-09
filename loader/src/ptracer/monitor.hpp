#pragma once

#include <set>
#include <string>
#include <vector>

#include "event_loop.hpp"
#include "main.hpp"
#include "types.hpp"
#include "zygote_abi.hpp"

// Helper to check ptrace status.
static inline bool stopped_with(int status, int sig, int event) {
    return WIFSTOPPED(status) && (status >> 8 == (sig | (event << 8)));
}

/**
 * @brief Defines the main application class for the NeoZygisk init monitor.
 *
 * This file contains the primary architectural components of the monitor daemon.
 * The core design is a single-threaded, event-driven application encapsulated
 * within the `AppMonitor` class.
 *
 * @section Architecture Overview
 *
 * The monitor's architecture is designed for stability and clarity. It revolves
 * around a central EventLoop that dispatches events to specialized, private
 * handler classes. These handlers translate low-level system events into high-level
 * commands for the main AppMonitor to process.
 *
 *
 *                       +-----------------------------------------+
 *                       |              KERNEL SPACE               |
 *                       +-----------------------------------------+
 *                            ^               ^                ^
 *                            | (ptrace)      | (signals)      | (socket I/O)
 *                            |               |                |
 *  +---------------------------------------------------------------------------------------+
 *  |                       USER SPACE (The Monitor Process)                                |
 *  |                                                                                       |
 *  |  +---------------------------------------------------------------------------------+  |
 *  |  | AppMonitor Class                                                                |  |
 *  |  |                                                                                 |  |
 *  |  |  +--------------------------+        +--------------------------------------+   |  |
 *  |  |  |        EventLoop         | <------|       Registers self with loop       |   |  |
 *  |  |  |--------------------------|        +--------------------------------------+   |  |
 *  |  |  |                          |                            |                      |  |
 *  |  |  | .Loop() method blocks,   |          (private members) |                      |  |
 *  |  |  |   waiting for events...  |       +--------------------+-------------------+  |  |
 *  |  |  |                          |       |                    |          (ptrace) |  |  |
 *  |  |  +-- dispatches events to --+       V                    V                   |  |  |
 *  |  |              |                +---------------+    +----------------+        |  |  |
 *  |  |              +--------->      | SocketHandler |    | SigChldHandler |<-------+  |  |
 *  |  |                               +---------------+    +----------------+           |  |
 *  |  |                                     ^                      ^                    |  |
 *  |  +-------------------------------------|----------------------|--------------------+  |
 *  |                                        | (calls public API)   | (calls public API)    |
 *  |                                        V                      V                       |
 *  |  +---------------------------------------------------------------------------------+  |
 *  |  |       AppMonitor Public Interface (request_stop(), update_status(), etc.)       |  |
 *  |  +---------------------------------------------------------------------------------+  |
 *  |                                        |                                              |
 *  |                                        | delegates ABI-specific logic to...           |
 *  |                                        V                                              |
 *  |                             +------------------------+                                |
 *  |                             |   ZygoteAbiManagers    |                                |
 *  |                             |   (zygote64_, etc.)    |                                |
 *  |                             +------------------------+                                |
 *  |                                                                                       |
 *  +---------------------------------------------------------------------------------------+
 *                ^                           ^                              ^
 *                |                           |                              |
 *          +-----------+               +-----------+                 +--------------+
 *          | User/CLI  |               |   Zygote  |                 | File System  |
 *          | (ctl cmd) |               |(fork/exec)|                 | (module.prop)|
 *          +-----------+               +-----------+                 +--------------+
 *
 * @section Component Roles
 *
 * 1.  **AppMonitor**: The central orchestrator and owner of all other components. It holds the
 *     application's high-level state (like `tracing_state_`) and exposes a clean public API for
 *     state transitions (e.g., `request_stop()`). It delegates ABI-specific tasks.
 *
 * 2.  **EventLoop**: A simple, generic, and passive engine. Its only job is to wait efficiently
 *     on multiple file descriptors (using `epoll`) and to wake up the correct handler when an
 *     event occurs. It is completely unaware of `ptrace`, Zygote, or sockets.
 *
 * 3.  **SocketHandler** (Private Nested Class): An internal implementation detail of AppMonitor. It
 *     owns the UNIX domain socket file descriptor. Its role is to listen for incoming user
 *     commands, parse the raw data, and translate them into clear, high-level calls to the
 *     AppMonitor's public interface (e.g., `monitor_.request_exit()`).
 *
 * 4.  **SigChldHandler** (Private Nested Class): The core of the monitoring logic. It owns the
 *     `signalfd` for `SIGCHLD` and is responsible for the entire `ptrace` lifecycle. It catches
 *     events like new process creation and `execve` calls. Like the SocketHandler, it translates
 *     these low-level system events into high-level calls and delegates ABI-specific logic to
 *     the appropriate manager.
 *
 * 5.  **ZygoteAbiManager**: A helper class that encapsulates all the state (`Status`, counters) and
 *     behavior (daemon creation, crash-loop detection) for a single architecture (64-bit or
 *     32-bit). This prevents code duplication and cleanly separates the logic for managing each
 *     Zygote type.
 */

class AppMonitor {
public:
    static constexpr char SOCKET_NAME[] = "init_monitor";

    AppMonitor();

    // Public Lifecycle Methods
    bool prepare_environment();
    void run();

    // Public Interface for state changes and notifications
    void update_status();
    void request_start();
    void request_stop(std::string reason);
    void request_exit();
    void notify_init_detached();

    // Public Accessors for owned components
    ZygoteAbiManager &get_abi_manager(bool is_64bit);
    TracingState get_tracing_state() const;

private:
    class SocketHandler : public EventHandler {
    public:
        explicit SocketHandler(AppMonitor &monitor) : monitor_(monitor) {}
        bool Init();
        int GetFd() override;
        void HandleEvent(EventLoop &loop, uint32_t) override;
        ~SocketHandler() override;

    private:
        struct [[gnu::packed]] MsgHead {
            Command cmd;
            int length;
            char data[0];
        };
        AppMonitor &monitor_;
        std::vector<uint8_t> buf_;
        int sock_fd_ = -1;
    };

    class SigChldHandler : public EventHandler {
    public:
        explicit SigChldHandler(AppMonitor &monitor) : monitor_(monitor) {}
        bool Init();
        int GetFd() override;
        void HandleEvent(EventLoop &, uint32_t) override;
        ~SigChldHandler() override;

    private:
        void handleChildEvent(int pid, int &status);
        void handleInitEvent(int pid, int &status);
        void handleNewProcess(int pid);
        void handleTracedProcess(int pid, int &status);
        void handleExecEvent(int pid, int &status);

        AppMonitor &monitor_;
        int signal_fd_ = -1;
        int status_ = 0;
        std::set<pid_t> process_;
    };

    void set_tracing_state(TracingState state);
    void write_abi_status_section(std::string &status_text, const Status &daemon_status,
                                  const char *abi_name);

    // Owned Components (Declaration order must match initializer list)
    EventLoop event_loop_;
    SocketHandler socket_handler_;
    SigChldHandler ptrace_handler_;
    ZygoteAbiManager zygote64_;
    ZygoteAbiManager zygote32_;

    // Private State
    TracingState tracing_state_;
    std::string monitor_stop_reason_;
    std::string prop_path_;
    std::string pre_section_;
    std::string post_section_;
};
