#pragma once

#include <sys/types.h>

#include <string>

// Defines common data structures used across the monitor application.

enum TracingState { TRACING = 1, STOPPING, STOPPED, EXITING };

struct Status {
    bool supported = false;
    bool zygote_injected = false;
    bool daemon_running = false;
    pid_t daemon_pid = -1;
    std::string daemon_info;
    std::string daemon_error_info;
};

struct StartCounter {
    struct timespec last_start_time{.tv_sec = 0, .tv_nsec = 0};
    int count = 0;
};
