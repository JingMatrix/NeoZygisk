#pragma once

void init_monitor();
bool trace_zygote(int pid);

enum Command {
    START = 1,
    STOP = 2,
    EXIT = 3,
    // sent from daemon
    ZYGOTE_INJECTED = 4,
    DAEMON_SET_INFO = 5,
    DAEMON_SET_ERROR_INFO = 6,
    SYSTEM_SERVER_STARTED = 7
};
