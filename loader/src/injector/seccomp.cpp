#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <fstream>

#include "logging.hpp"
#include "misc.hpp"
#include "zygisk.hpp"

// Our monitor arms PTRACE_O_TRACEEXEC on every zygote candidate, so the exec event leaves
// zygote holding its own pid in task->ptrace_message for each app it forks to inherit. A
// PTRACE_EVENT_SECCOMP overwrites that with the filter's return data, which is zero here.
// Later kernels clear the field on their own, where a filter would buy nothing and only add
// to the count /proc/self/status reports since 5.9.
void send_seccomp_event_if_needed() {
    if (!kernel_keeps_ptrace_message()) {
        return;
    }

    std::array<uint32_t, 4> args{};

    {
        std::ifstream random_file("/dev/urandom", std::ios::binary);
        if (!random_file.is_open()) {
            PLOGE("seccomp: open(/dev/urandom)");
            return;
        }
        random_file.read(reinterpret_cast<char *>(args.data()), args.size() * sizeof(uint32_t));
        if (!random_file) {
            PLOGE("seccomp: read(random_file)");
            return;
        }
    }

    // An exit status is eight bits wide, so this bit keeps the signature out of reach of a
    // real exit_group().
    args[0] |= 0x10000;

    const std::array<sock_filter, 12> filter = {{
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 9),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, args[0], 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, args[1], 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, args[2], 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[3])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, args[3], 0, 1),

        // Only our own signature is traced, and its return data, which the event message
        // takes, is zero. Everything else is allowed, so this filter never tightens the ones
        // zygote installs later.
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    }};

    sock_fprog prog = {
        .len = static_cast<unsigned short>(filter.size()),
        // prctl API requires a non-const pointer.
        .filter = const_cast<sock_filter *>(filter.data()),
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        PLOGE("seccomp: prctl(PR_SET_SECCOMP)");
        return;
    }

    // The tracer skips the syscall at the event stop, so zygote does not exit. A tracer that
    // never armed PTRACE_O_TRACESECCOMP gets no event and the kernel answers -ENOSYS, which
    // leaves the process alive and the message in place.
    syscall(__NR_exit_group, args[0], args[1], args[2], args[3]);
}
