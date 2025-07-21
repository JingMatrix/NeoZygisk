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
#include <string>

#include "logging.hpp"
#include "zygisk.hpp"

/**
 * @brief Checks if the seccomp-based clearing method should be skipped.
 *
 * This function's purpose is to facilitate a hybrid strategy for clearing
 * the ptrace_message. The seccomp method, while effective on older kernels,
 * creates a detectable artifact on newer kernels (Linux 5.9+): it increments
 * the filter count in the "Seccomp_filters:" field of /proc/self/status.
 *
 * This function checks for the *existence* of that field.
 * - If the field exists, it implies a newer kernel where this method is
 *   detectable. We should therefore SKIP this method and rely on a different
 *   one (e.g., PTRACE_SYSCALL) which is stealthier on new kernels.
 * - If the field does not exist, it implies an older kernel where this seccomp
 *   method is probably necessary and potentially invisible.
 *
 * @return True if the seccomp method should be skipped, false if it should be used.
 */

static bool should_skip_seccomp_injection() {
    // Use std::ifstream for automatic resource management (RAII).
    std::ifstream status_file("/proc/self/status");
    if (!status_file.is_open()) {
        // Fail-safe: if we can't check, we skip the injection.
        return true;
    }

    const std::string needle = "Seccomp_filters:";
    std::string line;

    while (std::getline(status_file, line)) {
        // C++20's starts_with is safer and more expressive than strncmp.
        if (line.starts_with(needle)) {
            return true;
        }
    }

    return false;
}

void send_seccomp_event_if_needed() {
    if (should_skip_seccomp_injection()) {
        return;
    }

    // Use std::array for type-safe, fixed-size arrays.
    std::array<uint32_t, 4> args{};

    // Read random bytes to create a unique syscall signature.
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
    }  // random_file is automatically closed here by its destructor.

    // Modify a bit to ensure the signature is highly unlikely to occur naturally.
    args[0] |= 0x10000;

    const std::array<sock_filter, 12> filter = {{
        // 1. Check if the syscall is __NR_exit_group. If not, allow it.
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 9),

        // 2. If it is __NR_exit_group, check if all 4 arguments match our random signature.
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, args[0], 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, args[1], 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, args[2], 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[3])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, args[3], 0, 1),

        // 3. If everything matches, trap the syscall, triggering a PTRACE_EVENT_SECCOMP.
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),

        // 4. Default action for any non-matching syscall is to allow it.
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

    // This syscall triggers the seccomp filter. The tracer will intercept it
    // and prevent it from actually executing, so Zygote will not exit.
    syscall(__NR_exit_group, args[0], args[1], args[2], args[3]);
}
