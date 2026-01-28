#include "utils.hpp"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sched.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ios>
#include <sstream>
#include <string>
#include <vector>

#include "logging.hpp"

/**
 * @brief Scans and parses the /proc/[pid]/maps file for a given process.
 * @param pid The process ID to scan, as a string ("self" is also valid).
 * @return A vector of MapInfo structs, each representing a memory mapping.
 */
std::vector<MapInfo> MapInfo::Scan(const std::string &pid) {
    std::vector<MapInfo> info;
    std::string file_name = "/proc/" + pid + "/maps";
    auto maps = std::unique_ptr<FILE, decltype(&fclose)>{fopen(file_name.c_str(), "r"), &fclose};

    if (!maps) {
        PLOGE("fopen %s", file_name.c_str());
        return info;
    }

    char *line = nullptr;
    size_t len = 0;
    while (getline(&line, &len, maps.get()) > 0) {
        // Line format: start-end perms offset dev:minor inode pathname
        uintptr_t start, end, off;
        ino_t inode;
        unsigned int dev_major, dev_minor;
        std::array<char, 5> perm{};  // rwxp\0
        int path_off;

        if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n", &start, &end,
                   perm.data(), &off, &dev_major, &dev_minor, &inode, &path_off) != 7) {
            continue;
        }

        // Find the start of the pathname, skipping spaces.
        while (path_off > 0 && isspace(line[path_off])) {
            path_off++;
        }

        // Trim trailing newline from path.
        if (auto nl = strchr(line + path_off, '\n'); nl != nullptr) {
            *nl = '\0';
        }

        auto &ref = info.emplace_back(MapInfo{start, end, 0, perm[3] == 'p', off,
                                              static_cast<dev_t>(makedev(dev_major, dev_minor)),
                                              inode, line + path_off});
        if (perm[0] == 'r') ref.perms |= PROT_READ;
        if (perm[1] == 'w') ref.perms |= PROT_WRITE;
        if (perm[2] == 'x') ref.perms |= PROT_EXEC;
    }
    free(line);
    return info;
}

/**
 * @brief Writes data to another process's memory using process_vm_writev.
 * @return The number of bytes written, or -1 on error.
 */
ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len) {
    // The iovec struct's iov_base is a non-const void*, so we must cast away constness.
    // This is safe as process_vm_writev treats the local iovec as a source.
    struct iovec local{.iov_base = const_cast<void *>(buf), .iov_len = len};
    struct iovec remote{.iov_base = (void *) remote_addr, .iov_len = len};

    ssize_t bytes_written = process_vm_writev(pid, &local, 1, &remote, 1, 0);

    if (bytes_written == -1) {
        PLOGE("process_vm_writev to addr 0x%" PRIxPTR, remote_addr);
    } else if (static_cast<size_t>(bytes_written) != len) {
        LOGW("not fully written to 0x%" PRIxPTR ": wrote %zd, expected %zu", remote_addr,
             bytes_written, len);
    }
    return bytes_written;
}

/**
 * @brief Reads data from another process's memory using process_vm_readv.
 * @return The number of bytes read, or -1 on error.
 */
ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len) {
    struct iovec local{.iov_base = buf, .iov_len = len};
    struct iovec remote{.iov_base = (void *) remote_addr, .iov_len = len};

    ssize_t bytes_read = process_vm_readv(pid, &local, 1, &remote, 1, 0);

    if (bytes_read == -1) {
        PLOGE("process_vm_readv from addr 0x%" PRIxPTR, remote_addr);
    } else if (static_cast<size_t>(bytes_read) != len) {
        LOGW("not fully read from 0x%" PRIxPTR ": read %zd, expected %zu", remote_addr, bytes_read,
             len);
    }
    return bytes_read;
}

// --- Register Manipulation (Architecture Specific) ---

bool get_regs(int pid, struct user_regs_struct &regs) {
#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        PLOGE("ptrace(PTRACE_GETREGS)");
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    struct iovec iov = {.iov_base = &regs, .iov_len = sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        PLOGE("ptrace(PTRACE_GETREGSET)");
#if defined(__arm__)
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            PLOGE("fallback to PTRACE_GETREGS");
            return false;
        }
#else
        return false;
#endif
    }
#endif
    return true;
}

bool set_regs(int pid, struct user_regs_struct &regs) {
#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        PLOGE("ptrace(PTRACE_SETREGS)");
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    struct iovec iov = {.iov_base = &regs, .iov_len = sizeof(regs)};
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        PLOGE("ptrace(PTRACE_SETREGSET)");
#if defined(__arm__)
        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
            PLOGE("fallback to PTRACE_SETREGS");
            return false;
        }
#else
        return false;
#endif
    }
#endif
    return true;
}

/**
 * @brief Finds the memory region containing an address and formats its details.
 * @param info A vector of memory maps for the process. Should be const.
 * @param addr The address to look for.
 * @return A formatted string like "/path/to/lib.so r-x", or "<unknown>".
 */
std::string get_addr_mem_region(const std::vector<MapInfo> &info, uintptr_t addr) {
    for (const auto &map : info) {
        if (map.start <= addr && map.end > addr) {
            std::ostringstream ss;
            ss << map.path << " ";
            ss << ((map.perms & PROT_READ) ? 'r' : '-');
            ss << ((map.perms & PROT_WRITE) ? 'w' : '-');
            ss << ((map.perms & PROT_EXEC) ? 'x' : '-');
            return ss.str();
        }
    }
    return "<unknown>";
}

/**
 * @brief Finds a suitable address within a module to use as a return address for remote calls.
 *        This heuristic looks for the first non-executable segment of the library.
 *        Using such an address ensures that when our remote call "returns", it traps
 *        with a SIGSEGV instead of executing unknown code, allowing us to regain control.
 */
void *find_module_return_addr(const std::vector<MapInfo> &info, std::string_view suffix) {
    for (const auto &map : info) {
        if ((map.perms & PROT_EXEC) == 0 && map.path.ends_with(suffix)) {
            return (void *) map.start;
        }
    }
    return nullptr;
}

/**
 * @brief Finds the base address of a loaded module (the first mapping with zero offset).
 */
void *find_module_base(const std::vector<MapInfo> &info, std::string_view suffix) {
    for (const auto &map : info) {
        if (map.offset == 0 && map.path.ends_with(suffix)) {
            return (void *) map.start;
        }
    }
    return nullptr;
}

/**
 * @brief Calculates the address of a function in a remote process.
 *
 * This works by finding the function's address in our own process (`dlopen`/`dlsym`),
 * then finding the base address of its containing library in both our process and the
 * remote process. The remote address is then calculated using the offset from the base.
 * remote_sym = remote_base + (local_sym - local_base)
 */
void *find_func_addr(const std::vector<MapInfo> &local_info,
                     const std::vector<MapInfo> &remote_info, std::string_view module,
                     std::string_view func) {
    auto lib = dlopen(module.data(), RTLD_NOW);
    if (lib == nullptr) {
        LOGE("failed to open lib %s: %s", module.data(), dlerror());
        return nullptr;
    }
    auto local_sym = reinterpret_cast<uintptr_t>(dlsym(lib, func.data()));
    dlclose(lib);  // Close the library handle immediately to avoid resource leaks.
    if (local_sym == 0) {
        LOGE("failed to find sym %s in %s: %s", func.data(), module.data(), dlerror());
        return nullptr;
    }

    auto local_base = (uintptr_t) find_module_base(local_info, module);
    if (local_base == 0) {
        LOGE("failed to find local base for module %s", module.data());
        return nullptr;
    }

    auto remote_base = (uintptr_t) find_module_base(remote_info, module);
    if (remote_base == 0) {
        LOGE("failed to find remote base for module %s", module.data());
        return nullptr;
    }

    uintptr_t remote_addr = remote_base + (local_sym - local_base);
    LOGV("found remote %s!%s at 0x%" PRIxPTR " (local base 0x%" PRIxPTR ", remote base 0x%" PRIxPTR
         ")",
         module.data(), func.data(), remote_addr, local_base, remote_base);

    return (void *) remote_addr;
}

// --- Remote Call Implementation ---

// Most ABIs require the stack to be 16-byte aligned.
constexpr uintptr_t STACK_ALIGN_MASK = ~0xf;

void align_stack(struct user_regs_struct &regs, long preserve) {
    regs.REG_SP = (regs.REG_SP - preserve) & STACK_ALIGN_MASK;
}

/**
 * @brief Pushes a string onto the remote process's stack.
 * @return The address of the string in the remote process, or 0 on failure.
 */
uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str) {
    size_t len = strlen(str) + 1;
    regs.REG_SP -= len;
    align_stack(regs);  // Re-align after subtracting length.

    uintptr_t remote_addr = regs.REG_SP;
    if (write_proc(pid, remote_addr, str, len) != static_cast<ssize_t>(len)) {
        LOGE("failed to write string '%s' to remote process", str);
        return 0;  // Return 0 on failure.
    }
    LOGV("pushed string \"%s\" to 0x%" PRIxPTR, str, remote_addr);
    return remote_addr;
}

/**
 * @brief Executes a function in the remote process.
 *
 * This function is highly architecture-specific. It works by:
 * 1.  Setting up the remote process's registers according to the platform's C calling convention
 * (ABI).
 * 2.  Pushing arguments onto the remote stack if necessary.
 * 3.  Setting the return address register/stack to a specific `return_addr` (usually a
 * non-executable address).
 * 4.  Setting the instruction pointer to the `func_addr`.
 * 5.  Continuing the process, which executes the function.
 * 6.  Waiting for the process to trap (usually via SIGSEGV at our fake return address).
 * 7.  Reading the function's return value from the appropriate register.
 *
 * @return The return value of the remote function, or 0 on failure.
 */
uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr,
                      uintptr_t return_addr, std::vector<long> &args) {
    align_stack(regs);
    LOGV("calling remote function 0x%" PRIxPTR " with %zu args, return to 0x%" PRIxPTR, func_addr,
         args.size(), return_addr);

#if defined(__x86_64__)
    // ABI: rdi, rsi, rdx, rcx, r8, r9, then stack
    if (args.size() > 0) regs.rdi = args[0];
    if (args.size() > 1) regs.rsi = args[1];
    if (args.size() > 2) regs.rdx = args[2];
    if (args.size() > 3) regs.rcx = args[3];
    if (args.size() > 4) regs.r8 = args[4];
    if (args.size() > 5) regs.r9 = args[5];
    if (args.size() > 6) {
        size_t stack_args_size = (args.size() - 6) * sizeof(long);
        regs.REG_SP -= stack_args_size;
        if (write_proc(pid, regs.REG_SP, args.data() + 6, stack_args_size) !=
            (ssize_t) stack_args_size) {
            LOGE("failed to push stack arguments for x86_64 call");
            return 0;
        }
    }
    // Push return address
    regs.REG_SP -= sizeof(long);
    if (write_proc(pid, regs.REG_SP, &return_addr, sizeof(return_addr)) != sizeof(return_addr)) {
        LOGE("failed to push return address for x86_64 call");
        return 0;
    }
    regs.REG_IP = func_addr;

#elif defined(__i386__)
    // ABI: All arguments on stack, pushed in reverse order.
    // Our vector is already in the correct order to write in one block.
    if (!args.empty()) {
        size_t stack_args_size = args.size() * sizeof(long);
        regs.REG_SP -= stack_args_size;
        if (write_proc(pid, regs.REG_SP, args.data(), stack_args_size) !=
            (ssize_t) stack_args_size) {
            LOGE("failed to push arguments for i386 call");
            return 0;
        }
    }
    // Push return address
    regs.REG_SP -= sizeof(long);
    if (write_proc(pid, regs.REG_SP, &return_addr, sizeof(return_addr)) != sizeof(return_addr)) {
        LOGE("failed to write return addr for i386 call");
        return 0;
    }
    regs.REG_IP = func_addr;

#elif defined(__aarch64__)
    // ABI: x0-x7, then stack
    for (size_t i = 0; i < args.size() && i < 8; i++) {
        regs.regs[i] = args[i];
    }
    if (args.size() > 8) {
        size_t stack_args_size = (args.size() - 8) * sizeof(long);
        regs.REG_SP -= stack_args_size;
        if (write_proc(pid, regs.REG_SP, args.data() + 8, stack_args_size) !=
            (ssize_t) stack_args_size) {
            LOGE("failed to push stack arguments for aarch64 call");
            return 0;
        }
    }
    regs.regs[30] = return_addr;  // Link Register (LR)
    regs.REG_IP = func_addr;

#elif defined(__arm__)
    // ABI: r0-r3, then stack
    for (size_t i = 0; i < args.size() && i < 4; i++) {
        regs.uregs[i] = args[i];
    }
    if (args.size() > 4) {
        size_t stack_args_size = (args.size() - 4) * sizeof(long);
        regs.REG_SP -= stack_args_size;
        if (write_proc(pid, (uintptr_t) regs.REG_SP, args.data() + 4, stack_args_size) !=
            (ssize_t) stack_args_size) {
            LOGE("failed to push stack arguments for arm call");
            return 0;
        }
    }
    regs.uregs[14] = return_addr;  // Link Register (LR)
    regs.REG_IP = func_addr;       // Program Counter (PC)

    // Handle Thumb vs ARM mode. The lowest bit of an address indicates Thumb mode.
    // The PC register itself must not have this bit set. It's stored in the CPSR.
    constexpr auto CPSR_T_MASK = 1lu << 5;
    if ((regs.REG_IP & 1) != 0) {
        // Thumb mode: remove LSB from PC and set T-bit in CPSR
        regs.REG_IP &= ~1;
        regs.uregs[16] |= CPSR_T_MASK;
    } else {
        // ARM mode: clear T-bit in CPSR
        regs.uregs[16] &= ~CPSR_T_MASK;
    }

#else
#error "Unsupported architecture for remote_call"
#endif

    if (!set_regs(pid, regs)) {
        LOGE("remote_call: failed to set registers before call");
        return 0;
    }

    ptrace(PTRACE_CONT, pid, 0, 0);
    int status;
    wait_for_trace(pid, &status, __WALL);  // wait_for_trace handles intermediate stops

    if (!get_regs(pid, regs)) {
        LOGE("remote_call: failed to get registers after call");
        return 0;
    }

    // We expect the tracee to stop at our fake return address.
    if (WIFSTOPPED(status) && static_cast<uintptr_t>(regs.REG_IP) == return_addr) {
        LOGV("remote call returned, result: 0x%" PRIXPTR, (uintptr_t) regs.REG_RET);
        return regs.REG_RET;
    } else {
        LOGE("process stopped unexpectedly after remote call: %s at ip=0x%" PRIXPTR
             ", expected stop at 0x%" PRIXPTR,
             parse_status(status).c_str(), (uintptr_t) regs.REG_IP, return_addr);
        return 0;
    }
}

// --- Process Management ---

/**
 * @brief Creates a fully detached daemon process using a double-fork.
 *
 * A double-fork ensures the final process is not a child of the original process,
 * but rather a child of init (PID 1). This prevents it from becoming a zombie
 * if the original parent exits without waiting for it.
 *
 * @return This function has different return values depending on which process is running:
 *         - In the **original parent process**, it returns the PID of the first child (> 0).
 *         - In the **final daemon (grandchild) process**, it returns 0.
 *         - On an initial fork error, it returns -1.
 */
int fork_dont_care() {
    pid_t pid = fork();
    if (pid < 0) {
        PLOGE("fork child");
        return -1;  // Return -1 on the first fork failure.
    }

    if (pid > 0) {
        // --- Original Parent Process ---
        // The parent waits for the *first* child to exit. This first child exits
        // almost immediately, allowing the parent to continue its work while the
        // second child (the daemon) continues in the background. It then returns
        // the PID of the child it forked, signaling to the caller that it is the parent.
        int status;
        waitpid(pid, &status, __WALL);
        return pid;
    }

    // --- First Child Process ---
    // This process exists only to spawn the final daemon process.
    pid_t grandchild_pid = fork();
    if (grandchild_pid < 0) {
        PLOGE("fork grandchild");
        exit(1);  // Exit with an error code if the second fork fails.
    }

    if (grandchild_pid > 0) {
        // The first child has successfully forked the grandchild, so its job is
        // done. It exits immediately. This orphans the grandchild, which is
        // then adopted by the 'init' process (PID 1). This is the key to detachment.
        exit(0);
    }

    // --- Second Child (Grandchild / Daemon) Process ---
    // The second fork() call returned 0 to this process. Now, we return 0 from
    // this function to let the new daemon's internal logic know that it is the
    // child process and should begin its work.
    return 0;
}

/**
 * @brief Skips the currently trapped syscall for a tracee.
 *
 * When a tracee is stopped due to a PTRACE_EVENT_SECCOMP, it is paused *before*
 * the syscall is executed. This function prevents the syscall from ever running
 * by modifying the tracee's registers.
 *
 * It sets the syscall number register to -1, which is an invalid syscall number.
 * The kernel recognizes this and skips the execution, causing the syscall to
 * immediately return with -ENOSYS, without any side effects.
 *
 * For ARM/ARM64, it also uses architecture-specific ptrace requests as a
 * fallback/alternative method to ensure the syscall is skipped. These might not
alway
s
 * work on all kernel versions, so their errors are ignored.
 *
 * @param pid The process ID of the tracee.
 */
void tracee_skip_syscall(int pid) {
    user_regs_struct regs;
    if (!get_regs(pid, regs)) {
        LOGE("tracee_skip_syscall: failed to get registers");
        exit(1);
    }

    // Set the syscall number to an invalid value (-1).
    // The kernel will see this and skip the syscall execution.
    regs.REG_SYSNR = -1;

    if (!set_regs(pid, regs)) {
        LOGE("tracee_skip_syscall: failed to set registers to skip syscall");
        exit(1);
    }

    // For ARM architectures, there are specific ptrace requests to modify the
    // syscall number. We attempt these as well, but don't check for errors
    // as they may not be supported on all kernels. The register modification
    // above is the primary method.
#if defined(__aarch64__)
    int sysnr = -1;
    struct iovec iov = {.iov_base = &sysnr, .iov_len = sizeof(sysnr)};
    ptrace(PTRACE_SETREGSET, pid, NT_ARM_SYSTEM_CALL, &iov);
#elif defined(__arm__)
    ptrace(PTRACE_SET_SYSCALL, pid, 0, (void *) -1);
#endif
}

/**
 * @brief Waits for a ptrace event, handling seccomp events specifically.
 *
 * This is a wrapper around waitpid that handles EINTR and automatically
 * continues the process after a PTRACE_EVENT_SECCOMP.
 *
 * @param pid The PID to wait for.
 * @param status A pointer to an integer where the status will be stored.
 * @param flags Flags for waitpid.
 */
void wait_for_trace(int pid, int *status, int flags) {
    while (true) {
        if (waitpid(pid, status, flags) == -1) {
            if (errno == EINTR) {
                continue;  // Interrupted by a signal, just retry.
            }
            PLOGE("waitpid(%d)", pid);
            exit(1);
        }

        // Check if the stop was caused by a PTRACE_EVENT_SECCOMP.
        if (*status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
            tracee_skip_syscall(pid);
            ptrace(PTRACE_CONT, pid, 0, 0);
            continue;  // Continue waiting for the next *real* stop event.
        }

        // If the process terminated or signaled instead of stopping, it's an error.
        if (!WIFSTOPPED(*status)) {
            LOGE("process %d did not stop as expected: %s", pid, parse_status(*status).c_str());
            exit(1);
        }

        // It's a valid stop event that we need to handle, so we return.
        return;
    }
}

std::string parse_status(int status) {
    std::ostringstream os;
    os << "0x" << std::hex << status << std::dec << " ";
    if (WIFEXITED(status)) {
        os << "exited with " << WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        os << "signaled with " << sigabbrev_np(WTERMSIG(status)) << "(" << WTERMSIG(status) << ")";
    } else if (WIFSTOPPED(status)) {
        os << "stopped by ";
        auto stop_sig = WSTOPSIG(status);
        os << "signal=" << sigabbrev_np(stop_sig) << "(" << stop_sig << "),";
        os << "event=" << parse_ptrace_event(status);
    } else {
        os << "unknown";
    }
    return os.str();
}

/**
 * @brief Gets the executable path of a process from /proc/[pid]/exe.
 * @return The path to the executable, or an empty string on failure.
 */
std::string get_program(int pid) {
    std::string path = "/proc/";
    path += std::to_string(pid);
    path += "/exe";
    constexpr const auto SIZE = 256;
    char buf[SIZE + 1];
    auto sz = readlink(path.c_str(), buf, SIZE);
    if (sz == -1) {
        PLOGE("readlink /proc/%d/exe", pid);
        return "";
    }
    buf[sz] = 0;
    return buf;
}
