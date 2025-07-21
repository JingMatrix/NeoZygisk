#include "utils.hpp"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sched.h>
#include <signal.h>
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

bool switch_mnt_ns(int pid, int *fd) {
    int nsfd, old_nsfd = -1;
    std::string path;
    if (pid == 0) {
        if (fd != nullptr) {
            nsfd = *fd;
            *fd = -1;
        } else
            return false;
        path = "/proc/self/fd/";
        path += std::to_string(nsfd);
    } else {
        if (fd != nullptr) {
            old_nsfd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
            if (old_nsfd == -1) {
                PLOGE("get old nsfd");
                return false;
            }
            *fd = old_nsfd;
        }
        path = std::string("/proc/") + std::to_string(pid) + "/ns/mnt";
        nsfd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (nsfd == -1) {
            PLOGE("open nsfd %s", path.c_str());
            close(old_nsfd);
            return false;
        }
    }
    if (setns(nsfd, CLONE_NEWNS) == -1) {
        PLOGE("set ns to %s", path.c_str());
        close(nsfd);
        close(old_nsfd);
        return false;
    }
    close(nsfd);
    return true;
}

std::vector<MapInfo> MapInfo::Scan(const std::string &pid) {
    constexpr static auto kPermLength = 5;
    constexpr static auto kMapEntry = 7;
    std::vector<MapInfo> info;
    std::string file_name = std::string("/proc/") + pid + "/maps";
    auto maps = std::unique_ptr<FILE, decltype(&fclose)>{fopen(file_name.c_str(), "r"), &fclose};
    if (maps) {
        char *line = nullptr;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&line, &len, maps.get())) > 0) {
            line[read - 1] = '\0';
            uintptr_t start = 0;
            uintptr_t end = 0;
            uintptr_t off = 0;
            ino_t inode = 0;
            unsigned int dev_major = 0;
            unsigned int dev_minor = 0;
            std::array<char, kPermLength> perm{'\0'};
            int path_off;
            if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n%*s", &start,
                       &end, perm.data(), &off, &dev_major, &dev_minor, &inode,
                       &path_off) != kMapEntry) {
                continue;
            }
            while (path_off < read && isspace(line[path_off])) path_off++;
            auto &ref = info.emplace_back(MapInfo{start, end, 0, perm[3] == 'p', off,
                                                  static_cast<dev_t>(makedev(dev_major, dev_minor)),
                                                  inode, line + path_off});
            if (perm[0] == 'r') ref.perms |= PROT_READ;
            if (perm[1] == 'w') ref.perms |= PROT_WRITE;
            if (perm[2] == 'x') ref.perms |= PROT_EXEC;
        }
        free(line);
    }
    return info;
}

ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len) {
    LOGV("write to remote addr %" PRIxPTR " size %zu", remote_addr, len);
    struct iovec local{.iov_base = (void *) buf, .iov_len = len};
    struct iovec remote{.iov_base = (void *) remote_addr, .iov_len = len};
    auto l = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (l == -1) {
        PLOGE("process_vm_writev");
    } else if (static_cast<size_t>(l) != len) {
        LOGW("not fully written: %zu, excepted %zu", l, len);
    }
    return l;
}

ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len) {
    struct iovec local{.iov_base = (void *) buf, .iov_len = len};
    struct iovec remote{.iov_base = (void *) remote_addr, .iov_len = len};
    auto l = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (l == -1) {
        PLOGE("process_vm_readv");
    } else if (static_cast<size_t>(l) != len) {
        LOGW("not fully read: %zu, excepted %zu", l, len);
    }
    return l;
}

bool get_regs(int pid, struct user_regs_struct &regs) {
#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        PLOGE("getregs");
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    struct iovec iov = {
        .iov_base = &regs,
        .iov_len = sizeof(struct user_regs_struct),
    };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        PLOGE("getregs");
        return false;
    }
#endif
    return true;
}

bool set_regs(int pid, struct user_regs_struct &regs) {
#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        PLOGE("setregs");
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    struct iovec iov = {
        .iov_base = &regs,
        .iov_len = sizeof(struct user_regs_struct),
    };
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        PLOGE("setregs");
        return false;
    }
#endif
    return true;
}

std::string get_addr_mem_region(std::vector<MapInfo> &info, uintptr_t addr) {
    for (auto &map : info) {
        if (map.start <= addr && map.end > addr) {
            auto s = std::string(map.path);
            s += ' ';
            s += map.perms & PROT_READ ? 'r' : '-';
            s += map.perms & PROT_WRITE ? 'w' : '-';
            s += map.perms & PROT_EXEC ? 'x' : '-';
            return s;
        }
    }
    return "<unknown>";
}

void *find_module_return_addr(std::vector<MapInfo> &info, std::string_view suffix) {
    for (auto &map : info) {
        if ((map.perms & PROT_EXEC) == 0 && map.path.ends_with(suffix)) {
            return (void *) map.start;
        }
    }
    return nullptr;
}

void *find_module_base(std::vector<MapInfo> &info, std::string_view suffix) {
    for (auto &map : info) {
        if (map.offset == 0 && map.path.ends_with(suffix)) {
            return (void *) map.start;
        }
    }
    return nullptr;
}

void *find_func_addr(std::vector<MapInfo> &local_info, std::vector<MapInfo> &remote_info,
                     std::string_view module, std::string_view func) {
    auto lib = dlopen(module.data(), RTLD_NOW);
    if (lib == nullptr) {
        LOGE("failed to open lib %s: %s", module.data(), dlerror());
        return nullptr;
    }
    auto sym = reinterpret_cast<uint8_t *>(dlsym(lib, func.data()));
    if (sym == nullptr) {
        LOGE("failed to find sym %s in %s: %s", func.data(), module.data(), dlerror());
        dlclose(lib);
        return nullptr;
    }
    LOGD("sym %s: %p", func.data(), sym);
    dlclose(lib);
    auto local_base = reinterpret_cast<uint8_t *>(find_module_base(local_info, module));
    if (local_base == nullptr) {
        LOGE("failed to find local base for module %s", module.data());
        return nullptr;
    }
    auto remote_base = reinterpret_cast<uint8_t *>(find_module_base(remote_info, module));
    if (remote_base == nullptr) {
        LOGE("failed to find remote base for module %s", module.data());
        return nullptr;
    }
    LOGD("found local base %p remote base %p", local_base, remote_base);
    auto addr = (sym - local_base) + remote_base;
    LOGD("addr %p", addr);
    return addr;
}

void align_stack(struct user_regs_struct &regs, long preserve) {
    regs.REG_SP = (regs.REG_SP - preserve) & ~0xf;
}

uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str) {
    auto len = strlen(str) + 1;
    regs.REG_SP -= len;
    align_stack(regs);
    auto addr = static_cast<uintptr_t>(regs.REG_SP);
    if (!write_proc(pid, addr, str, len)) {
        LOGE("failed to write string %s", str);
    }
    LOGD("pushed string %" PRIxPTR, addr);
    return addr;
}

uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr,
                      uintptr_t return_addr, std::vector<long> &args) {
    align_stack(regs);
    LOGV("calling remote function %" PRIxPTR " args %zu", func_addr, args.size());
    for (auto &a : args) {
        LOGV("arg %p", (void *) a);
    }
#if defined(__x86_64__)
    if (args.size() >= 1) {
        regs.rdi = args[0];
    }
    if (args.size() >= 2) {
        regs.rsi = args[1];
    }
    if (args.size() >= 3) {
        regs.rdx = args[2];
    }
    if (args.size() >= 4) {
        regs.rcx = args[3];
    }
    if (args.size() >= 5) {
        regs.r8 = args[4];
    }
    if (args.size() >= 6) {
        regs.r9 = args[5];
    }
    if (args.size() > 6) {
        auto remain = (args.size() - 6) * sizeof(long);
        align_stack(regs, remain);
        if (!write_proc(pid, (uintptr_t) regs.REG_SP, args.data(), remain)) {
            LOGE("failed to push arguments");
        }
    }
    regs.REG_SP -= sizeof(long);
    if (!write_proc(pid, (uintptr_t) regs.REG_SP, &return_addr, sizeof(return_addr))) {
        LOGE("failed to write return addr");
    }
    regs.REG_IP = func_addr;
#elif defined(__i386__)
    if (args.size() > 0) {
        auto remain = (args.size()) * sizeof(long);
        align_stack(regs, remain);
        if (!write_proc(pid, (uintptr_t) regs.REG_SP, args.data(), remain)) {
            LOGE("failed to push arguments");
        }
    }
    regs.REG_SP -= sizeof(long);
    if (!write_proc(pid, (uintptr_t) regs.REG_SP, &return_addr, sizeof(return_addr))) {
        LOGE("failed to write return addr");
    }
    regs.REG_IP = func_addr;
#elif defined(__aarch64__)
    for (size_t i = 0; i < args.size() && i < 8; i++) {
        regs.regs[i] = args[i];
    }
    if (args.size() > 8) {
        auto remain = (args.size() - 8) * sizeof(long);
        align_stack(regs, remain);
        write_proc(pid, (uintptr_t) regs.REG_SP, args.data(), remain);
    }
    regs.regs[30] = return_addr;
    regs.REG_IP = func_addr;
#elif defined(__arm__)
    for (size_t i = 0; i < args.size() && i < 4; i++) {
        regs.uregs[i] = args[i];
    }
    if (args.size() > 4) {
        auto remain = (args.size() - 4) * sizeof(long);
        align_stack(regs, remain);
        write_proc(pid, (uintptr_t) regs.REG_SP, args.data(), remain);
    }
    regs.uregs[14] = return_addr;
    regs.REG_IP = func_addr;
    constexpr auto CPSR_T_MASK = 1lu << 5;
    if ((regs.REG_IP & 1) != 0) {
        regs.REG_IP = regs.REG_IP & ~1;
        regs.uregs[16] = regs.uregs[16] | CPSR_T_MASK;
    } else {
        regs.uregs[16] = regs.uregs[16] & ~CPSR_T_MASK;
    }
#endif
    if (!set_regs(pid, regs)) {
        LOGE("failed to set regs");
        return 0;
    }
    ptrace(PTRACE_CONT, pid, 0, 0);
    int status;
    wait_for_trace(pid, &status, __WALL);
    if (!get_regs(pid, regs)) {
        LOGE("failed to get regs after call");
        return 0;
    }
    if (WSTOPSIG(status) == SIGSEGV) {
        if (static_cast<uintptr_t>(regs.REG_IP) != return_addr) {
            LOGE("wrong return addr %p", (void *) regs.REG_IP);
            return 0;
        }
        return regs.REG_RET;
    } else {
        LOGE("stopped by other reason %s at addr %p", parse_status(status).c_str(),
             (void *) regs.REG_IP);
    }
    return 0;
}

int fork_dont_care() {
    auto pid = fork();
    if (pid < 0) {
        PLOGE("fork 1");
    } else if (pid == 0) {
        pid = fork();
        if (pid < 0) {
            PLOGE("fork 2");
        } else if (pid > 0) {
            exit(0);
        }
    } else {
        int status;
        waitpid(pid, &status, __WALL);
    }
    return pid;
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
            PLOGE("waitpid(%d) failed", pid);
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
            LOGE("Process %d did not stop as expected: %s. Exiting.", pid,
                 parse_status(*status).c_str());
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
