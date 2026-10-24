#pragma once
#include <sys/ptrace.h>

#include <cstdint>
#include <string>
#include <vector>

struct MapInfo {
    /// \brief The start address of the memory region.
    uintptr_t start;
    /// \brief The end address of the memory region.
    uintptr_t end;
    /// \brief The permissions of the memory region. This is a bit mask of the following values:
    /// - PROT_READ
    /// - PROT_WRITE
    /// - PROT_EXEC
    uint8_t perms;
    /// \brief Whether the memory region is private.
    bool is_private;
    /// \brief The offset of the memory region.
    uintptr_t offset;
    /// \brief The device number of the memory region.
    /// Major can be obtained by #major()
    /// Minor can be obtained by #minor()
    dev_t dev;
    /// \brief The inode number of the memory region.
    ino_t inode;
    /// \brief The path of the memory region.
    std::string path;

    /// \brief Scans /proc/self/maps and returns a list of \ref MapInfo entries.
    /// This is useful to find out the inode of the library to hook.
    /// \return A list of \ref MapInfo entries.
    static std::vector<MapInfo> Scan(const std::string &pid = "self");
};

#if defined(__x86_64__)
#define REG_SP rsp
#define REG_IP rip
#define REG_RET rax
#define REG_SYSNR orig_rax
#elif defined(__i386__)
#define REG_SP esp
#define REG_IP eip
#define REG_RET eax
#define REG_SYSNR orig_eax
#elif defined(__aarch64__)
#define REG_SP sp
#define REG_IP pc
#define REG_RET regs[0]
#define REG_SYSNR regs[8]
#elif defined(__arm__)
#define REG_SP uregs[13]
#define REG_IP uregs[15]
#define REG_RET uregs[0]
#define REG_SYSNR uregs[7]
#define user_regs_struct user_regs
#endif

ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len);

ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len);

bool get_regs(int pid, struct user_regs_struct &regs);

bool set_regs(int pid, struct user_regs_struct &regs);

std::string get_addr_mem_region(std::vector<MapInfo> &info, uintptr_t addr);

void *find_module_base(const std::vector<MapInfo> &info, std::string_view suffix);

void *find_func_addr(const std::vector<MapInfo> &local_info,
                     const std::vector<MapInfo> &remote_info, std::string_view module,
                     std::string_view func);

void align_stack(struct user_regs_struct &regs, long preserve = 0);

uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str);

uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr,
                      uintptr_t return_addr, std::vector<long> &args);

int fork_dont_care();

void wait_for_trace(int pid, int *status, int flags);

std::string parse_status(int status);

#define WPTEVENT(x) (x >> 16)

#define CASE_CONST_RETURN(x)                                                                       \
    case x:                                                                                        \
        return #x;

inline const char *parse_ptrace_event(int status) {
    status = status >> 16;
    switch (status) {
        CASE_CONST_RETURN(PTRACE_EVENT_FORK)
        CASE_CONST_RETURN(PTRACE_EVENT_VFORK)
        CASE_CONST_RETURN(PTRACE_EVENT_CLONE)
        CASE_CONST_RETURN(PTRACE_EVENT_EXEC)
        CASE_CONST_RETURN(PTRACE_EVENT_VFORK_DONE)
        CASE_CONST_RETURN(PTRACE_EVENT_EXIT)
        CASE_CONST_RETURN(PTRACE_EVENT_SECCOMP)
        CASE_CONST_RETURN(PTRACE_EVENT_STOP)
    default:
        return "(no event)";
    }
}

inline const char *sigabbrev_np(int sig) {
    if (sig > 0 && sig < NSIG) return sys_signame[sig];
    return "(unknown)";
}

std::string get_program(int pid);
void *find_module_return_addr(const std::vector<MapInfo> &info, std::string_view suffix);

/// \brief Reads /proc/<pid>/comm, without the trailing newline.
///
/// Note this is the thread name, not argv[0]. A zygote reports "main" here, because it
/// rewrites its cmdline and never calls prctl(PR_SET_NAME) -- which is why `pidof zygote64`
/// finds it but a comm comparison does not. system_server does set its name.
/// \return The name, or an empty string if it could not be read.
std::string get_comm(pid_t pid);

/// \brief Reads the parent pid from /proc/<pid>/status.
/// \return The parent pid, or -1 if it could not be read.
pid_t get_ppid(pid_t pid);

/// \brief Finds every live process whose /proc/<pid>/exe resolves to \p exe.
///
/// The executable is the same key the monitor's spawn path matches on, so using it here
/// keeps the two paths in agreement -- notably it finds every zygote of this ABI, not just
/// the one named "zygote64". Callers separate zygotes from system_server by comm, since
/// system_server is a forked zygote and shares its executable.
std::vector<pid_t> find_processes_by_exe(std::string_view exe);

/// \brief Tests whether \p pid already has a library whose path contains \p suffix mapped.
/// This is how the rearm path recognises an already-injected process: it reads the
/// tracee's own mappings rather than trusting monitor-side state, which a previous
/// monitor instance would not have shared.
bool has_library_mapped(pid_t pid, std::string_view suffix);
