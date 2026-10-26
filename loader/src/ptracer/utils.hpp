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
                      uintptr_t return_addr, std::vector<long> &args, bool *ok = nullptr);

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

/// The module directory, resolved once from /proc/self/exe. Every path the monitor and the
/// tracer need is built from this, not from the working directory, which a reinstall
/// invalidates and a root shell never sets sensibly.
const std::string &get_module_dir();

/// Reads /proc/<pid>/comm, the thread name, without the trailing newline. Not argv[0]: a
/// zygote reports "main" here, while system_server does set its name. Empty when unreadable.
std::string get_comm(pid_t pid);

/// Reads the parent pid from /proc/<pid>/status, or -1 when unreadable.
pid_t get_ppid(pid_t pid);

/// Reads /proc/<pid>/cmdline as the argument vector it stores. Unlike comm, this sees the
/// "zygote64" a zygote writes over its own argv[0]. Empty when unreadable.
std::vector<std::string> read_cmdline(pid_t pid);

/// Finds every live process whose /proc/<pid>/exe resolves to this path, the same key the
/// monitor's spawn path matches on, so the two agree. Callers separate zygotes from
/// system_server by comm, since it is a forked zygote with the same executable.
std::vector<pid_t> find_processes_by_exe(std::string_view exe);

/// Reads the single-letter state from /proc/<pid>/status: 'T' for a process stopped by a
/// signal, 't' for one in a ptrace stop. Zero when unreadable.
char get_process_state(pid_t pid);

/// Reads the pid tracing this process from /proc/<pid>/status: its pid, 0 when untraced, or
/// -1 when unreadable. Only one process may trace init, which makes this the answer to "is a
/// monitor still attached": its socket closes before it dies, so a replacement waits out the
/// attachment.
pid_t get_tracer_pid(pid_t pid);

/// Tests whether argv says this is a zygote, in either of the two shapes it has. The
/// executable and init parentage are not enough: anything a boot script backgrounds is
/// reparented to init, and a framework's daemon is typically app_process under a
/// --nice-name. argv settles it -- init passes --zygote, and argv[0] becomes "zygote64" --
/// while comm stays "main" through both.
bool has_zygote_cmdline(pid_t pid);

/// Finds every running zygote of this build's own ABI, the only one it can inject.
std::vector<pid_t> find_zygotes();

/// Tests whether a process already has a library whose path contains this suffix mapped.
/// How the rearm path tells a bare process from an injected one, read from the tracee
/// itself rather than from monitor state a previous instance would not have shared. It says
/// nothing about hooks: only the daemon's heartbeat does.
bool has_library_mapped(pid_t pid, std::string_view suffix);
