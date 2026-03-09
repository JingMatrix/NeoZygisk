#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "daemon.hpp"
#include "logging.hpp"
#include "main.hpp"
#include "utils.hpp"

/**
 * @brief Shared logic to remotely load and initialize the injector library.
 */
static bool execute_remote_injection(int pid, struct user_regs_struct &regs, const char *lib_path,
                                     TraceMode mode) {
    auto map = MapInfo::Scan(std::to_string(pid));
    auto local_map = MapInfo::Scan();
    auto libc_return_addr = find_module_return_addr(map, "libc.so");

    // Remotely call dlopen(lib_path, RTLD_NOW)
    LOGV("executing remote call to dlopen(\"%s\")", lib_path);
    auto dlopen_addr = find_func_addr(local_map, map, "libdl.so", "dlopen");
    if (dlopen_addr == nullptr) {
        LOGE("could not find address of dlopen in the target process");
        return false;
    }
    std::vector<long> args;
    auto remote_lib_path = push_string(pid, regs, lib_path);
    args.push_back((long) remote_lib_path);
    args.push_back((long) RTLD_NOW);
    auto remote_handle =
        remote_call(pid, regs, (uintptr_t) dlopen_addr, (uintptr_t) libc_return_addr, args);

    if (remote_handle == 0) {
        LOGE("remote call to dlopen failed, retrieving error message with dlerror");

        auto dlerror_addr = find_func_addr(local_map, map, "libdl.so", "dlerror");
        if (dlerror_addr == nullptr) {
            LOGE("could not find address of dlerror; cannot retrieve error string");
            return false;
        }

        // Remotely call dlerror() (takes no arguments)
        args.clear();
        auto dlerror_str_addr =
            remote_call(pid, regs, (uintptr_t) dlerror_addr, (uintptr_t) libc_return_addr, args);

        if (dlerror_str_addr == 0) {
            LOGE("remote call to dlerror returned null");
            return false;
        }

        auto strlen_addr = find_func_addr(local_map, map, "libc.so", "strlen");
        if (strlen_addr == nullptr) {
            LOGE("could not find address of strlen; cannot measure error string length");
            return false;
        }

        // Remotely call strlen(dlerror_str_addr)
        args.clear();
        args.push_back(dlerror_str_addr);
        auto dlerror_len =
            remote_call(pid, regs, (uintptr_t) strlen_addr, (uintptr_t) libc_return_addr, args);

        if (dlerror_len <= 0) {
            LOGE("dlerror string length is invalid (%" PRIuPTR ")", dlerror_len);
            return false;
        }

        // Read the actual error string from system_server's memory
        std::string err;
        err.resize(dlerror_len + 1, 0);
        read_proc(pid, (uintptr_t) dlerror_str_addr, err.data(), dlerror_len);

        LOGE("dlopen error: %s", err.c_str());
        return false;
    }

    LOGI("successfully loaded library via remote dlopen, handle: 0x%" PRIxPTR, remote_handle);

    // Remotely call dlsym(handle, "entry")
    LOGV("executing remote call to dlsym to find the 'entry' symbol");
    auto dlsym_addr = find_func_addr(local_map, map, "libdl.so", "dlsym");
    if (dlsym_addr == nullptr) {
        LOGE("could not find address of dlsym in the target process");
        return false;
    }
    args.clear();
    auto remote_entry_str = push_string(pid, regs, "entry");
    args.push_back(remote_handle);
    args.push_back((long) remote_entry_str);
    auto injector_entry =
        remote_call(pid, regs, (uintptr_t) dlsym_addr, (uintptr_t) libc_return_addr, args);

    if (injector_entry == 0) {
        LOGE("dlsym failed to find the 'entry' symbol in the injected library");
        return false;
    }
    LOGI("found injector entry point at address 0x%" PRIxPTR, injector_entry);

    // Find the address range of the injected library to pass to its entry function.
    map = MapInfo::Scan(std::to_string(pid));
    void *start_addr = nullptr;
    size_t block_size = 0;
    for (const auto &info : map) {
        if (info.path.find("libzygisk.so") != std::string::npos) {
            if (start_addr == nullptr) start_addr = (void *) info.start;
            block_size += (info.end - info.start);
        }
    }
    LOGV("found injected library mapped from %p with total size %zu", start_addr, block_size);

    // Remotely call our entry(start_addr, block_size, path) function
    LOGI("calling the injector's entry function to initialize NeoZygisk");
    args.clear();
    args.push_back((uintptr_t) start_addr);
    args.push_back(block_size);
    auto remote_tmp_path = push_string(pid, regs, zygiskd::GetTmpPath().c_str());
    args.push_back((long) remote_tmp_path);
    args.push_back(mode);
    remote_call(pid, regs, injector_entry, (uintptr_t) libc_return_addr, args);

    return true;
}

/**
 * @brief Injects a shared library into a running process at its main entry point.
 *
 * This function orchestrates the core injection logic. It attaches to the target process,
 * intercepts its execution just before the first instruction, and uses this opportunity
 * to load a shared library (`libzygisk.so`) into the process's address space.
 *
 * The strategy is as follows:
 * 1.  **Parse Kernel Argument Block**: Read the process's stack to find the location of program
 *     arguments, environment variables, and the ELF Auxiliary Vector (auxv).
 * 2.  **Find Entry Point**: From the auxv, extract the `AT_ENTRY` value, which is the memory
 *     address of the program's first executable instruction. The dynamic linker has already
 *     run at this stage, making libraries like `libdl.so` available.
 * 3.  **Hijack Execution**: Overwrite the `AT_ENTRY` value in the process's memory with a
 *     deliberately invalid address. When the process is resumed, it will immediately trigger a
 *     segmentation fault (`SIGSEGV`), which we, as the tracer, can catch. This is a reliable
 *     way to pause the process at the perfect moment.
 * 4.  **execute_remote_injection**: Once the process is paused, we restore the original entry
 * point. We then use `ptrace` to execute functions within the target process's context.
 *     - Remotely call `dlopen()` to load our library.
 *     - Remotely call `dlsym()` to find the address of our library's `entry` function.
 *     - Remotely call our `entry` function to initialize NeoZygisk.
 * 5.  **Restore State**: After injection, restore all CPU registers, which allows the original
 *     entry point to be called when the process is fully resumed.
 *
 * @param pid The Process ID of the target (e.g., Zygote).
 * @param lib_path The absolute path to the shared library to be injected.
 * @return True on successful injection, false otherwise.
 */
bool inject_before_start(int pid, const char *lib_path, TraceMode mode) {
    LOGI("starting early library injection for PID: %d, library: %s", pid, lib_path);

    // Backup of the target's registers, to be restored before detaching.
    struct user_regs_struct regs{}, backup{};
    auto map = MapInfo::Scan(std::to_string(pid));
    if (!get_regs(pid, regs)) {
        LOGE("failed to get registers for PID %d, injection aborted", pid);
        return false;
    }

    // --- Step 1 & 2: Parse Kernel Argument Block to Find Entry Point ---
    // The stack pointer (SP) at process startup points to the Kernel Argument Block.
    // We parse this structure to locate argc, argv, envp, and the auxiliary vector (auxv).
    // Ref:
    // https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/private/KernelArgumentBlock.h
    LOGV("reading kernel argument block from stack pointer: 0x%lx", (unsigned long) regs.REG_SP);
    auto sp = static_cast<uintptr_t>(regs.REG_SP);

    int argc;
    read_proc(pid, sp, &argc, sizeof(argc));

    auto argv = reinterpret_cast<char **>(sp + sizeof(uintptr_t));
    auto envp = argv + argc + 1;

    // Iterate past the environment variables to find the start of the auxiliary vector.
    // The end of envp is marked by a null pointer.
    auto p = envp;
    while (true) {
        uintptr_t val;
        read_proc(pid, (uintptr_t) p, &val, sizeof(val));
        if (val != 0) {
            p++;
        } else {
            break;
        }
    }
    p++;  // Skip the final null pointer to get to auxv.
    auto auxv = reinterpret_cast<ElfW(auxv_t) *>(p);
    LOGV("parsed process startup info: argc=%d, argv=%p, envp=%p, auxv=%p", argc, argv, envp, auxv);

    // Now, scan the auxiliary vector to find AT_ENTRY. This gives us the program's
    // entry address, which is where execution will begin.
    uintptr_t entry_addr = 0;
    uintptr_t addr_of_entry_addr = 0;
    auto v = auxv;
    while (true) {
        ElfW(auxv_t) buf;
        read_proc(pid, (uintptr_t) v, &buf, sizeof(buf));
        if (buf.a_type == AT_NULL) {
            break;  // End of auxiliary vector.
        }
        if (buf.a_type == AT_ENTRY) {
            entry_addr = (uintptr_t) buf.a_un.a_val;
            addr_of_entry_addr = (uintptr_t) v + offsetof(ElfW(auxv_t), a_un);
            break;
        }
        v++;
    }

    if (entry_addr == 0) {
        LOGE("failed to find AT_ENTRY in auxiliary vector for PID %d, cannot determine entry point",
             pid);
        return false;
    }
    LOGI("found program entry point at 0x%" PRIxPTR, entry_addr);

    // --- Step 3: Hijack Execution Flow ---
    // We replace the program's entry point with an invalid address. This causes a SIGSEGV
    // as soon as we resume the process, allowing us to regain control at the perfect time.
    LOGV("hijacking entry point to intercept execution");
    // For arm32 compatibility, we set the last bit to the same as the entry address.
    uintptr_t break_addr = (-0x05ec1cff & ~1) | (entry_addr & 1);  // An arbitrary invalid address.
    if (!write_proc(pid, addr_of_entry_addr, &break_addr, sizeof(break_addr))) {
        LOGE("failed to write hijack address to PID %d, injection aborted", pid);
        return false;
    }

    int status;

    while (true) {
        // Resume execution. We pass 0 to signal to suppress any pending SIGSTOPs.
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
            PLOGE("ptrace(PTRACE_CONT) failed");
            return false;
        }

        wait_for_trace(pid, &status, __WALL);

        // 1. Handle Process Death
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            LOGE("process died unexpectedly: %s", parse_status(status).c_str());
            return false;
        }

        // 2. Handle Stops
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            if (sig == SIGSEGV) {
                // SUCCESS: We hit our trap.
                break;
            } else if (sig == SIGSTOP) {
                // NOISE: Spurious stop from PTRACE_ATTACH. Ignore and continue.
                continue;
            } else {
                // ERROR: Unexpected signal (e.g., SIGILL, SIGBUS). Abort.
                LOGE("process stopped for unexpected signal: %d", sig);
                return false;
            }
        }
    }

    // Verify we are truly at the trap
    if (!get_regs(pid, regs)) {
        LOGE("failed to get registers after SIGSEGV for PID %d", pid);
        return false;
    }
    // Sanity check: ensure we stopped at our invalid address.
    if (static_cast<uintptr_t>(regs.REG_IP & ~1) != (break_addr & ~1)) {
        LOGE("process stopped at unexpected address 0x%lx, expected ~0x%" PRIxPTR, regs.REG_IP,
             break_addr);
        return false;
    }

    LOGI("successfully intercepted process %d at its entry point", pid);

    // --- Step 4: Remote Code Execution ---
    // First, restore the original entry point in memory.
    if (!write_proc(pid, addr_of_entry_addr, &entry_addr, sizeof(entry_addr))) {
        LOGE("FATAL: failed to restore original entry point, process %d will not recover", pid);
        return false;
    }

    // Backup the current registers before we start making remote calls.
    memcpy(&backup, &regs, sizeof(regs));

    if (!execute_remote_injection(pid, regs, lib_path, mode)) {
        return false;
    }

    // --- Step 5: Restore State ---
    // Set the instruction pointer back to the original entry address and restore all registers.
    backup.REG_IP = (long) entry_addr;
    LOGI("injection complete, restoring registers before resuming normal execution");
    if (!set_regs(pid, backup)) {
        LOGE("failed to restore original registers for PID %d", pid);
        return false;
    }

    return true;
}

bool inject_after_start(int pid, const char *lib_path, TraceMode mode) {
    LOGI("starting late library injection for PID: %d, library: %s", pid, lib_path);

    struct user_regs_struct regs{}, backup{};
    if (!get_regs(pid, regs)) {
        LOGE("failed to get registers for PID %d, injection aborted", pid);
        return false;
    }

    // Backup current registers (this includes the current Instruction Pointer).
    memcpy(&backup, &regs, sizeof(regs));

    // The process was interrupted and is likely sleeping inside a syscall.
    // If we simply change REG_IP and continue, the kernel's syscall restart logic
    // will kick in and decrement the instruction pointer by 2 (x86) or 4 (ARM),
    // throwing execution into invalid padding bytes (SIGTRAP) before dlopen.
    // We must artificially clear the syscall state from our working registers.
#if defined(__x86_64__)
    regs.orig_rax = -1;
    regs.rax = 0;
#elif defined(__i386__)
    regs.orig_eax = -1;
    regs.eax = 0;
#elif defined(__arm__)
    regs.uregs[17] = -1;  // orig_r0
    regs.uregs[0] = 0;
#elif defined(__aarch64__)
    regs.regs[0] = 0;  // Clear x0 to prevent -ERESTARTSYS match in kernel
#endif

    // Execute the shared remote injection logic
    bool sucess = execute_remote_injection(pid, regs, lib_path, mode);

    // Restore State directly.
    // The instruction pointer (REG_IP) is already correct in the backup.
    LOGI("injection complete, restoring registers before resuming normal execution");
    if (!set_regs(pid, backup)) {
        LOGE("failed to restore original registers for PID %d", pid);
        return false;
    }

    return sucess;
}

// Macro helper to check for specific ptrace stop events.
#define STOPPED_WITH(sig, event)                                                                   \
    (WIFSTOPPED(status) && WSTOPSIG(status) == (sig) && (status >> 16) == (event))

// Common wait routine to avoid repetition.
// Returns false if wait failed or process died unexpectedly.
static bool wait_for_process(int pid, int *status) {
    if (waitpid(pid, status, __WALL) < 0) {
        PLOGE("waitpid on PID %d", pid);
        return false;
    }
    return true;
}

/**
 * @brief Copies the library to a world-readable temporary file to bypass DAC restrictions.
 * @param src_path The original path (e.g., /data/adb/neozygisk/lib64/libzygisk.so)
 * @return The path to the temporary file, or an empty string on failure.
 */
static std::string copy_to_temp(const std::string &src_path) {
    char tmp_path[] = "/data/local/tmp/zygisk_XXXXXX.so";

    // mkstemps securely creates the file with a random 6-character string replacing XXXXXX.
    // The '3' tells it to preserve the ".so" suffix.
    int fd_out = mkstemps(tmp_path, 3);
    if (fd_out < 0) {
        PLOGE("failed to create temporary file in /data/local/tmp");
        return "";
    }

    int fd_in = open(src_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_in < 0) {
        PLOGE("failed to open source library: %s", src_path.c_str());
        close(fd_out);
        unlink(tmp_path);
        return "";
    }

    // Copy contents
    char buf[4096];
    ssize_t bytes_read;
    while ((bytes_read = read(fd_in, buf, sizeof(buf))) > 0) {
        if (write(fd_out, buf, bytes_read) != bytes_read) {
            PLOGE("failed to write to temporary library");
            close(fd_in);
            close(fd_out);
            unlink(tmp_path);
            return "";
        }
    }

    close(fd_in);
    close(fd_out);

    // Make the file world-readable (and executable) so UID 1000 (system_server) can load it.
    if (chmod(tmp_path, 0755) != 0) {
        PLOGE("failed to chmod temporary library %s", tmp_path);
    }

    LOGV("created temporary library copy at: %s", tmp_path);
    return std::string(tmp_path);
}

/**
 * @brief Injects the Zygisk library into the main thread.
 *
 * Shared logic between Seize and Attach methods.
 */
static bool perform_injection(int pid, TraceMode mode) {
    std::string lib_path = zygiskd::GetTmpPath();
    lib_path += "/lib" LP_SELECT("", "64") "/libzygisk.so";
    bool process_started = mode == TraceMode::STANDALONE || mode == TraceMode::SYSTEM_SERVER;

    std::string inject_path = lib_path;
    bool use_temp = false;

    // if (mode == TraceMode::SYSTEM_SERVER) {
    //     inject_path = copy_to_temp(lib_path);
    //     if (inject_path.empty()) {
    //         LOGE("aborting injection: could not create accessible library copy");
    //         return false;
    //     }
    //     use_temp = true;
    // }

    bool success = false;

    if (process_started) {
        success = inject_after_start(pid, inject_path.c_str(), mode);
    } else {
        success = inject_before_start(pid, inject_path.c_str(), mode);
    }

    if (use_temp) {
        LOGV("cleaning up temporary library: %s", inject_path.c_str());
        unlink(inject_path.c_str());
    }

    return success;
}

/**
 * @brief Executes the GKI 2.0 Workaround and detaches.
 *
 * Advances the process by one syscall to clear internal kernel ptrace state
 * before finally detaching.
 */
static bool detach_with_gki_workaround(int pid, int detach_signal) {
    int status;
    LOGV("applying GKI 2.0 workaround (step syscall) before detach");

    // 1. Advance to next syscall entry/exit to clear signal-stop state
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        PLOGE("ptrace(PTRACE_SYSCALL) on PID %d", pid);
        ptrace(PTRACE_DETACH, pid, 0, detach_signal);  // Try to detach anyway
        return false;
    }

    // 2. Wait for the syscall stop
    if (!wait_for_process(pid, &status)) {
        // If wait fails, force detach
        ptrace(PTRACE_DETACH, pid, 0, detach_signal);
        return false;
    }

    // 3. Clean detach
    if (ptrace(PTRACE_DETACH, pid, 0, detach_signal) == -1) {
        PLOGE("ptrace(PTRACE_DETACH) on PID %d", pid);
        return false;
    }
    return true;
}

// --- Strategy 1: PTRACE_SEIZE (Preferred) ---

static bool trace_with_seize(int pid, TraceMode mode) {
    LOGI("attempting trace_seize on PID %d", pid);

    bool process_started = mode == TraceMode::STANDALONE || mode == TraceMode::SYSTEM_SERVER;

    int options = process_started ? 0 : PTRACE_O_EXITKILL;
    // PTRACE_O_EXITKILL ensures target dies if we crash, preventing a zombie state.
    if (ptrace(PTRACE_SEIZE, pid, 0, options) == -1) {
        // We do not return false here immediately; we let the caller handle errno.
        return false;
    }

    if (process_started) {
        // PTRACE_SEIZE does NOT stop the process. We must explicitly interrupt it.
        LOGV("standalone mode: sending PTRACE_INTERRUPT to pause the running process");
        if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
            PLOGE("ptrace(PTRACE_INTERRUPT) on PID %d", pid);
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return false;
        }
    }

    int status;
// Helper macro for local flow control
#define BAIL_AND_DETACH                                                                            \
    ptrace(PTRACE_DETACH, pid, 0, 0);                                                              \
    return false;

    // Wait for the initial Seize stop
    if (!wait_for_process(pid, &status)) return false;

    // Determine the expected stop signal.
    // Normal flow (already SIGSTOPped): SIGSTOP + PTRACE_EVENT_STOP
    // Standalone (PTRACE_INTERRUPT):    SIGTRAP + PTRACE_EVENT_STOP
    bool valid_stop = process_started ? STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP)
                                      : STOPPED_WITH(SIGSTOP, PTRACE_EVENT_STOP);

    if (valid_stop) {
        // 1. Inject Payload
        if (!perform_injection(pid, mode)) {
            BAIL_AND_DETACH
        }

        if (mode == TraceMode::SYSTEM_SERVER) {
            LOGV("system_server injected");
            return true;
        } else if (mode == TraceMode::STANDALONE) {
            // In standalone mode, we interrupted a running process. It doesn't need
            // a SIGCONT to wake up, just a clean detach.
            LOGV("standalone injection complete");
            return true;
        } else {
            LOGV("injection complete, starting signal continuation sequence");

            // 2. Send SIGCONT to the process
            if (kill(pid, SIGCONT) == -1) {
                PLOGE("kill(SIGCONT) on PID %d", pid);
                BAIL_AND_DETACH
            }

            // 3. Resume (PTRACE_CONT)
            if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
                PLOGE("ptrace(PTRACE_CONT) failed");
                BAIL_AND_DETACH
            }
            if (!wait_for_process(pid, &status)) return false;

            // 4. Expect SIGTRAP (caused by the signal interruption in Seize mode)
            if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP)) {
                if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
                    BAIL_AND_DETACH
                }
                if (!wait_for_process(pid, &status)) return false;

                // 5. Expect the actual SIGCONT delivery
                if (STOPPED_WITH(SIGCONT, 0)) {
                    LOGV("received expected SIGCONT");
                    // 6. Workaround + Detach
                    return detach_with_gki_workaround(pid, SIGCONT);
                } else {
                    LOGE("unexpected state after SIGTRAP: %s", parse_status(status).c_str());
                    BAIL_AND_DETACH
                }
            } else {
                LOGE("expected SIGTRAP after CONT, got: %s", parse_status(status).c_str());
                BAIL_AND_DETACH
            }
        }
    } else {
        LOGE("seize attached, but unexpected initial state: %s", parse_status(status).c_str());
        BAIL_AND_DETACH
    }

#undef BAIL_AND_DETACH
    return true;
}

// --- Strategy 2: PTRACE_ATTACH (Fallback) ---

static bool trace_with_attach(int pid, TraceMode mode) {
    LOGI("falling back to trace_attach on PID %d", pid);

    // Classic attach. This sends SIGSTOP to the process immediately.
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        PLOGE("ptrace(PTRACE_ATTACH) on PID %d", pid);
        return false;
    }

    int status;
    if (!wait_for_process(pid, &status)) {
        // If wait fails, we must try to detach or the process hangs forever
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }

    // Classic ATTACH results in a STOPPED status with SIGSTOP.
    // It does NOT use PTRACE_EVENT_STOP in the status bits usually.
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        if (mode == TraceMode::SPAWN) {
            // Set EXITKILL for parity with SEIZE
            ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
        }

        // 1. Inject Payload
        if (!perform_injection(pid, mode)) {
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return false;
        }

        // 2. Detach
        // For classic attach, we don't need the SIGTRAP/SIGCONT dance because
        // we haven't manually sent a SIGCONT via kill().
        // The process is simply stopped by the attach.
        // We use the GKI workaround to ensure the detach is clean.
        // We pass SIGCONT to detach to ensure the process resumes.
        return detach_with_gki_workaround(pid, SIGCONT);

    } else {
        LOGE("attach succeeded but process state unexpected: %s", parse_status(status).c_str());
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }
}

/**
 * @brief Attaches to the target process and initiates the injection.
 *
 * Tries modern PTRACE_SEIZE first. If that fails with I/O error (EIO),
 * falls back to classic PTRACE_ATTACH.
 *
 * @return True on success, false on failure.
 */
bool trace_target(int pid, TraceMode mode) {
    LOGI("attaching to process [PID: %d, mode : %d]", pid, mode);

    // 1. Try SEIZE (Modern, robust handling of group stops)
    if (trace_with_seize(pid, mode)) {
        LOGI("successfully detached from %d (via SEIZE), NeoZygisk active", pid);
        return true;
    }

    // 2. Check for fallback condition
    // PTRACE_SEIZE returns EIO if the process state prohibits seizing,
    // or sometimes if security modules interfere.
    if (errno == EIO) {
        LOGW("PTRACE_SEIZE failed with EIO, attempting fallback to PTRACE_ATTACH");

        if (trace_with_attach(pid, mode)) {
            LOGI("successfully detached from %d (via ATTACH), NeoZygisk active", pid);
            return true;
        }
    } else {
        // If it wasn't EIO (e.g., EPERM, ESRCH), Attach will likely fail too,
        // or the error is fatal.
        PLOGE("PTRACE_SEIZE failed (errno: %d)", errno);
    }

    return false;
}
