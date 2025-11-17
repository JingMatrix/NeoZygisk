#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <signal.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
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
#include "utils.hpp"

// Macro helper to check for specific ptrace stop events.
#define STOPPED_WITH(sig, event)                                                                   \
    (WIFSTOPPED(status) && WSTOPSIG(status) == (sig) && (status >> 16) == (event))

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
 * 4.  **Remote Code Execution**: Once the process is paused, we restore the original entry point.
 *     We then use `ptrace` to execute functions within the target process's context.
 *     - Remotely call `dlopen()` to load our library.
 *     - Remotely call `dlsym()` to find the address of our library's `entry` function.
 *     - Remotely call our `entry` function to initialize ShamrockZygisk.
 * 5.  **Restore State**: After injection, restore all CPU registers, which allows the original
 *     entry point to be called when the process is fully resumed.
 *
 * @param pid The Process ID of the target (e.g., Zygote).
 * @param lib_path The absolute path to the shared library to be injected.
 * @return True on successful injection, false otherwise.
 */
bool inject_on_main(int pid, const char *lib_path) {
    LOGI("starting library injection for PID: %d, library: %s", pid, lib_path);

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

    ptrace(PTRACE_CONT, pid, 0, 0);
    int status;
    wait_for_trace(pid, &status, __WALL);

    // We expect the process to stop with a SIGSEGV.
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV) {
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
        map = MapInfo::Scan(std::to_string(pid));  // Re-scan maps as they may have changed.
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
            args.clear();
            auto dlerror_str_addr = remote_call(pid, regs, (uintptr_t) dlerror_addr,
                                                (uintptr_t) libc_return_addr, args);
            if (dlerror_str_addr == 0) {
                LOGE("remote call to dlerror returned null");
                return false;
            }
            auto strlen_addr = find_func_addr(local_map, map, "libc.so", "strlen");
            if (strlen_addr == nullptr) {
                LOGE("could not find address of strlen; cannot measure error string length");
                return false;
            }
            args.clear();
            args.push_back(dlerror_str_addr);
            auto dlerror_len =
                remote_call(pid, regs, (uintptr_t) strlen_addr, (uintptr_t) libc_return_addr, args);
            if (dlerror_len <= 0) {
                LOGE("dlerror string length is invalid (%" PRIuPTR ")", dlerror_len);
                return false;
            }
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
        LOGI("calling the injector's entry function to initialize ShamrockZygisk");
        args.clear();
        args.push_back((uintptr_t) start_addr);
        args.push_back(block_size);
        auto remote_tmp_path = push_string(pid, regs, zygiskd::GetTmpPath().c_str());
        args.push_back((long) remote_tmp_path);
        remote_call(pid, regs, injector_entry, (uintptr_t) libc_return_addr, args);

        // --- Step 5: Restore State ---
        // Set the instruction pointer back to the original entry address and restore all registers.
        backup.REG_IP = (long) entry_addr;
        LOGI("injection complete, restoring registers before resuming normal execution");
        if (!set_regs(pid, backup)) {
            LOGE("failed to restore original registers for PID %d", pid);
            return false;
        }

        return true;
    } else {
        LOGE("process stopped for an unexpected reason: %s", parse_status(status).c_str());
    }
    return false;
}

/**
 * @brief Attaches to the Zygote process and initiates the injection.
 *
 * This function uses ptrace to seize control of the Zygote process right after it starts.
 * It then orchestrates a delicate sequence of signals and continuations to ensure Zygote
 * is correctly resumed after injection, handling special workarounds for modern Android kernels.
 *
 * @param pid The Zygote process ID.
 * @return True on success, false on failure.
 */
bool trace_zygote(int pid) {
    LOGI("attaching to zygote (PID: %d) to begin injection", pid);

    // Convenience macros for the complex wait/continue sequence.
#define WAIT_OR_DIE wait_for_trace(pid, &status, __WALL);
#define CONT_OR_DIE                                                                                \
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {                                                    \
        PLOGE("ptrace(PTRACE_CONT) on PID %d", pid);                                               \
        return false;                                                                              \
    }

    int status;
    LOGI("tracing PID %d from tracer PID %d", pid, getpid());
    // PTRACE_SEIZE is a modern and more robust way to attach than PTRACE_ATTACH.
    // - PTRACE_O_EXITKILL: Ensures the tracee is killed if the tracer exits.
    // - PTRACE_O_TRACESECCOMP: Allows us to trace seccomp events if needed.
    if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP) == -1) {
        PLOGE("ptrace(PTRACE_SEIZE) on PID %d", pid);
        return false;
    }
    WAIT_OR_DIE

    // After seizing, we expect a group-stop, indicated by SIGSTOP and a PTRACE_EVENT_STOP.
    if (STOPPED_WITH(SIGSTOP, PTRACE_EVENT_STOP)) {
        std::string lib_path = zygiskd::GetTmpPath();
        lib_path += "/lib" LP_SELECT("", "64") "/libzygisk.so";
        if (!inject_on_main(pid, lib_path.c_str())) {
            LOGE("failed to inject library into zygote, detaching");
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return false;
        }

        LOGV("injection complete, beginning post-injection continuation sequence");

        // This sequence is critical. A simple PTRACE_DETACH is not sufficient.
        // We must manually shepherd the process through its next few signals.
        if (kill(pid, SIGCONT)) {
            PLOGE("kill(SIGCONT) on PID %d", pid);
            return false;
        }
        CONT_OR_DIE
        WAIT_OR_DIE

        // Expect a SIGTRAP, which is part of the normal post-seize process.
        if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP)) {
            CONT_OR_DIE
            WAIT_OR_DIE

            // Now expect the SIGCONT we sent with kill().
            if (STOPPED_WITH(SIGCONT, 0)) {
                LOGV("received expected SIGCONT, applying GKI 2.0 workaround and detaching");
                // Simple workaround to reset PTRACE_GETEVENTMSG for GKI 2.0 devices.
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                WAIT_OR_DIE
                ptrace(PTRACE_DETACH, pid, 0, SIGCONT);
            } else {
                LOGE("zygote stopped unexpectedly after injection: %s, expected SIGCONT",
                     parse_status(status).c_str());
                ptrace(PTRACE_DETACH, pid, 0, 0);
                return false;
            }
        } else {
            LOGE("zygote stopped unexpectedly after injection: %s, expected SIGTRAP",
                 parse_status(status).c_str());
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return false;
        }
    } else {
        LOGE("attached to zygote, but it was in an unexpected state: %s",
             parse_status(status).c_str());
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }

    LOGI("successfully detached from zygote, ShamrockZygisk should now be active");
    return true;
}
