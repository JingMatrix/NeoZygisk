## 🚀 v2.3 - Robustness & Improved Root Support 🚀

This release focuses on improving stability for older architectures, ensuring compatibility with the latest KernelSU interfaces.

### 🛠 KernelSU & Root Integration
*   **KernelSU Supercall Support**: Implemented the new `ioctl`-based supercall interface for KernelSU (v20000+). This replaces the deprecated `prctl` method, ensuring compatibility with the latest KernelSU versions.
*   **Relaxed Version Checks**: Version limits for KernelSU have been relaxed to support community variants, with warnings now issued in logs instead of strict enforcement.

### 📱 Android 12 & 32-bit Compatibility
*   **Direct FD Passing**: Migrated mount namespace transfers to use Unix domain sockets (`SCM_RIGHTS`). This resolves "Permission denied" errors (Errno 13) encountered on certain Android 12 (arm32) devices when accessing namespace paths via `/proc`.
*   **Ptrace Fallback Mechanism**: Introduced a fallback to `PTRACE_ATTACH` for kernels where `PTRACE_SEIZE` fails with an I/O error. This includes robust signal handling to ignore spurious "noise" signals during the injection process.
*   **Legacy Register Support**: Added support for `PTRACE_GETREGS` and `PTRACE_SETREGS` for 32-bit ARM devices that do not support modern regset interfaces.
*   **Path Correction**: Fixed the executable path for the 32-bit Zygote to correctly point to `/system/bin/app_process32`.

### 🐛 Bug Fixes & Internal Improvements
*   **Socket Communication Fix**: Resolved a critical buffer overwrite bug in `recv_fds` where control message validation was failing due to dummy data corruption.
*   **Improved Fossil Detection**: Enhanced the detection of suspicious "zygote fossils" by monitoring loop device mounts, improving the stealth and cleanliness of the environment.
*   **FD Sealing**: The daemon now gracefully ignores errors when adding seals to module file descriptors, improving compatibility with older or custom kernels that lack full sealing support.
*   **Protocol Synchronization**: Added status byte checks to the communication protocol to prevent stream desynchronization during namespace transfers.
