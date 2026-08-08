## 🚀 v2.4 - Android 17 & Device Compatibility 🚀

This release adds Android 17 support and resolves injection failures across a range of device, kernel, and emulator configurations.

### 📱 Android 17
*   **Zygote Signatures**: Added the reworked app-specialize signatures for Android 17 (`useFifoUi`, and `cgroupUid` on QPR2) and GrapheneOS 17 (relocated `extraLongArgs`); outdated signatures previously left app processes uninjected. Unresolved signatures are now logged rather than skipped silently.
*   **ProtectedData Symbols**: Added a fallback for the `ProtectedData` (de-)constructor symbols absent on the Android 17 preview.

### 🖥 Device & Kernel Compatibility
*   **ARMv9 BTI**: Cleared the stale `PSTATE.BTYPE` before remote calls, fixing a SIGILL on `dlopen` via ptrace on BTI-enabled hardware such as the Pixel 10 Pro XL.
*   **Nested Zygote Startup**: Added hierarchical tracing through stub processes for `init → stub_zygote → zygote` boot chains, such as some VR headsets.
*   **Emulators**: Updated the SELinux policy to permit reading the mount namespace, fixing root-process namespace updates under AVD (qemu) emulators.
*   **Stack Guard Pages**: Skipped non-readable guard pages when scanning the main stack, fixing a SIGSEGV during system server fork on kernels that report the guard page inside the stack region.

### 🔒 Root & Mounting
*   **KernelSU Unmount**: Disabled KernelSU's in-kernel `kernel_umount`; NeoZygisk now performs module unmounting itself.
*   **Isolated Processes**: Skipped module loading and process-flag retrieval for isolated processes when the daemon is unreachable.
