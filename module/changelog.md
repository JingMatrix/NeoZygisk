### 🐛 Bug Fixes & Improvements 🛠️

This is a hotfix release to address a critical bug introduced by a pre-release version of NDK (r29).
This bug caused the `munmap` call in `libzygisk.so` to fail, leaving behind clear traces of NeoZygisk's injection.

In addition to squashing that pesky bug, we've packed in a few other enhancements:

*   **🚀 Added support for KernelSU Next!** You can now use NeoZygisk with `com.rifsxd.ksunext`.
*   **🛡️ Patched detection points in LSPlt.** We've addressed some recently discovered detection methods.
*   **🔧 Fixed a kernel exploit.** A detection point related to a `ptrace_message` bug in Linux kernels prior to v6.1 has been resolved.
*   **💥 Corrected a Zygote crash.** We've fixed an issue where module overlays could cause Zygote to crash.
