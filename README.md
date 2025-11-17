# ShamrockZygisk

ShamrockZygisk is a Zygote injection module, implemented via [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html), that provides Zygisk API support for APatch and KernelSU.
It also functions as a powerful replacement for Magisk's built-in Zygisk.

## Core Principles

ShamrockZygisk is engineered with four key objectives:

1.  **API Compatibility:** Maintains full API compatibility with [Magisk's built-in Zygisk](https://github.com/topjohnwu/Magisk/tree/master/native/src/core/zygisk). The relevant API designs are mirrored in the source folder [injector](https://github.com/JingMatrix/ShamrockZygisk/tree/master/loader/src/injector) for reference.
2.  **Minimalist Design:** Focuses on a lean and efficient implementation of the Zygisk API, avoiding feature bloat to ensure stability and performance.
3.  **Trace Cleaning:** Guarantees the complete removal of its injection traces from application processes once all Zygisk modules are unloaded.
4.  **Advanced Stealth:** Employs a sophisticated DenyList to provide granular control over root and module visibility, effectively hiding the traces of your root solution.

## The DenyList Explained

Modern systemless root solutions operate by creating overlay filesystems using [`mount`](https://man7.org/linux/man-pages/man8/mount.8.html) rather than directly modifying system partitions. The DenyList is a core feature designed to hide these modifications by precisely controlling the [mount namespaces](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html) for each application process.

Here is how ShamrockZygisk manages visibility for different application states:

| Application State | Mount Namespace Visibility | Description & Use Case |
| :--- | :--- | :--- |
| **Granted Root Privileges** | Root Solution Mounts + Module Mounts | For trusted applications that require full root access to function correctly (e.g., advanced file managers). |
| **On DenyList** | Clean, Unmodified Mount Namespace | Provides a pristine environment for applications that perform root detection. The app's root privileges might be revoked, and all traces of root and module mounts are hidden. |

To achieve a clean mount namespace for applications on the DenyList, ShamrockZygisk employs two distinct strategies: a primary, aggressive approach and a reliable fallback.

1.  **Direct Zygote Unmounting (Primary Strategy)**
    As an experimental feature for bypassing advanced detection, ShamrockZygisk attempts to unmount all root-related traces directly from the zygote process itself. This cleans the environment *before* an application process is fully specialized, offering a potentially more robust hiding mechanism. To ensure system stability, this operation is only performed after a strict safety check. If a module is providing critical system resources (e.g., an overlay in `/product`), this direct unmount is aborted to prevent a zygote crash.

2.  **Namespace Switching (Fallback Strategy)**
    If the direct unmount strategy is aborted for safety, or if any traces failed to unmount, ShamrockZygisk reverts to its standard, reliable method. After an app process forks, the `setns` syscall is used to switch it into a cached, completely clean mount namespace, effectively isolating it from all system modifications.

## Configuration

To configure the DenyList for a specific application, use the appropriate setting within your root management app:

*   **For APatch/KernelSU:** Enable the **`Umount modules`** option for your target application.
*   **For Magisk:** Use the **`Configure DenyList`** menu.

> **Important Note for Magisk Users**
>
> The **`Enforce DenyList`** option in Magisk enables Magisk's *own* DenyList implementation. This is separate from ShamrockZygisk's functionality, is not guaranteed to hide all mount-related traces, and may conflict with ShamrockZygisk's hiding mechanisms. It is strongly recommended to leave this option disabled and rely solely on ShamrockZygisk's configuration.
