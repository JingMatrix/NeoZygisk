// src/root_impl/kernelsu.rs

//! Detection and interaction logic for the KernelSU root solution.
//!
//! This module provides a unified API to interface with KernelSU, abstracting away the
//! underlying communication details. It is designed with backwards compatibility in mind,
//! supporting both the modern `ioctl` interface and the legacy `prctl` interface.
//!
//! The core design revolves around a one-shot detection mechanism. On the first call to
//! any function in this module, `detect_version`'s initialization logic runs once.
//! It first attempts to connect using the modern `ioctl` method. If that fails, it falls
//! back to the legacy `prctl` method. The result of this detection—including the determined
//! communication method and version status—is cached globally for the lifetime of the process.
//! All subsequent calls are then dispatched to the correct implementation instantly,
//! avoiding any repeated detection overhead.

use crate::constants::{MAX_KSU_VERSION, MIN_KSU_VERSION};
use std::ffi::c_char;
use std::fs;
use std::os::fd::RawFd;
use std::path::Path;
use std::sync::OnceLock;

// --- KernelSU Communication Method Enum & Cached State ---

/// Represents the detected communication method for the current KernelSU version.
/// This enum is central to dispatching calls to the correct implementation.
#[derive(Clone, Copy)]
enum Method {
    /// Modern ioctl interface via a dedicated file descriptor. The `RawFd` is cached
    /// here to be reused for all subsequent communication.
    Ioctl(RawFd),
    /// Legacy prctl interface, used by older KernelSU versions.
    Prctl,
}

/// Represents the complete, immutable result of the one-time detection process.
/// Caching this entire struct ensures all necessary information is available atomically.
#[derive(Clone, Copy)]
struct DetectionResult {
    /// The communication channel to use (ioctl or prctl).
    method: Method,
    /// The determined version status of KernelSU.
    version: Version,
}

/// Lazily initialized detection result. This `OnceLock` is the cornerstone of the module's
/// one-shot detection and caching strategy. It ensures that the detection logic is
/// thread-safe and executes exactly once.
static KSU_RESULT: OnceLock<Option<DetectionResult>> = OnceLock::new();

// --- Modern `ioctl` Interface Constants and Structs ---

/// Magic numbers used in the `reboot` syscall to request a KernelSU driver file descriptor.
const KSU_INSTALL_MAGIC1: u32 = 0xDEADBEEF;
const KSU_INSTALL_MAGIC2: u32 = 0xCAFEBABE;

/// ioctl command codes. These must match the definitions in the KernelSU driver.
const KSU_IOCTL_GET_INFO: u32 = 0x80004b02;
const KSU_IOCTL_UID_GRANTED_ROOT: u32 = 0xc0004b09;
const KSU_IOCTL_UID_SHOULD_UMOUNT: u32 = 0xc0004b0a;
const KSU_IOCTL_GET_MANAGER_UID: u32 = 0x80004b0b;

/// Data structures for ioctl commands.
/// The `#[repr(C)]` attribute is critical to ensure that the memory layout of these
/// Rust structs is identical to their C counterparts in the kernel, preventing data
/// corruption during FFI calls.
#[repr(C)]
struct KsuGetInfoCmd {
    version: u32,
    flags: u32,
    features: u32,
}

#[repr(C)]
struct KsuUidGrantedRootCmd {
    uid: u32,
    granted: u8,
}

#[repr(C)]
struct KsuUidShouldUmountCmd {
    uid: u32,
    should_umount: u8,
}

#[repr(C)]
struct KsuGetManagerUidCmd {
    uid: u32,
}

// --- Legacy `prctl` Interface Constants ---

/// The magic number identifying KernelSU-specific prctl commands.
const KERNEL_SU_OPTION: i32 = 0xdeadbeefu32 as i32;
/// prctl command codes for the legacy interface.
const CMD_GET_VERSION: usize = 2;
const CMD_UID_GRANTED_ROOT: usize = 12;
const CMD_UID_SHOULD_UMOUNT: usize = 13;
const CMD_GET_MANAGER_UID: usize = 16;
/// Special prctl command to detect KernelSU variants (e.g., "Next").
const CMD_HOOK_MODE: usize = 0xC0DEAD1A;

/// Represents detected variants of KernelSU, which had slightly different behavior
/// in the legacy prctl implementation.
#[derive(Clone, Copy, Debug)]
enum KernelSuVariant {
    Official,
    Next,
}

/// Lazily initialized variant for the legacy prctl method. Only used if fallback occurs.
static LEGACY_VARIANT: OnceLock<KernelSuVariant> = OnceLock::new();
/// Lazily initialized capability flag for the legacy prctl method. Only used if fallback occurs.
static LEGACY_SUPPORTS_MANAGER_UID: OnceLock<bool> = OnceLock::new();

/// Represents the detected version status of KernelSU, independent of the communication method.
#[derive(Clone, Copy)]
pub enum Version {
    Supported,
    TooOld,
}

// --- Core Detection and Dispatch Logic ---

/// Detects if KernelSU is active and its version, determining the correct communication method.
/// This function implements the "ioctl-first, prctl-fallback" strategy and caches the result.
pub fn detect_version() -> Option<Version> {
    // `get_or_init` ensures the complex detection logic within the closure runs exactly once.
    // The closure's return value of type `Option<DetectionResult>` is then cached in `KSU_RESULT`.
    let result = KSU_RESULT.get_or_init(|| {
        // --- Stage 1: Attempt to use the modern ioctl interface ---
        // This is the preferred method for modern KernelSU versions.
        if let Some(fd) = init_driver_fd() {
            let mut cmd = KsuGetInfoCmd {
                version: 0,
                flags: 0,
                features: 0,
            };
            if ksuctl_ioctl(fd, KSU_IOCTL_GET_INFO, &mut cmd).is_ok() {
                let version_code = cmd.version as i32;
                if version_code > 0 {
                    // Success! A valid version was returned via ioctl.
                    let method = Method::Ioctl(fd);
                    if (MIN_KSU_VERSION..=MAX_KSU_VERSION).contains(&version_code)
                        && Path::new("/data/adb/ksud").exists()
                    {
                        // Version is supported and ksud exists. Cache the result and finish.
                        return Some(DetectionResult {
                            method,
                            version: Version::Supported,
                        });
                    } else if version_code < MIN_KSU_VERSION {
                        // Version is too old but detected. Cache the result and finish.
                        return Some(DetectionResult {
                            method,
                            version: Version::TooOld,
                        });
                    }
                    // If version is too high or ksud is missing, we fall through, treating it
                    // as if this method failed to allow the prctl fallback to run.
                }
            }
        }

        // --- Stage 2: Fallback to the legacy prctl interface ---
        // This block only executes if the ioctl method fails to yield a valid result.
        let mut version_code = 0;
        unsafe {
            // Safety: This is an FFI call. We provide a valid pointer to a stack variable.
            libc::prctl(
                KERNEL_SU_OPTION,
                CMD_GET_VERSION,
                &mut version_code as *mut i32,
                0,
                0,
            );
        }

        if version_code > 0 {
            // Success with prctl. We must now probe for legacy capabilities.
            init_legacy_variant_probe();
            let method = Method::Prctl;
            if (MIN_KSU_VERSION..=MAX_KSU_VERSION).contains(&version_code)
                && Path::new("/data/adb/ksud").exists()
            {
                return Some(DetectionResult {
                    method,
                    version: Version::Supported,
                });
            } else if version_code < MIN_KSU_VERSION {
                return Some(DetectionResult {
                    method,
                    version: Version::TooOld,
                });
            }
        }

        // --- Stage 3: Failure ---
        // If both the ioctl and prctl methods fail, KernelSU is not detected.
        None
    });

    // After the cache is populated (or retrieved), map the cached `DetectionResult`
    // to this function's public return type, `Option<Version>`.
    result.as_ref().map(|r| r.version)
}

/// Checks if a UID has been granted root by KernelSU.
/// This is a high-level dispatcher function. It checks the cached detection result
/// and calls the appropriate low-level implementation.
pub fn uid_granted_root(uid: i32) -> bool {
    match KSU_RESULT.get().and_then(|opt| opt.as_ref()) {
        Some(result) => match result.method {
            Method::Ioctl(fd) => uid_granted_root_ioctl(fd, uid),
            Method::Prctl => uid_granted_root_prctl(uid),
        },
        None => false,
    }
}

/// Checks if a UID is on the unmount list in KernelSU.
/// This is a high-level dispatcher function.
pub fn uid_should_umount(uid: i32) -> bool {
    match KSU_RESULT.get().and_then(|opt| opt.as_ref()) {
        Some(result) => match result.method {
            Method::Ioctl(fd) => uid_should_umount_ioctl(fd, uid),
            Method::Prctl => uid_should_umount_prctl(uid),
        },
        None => false,
    }
}

/// Checks if a UID belongs to the KernelSU manager app.
/// This is a high-level dispatcher function.
pub fn uid_is_manager(uid: i32) -> bool {
    match KSU_RESULT.get().and_then(|opt| opt.as_ref()) {
        Some(result) => match result.method {
            Method::Ioctl(fd) => uid_is_manager_ioctl(fd, uid),
            Method::Prctl => uid_is_manager_prctl(uid),
        },
        None => false,
    }
}

// --- `ioctl` Implementation Details ---

/// Scans `/proc/self/fd` to find an existing driver file descriptor.
/// This is an important optimization to avoid the `reboot` syscall if the fd
/// has already been opened, for example, by a parent process.
fn scan_driver_fd() -> Option<RawFd> {
    let fd_dir = fs::read_dir("/proc/self/fd").ok()?;
    for entry in fd_dir.flatten() {
        if let Ok(target) = fs::read_link(entry.path()) {
            if target.to_string_lossy().contains("[ksu_driver]") {
                return entry.file_name().to_string_lossy().parse().ok();
            }
        }
    }
    None
}

/// Initializes the driver file descriptor. It first attempts to scan for an
/// existing one and falls back to the `reboot` syscall "secret knock" if none is found.
fn init_driver_fd() -> Option<RawFd> {
    if let Some(fd) = scan_driver_fd() {
        return Some(fd);
    }

    let mut fd: RawFd = -1;
    unsafe {
        // Safety: This is a raw syscall. The kernel expects specific magic numbers
        // and a valid pointer to write the resulting file descriptor into.
        libc::syscall(
            libc::SYS_reboot,
            KSU_INSTALL_MAGIC1,
            KSU_INSTALL_MAGIC2,
            0,
            &mut fd,
        );
    }
    if fd >= 0 { Some(fd) } else { None }
}

/// A safe, generic wrapper around the `ioctl` syscall, matching the style of the
/// official KernelSU Manager for consistency.
fn ksuctl_ioctl<T>(fd: RawFd, request: u32, arg: *mut T) -> std::io::Result<()> {
    // Safety: FFI call. `fd` must be a valid file descriptor, and `arg` must
    // point to a valid memory region for a `#[repr(C)]` struct.
    let ret = unsafe { libc::ioctl(fd, request as _, arg) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `ioctl` implementation for checking if a UID has root.
fn uid_granted_root_ioctl(fd: RawFd, uid: i32) -> bool {
    let mut cmd = KsuUidGrantedRootCmd {
        uid: uid as u32,
        granted: 0,
    };
    ksuctl_ioctl(fd, KSU_IOCTL_UID_GRANTED_ROOT, &mut cmd)
        .map(|_| cmd.granted != 0)
        .unwrap_or(false)
}

/// `ioctl` implementation for checking if a UID should have mounts unmounted.
fn uid_should_umount_ioctl(fd: RawFd, uid: i32) -> bool {
    let mut cmd = KsuUidShouldUmountCmd {
        uid: uid as u32,
        should_umount: 0,
    };
    ksuctl_ioctl(fd, KSU_IOCTL_UID_SHOULD_UMOUNT, &mut cmd)
        .map(|_| cmd.should_umount != 0)
        .unwrap_or(false)
}

/// `ioctl` implementation for checking if a UID is the manager app.
fn uid_is_manager_ioctl(fd: RawFd, uid: i32) -> bool {
    let mut cmd = KsuGetManagerUidCmd { uid: 0 };
    if ksuctl_ioctl(fd, KSU_IOCTL_GET_MANAGER_UID, &mut cmd).is_ok() {
        return uid as u32 == cmd.uid;
    }
    false
}

// --- `prctl` Implementation Details ---

/// Probes and caches capabilities for the legacy prctl method.
/// This is necessary because the old API was not unified, and different KernelSU
/// versions or variants had different feature sets that must be detected at runtime.
fn init_legacy_variant_probe() {
    LEGACY_VARIANT.get_or_init(|| {
        let mut mode: [c_char; 16] = [0; 16];
        unsafe {
            // Safety: FFI call. `mode.as_mut_ptr()` provides a valid buffer.
            libc::prctl(
                KERNEL_SU_OPTION,
                CMD_HOOK_MODE,
                mode.as_mut_ptr() as usize,
                0,
                0,
            );
        }
        if mode[0] != 0 {
            KernelSuVariant::Next
        } else {
            KernelSuVariant::Official
        }
    });

    LEGACY_SUPPORTS_MANAGER_UID.get_or_init(|| {
        let mut result_ok: i32 = 0;
        unsafe {
            // Safety: FFI call. We provide a valid pointer to check for support.
            libc::prctl(
                KERNEL_SU_OPTION,
                CMD_GET_MANAGER_UID,
                0,
                0,
                &mut result_ok as *mut _ as usize,
            );
        }
        // The prctl interface confirms support by writing back the magic number.
        result_ok as u32 == KERNEL_SU_OPTION as u32
    });
}

/// A safe wrapper for the legacy boolean `prctl` commands.
/// This function handles the specific API contract of the old interface, where
/// success is indicated by the kernel writing back a magic number.
fn ksu_prctl_bool_query(command: usize, uid: i32) -> Option<bool> {
    let mut result_payload: bool = false;
    let mut result_ok: u32 = 0;
    unsafe {
        // Safety: FFI call. We provide valid pointers for the two output parameters.
        libc::prctl(
            KERNEL_SU_OPTION,
            command,
            uid,
            &mut result_payload as *mut bool as usize,
            &mut result_ok as *mut u32 as usize,
        );
    }
    if result_ok == KERNEL_SU_OPTION as u32 {
        Some(result_payload)
    } else {
        None
    }
}

/// `prctl` implementation for checking if a UID has root.
fn uid_granted_root_prctl(uid: i32) -> bool {
    ksu_prctl_bool_query(CMD_UID_GRANTED_ROOT, uid).unwrap_or(false)
}

/// `prctl` implementation for checking if a UID should have mounts unmounted.
fn uid_should_umount_prctl(uid: i32) -> bool {
    ksu_prctl_bool_query(CMD_UID_SHOULD_UMOUNT, uid).unwrap_or(false)
}

/// `prctl` implementation for checking if a UID is the manager app.
/// This function contains its own internal fallback, which was necessary due to the
/// inconsistencies of the old API.
fn uid_is_manager_prctl(uid: i32) -> bool {
    // First, try the most reliable method: asking the kernel directly.
    if *LEGACY_SUPPORTS_MANAGER_UID.get().unwrap_or(&false) {
        let mut manager_uid: u32 = 0;
        let mut result_ok: u32 = 0;
        unsafe {
            // Safety: FFI call with valid pointers.
            libc::prctl(
                KERNEL_SU_OPTION,
                CMD_GET_MANAGER_UID,
                &mut manager_uid as *mut u32 as usize,
                0,
                &mut result_ok as *mut u32 as usize,
            );
        }
        if result_ok == KERNEL_SU_OPTION as u32 {
            return uid as u32 == manager_uid;
        }
    }

    // Fallback: if the kernel doesn't support the direct query, check the known package
    // paths on disk based on the detected variant. This is less reliable.
    let manager_path = match LEGACY_VARIANT.get() {
        Some(KernelSuVariant::Official) => "/data/user_de/0/me.weishu.kernelsu",
        Some(KernelSuVariant::Next) => "/data/user_de/0/com.rifsxd.ksunext",
        None => return false, // Should not happen if detect_version ran.
    };
    if let Ok(s) = rustix::fs::stat(manager_path) {
        return s.st_uid == uid as u32;
    }
    false
}
