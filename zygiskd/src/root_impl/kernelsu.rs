// src/root_impl/kernelsu.rs

//! Detection and interaction logic for the KernelSU root solution.
//!
//! This module supports both the modern `ioctl` interface and the legacy `prctl`
//! interface for backwards compatibility. It will prefer the `ioctl` method and
//! fall back to `prctl` if the modern interface is not detected.

use crate::constants::{MAX_KSU_VERSION, MIN_KSU_VERSION};
use std::ffi::c_char;
use std::fs;
use std::os::fd::RawFd;
use std::path::Path;
use std::sync::OnceLock;

// --- KernelSU Communication Method Enum & Cached State ---

/// Represents the detected communication method for the current KernelSU version.
#[derive(Clone, Copy)]
enum Method {
    /// Modern ioctl interface, storing the cached file descriptor.
    Ioctl(RawFd),
    /// Legacy prctl interface.
    Prctl,
}

/// Represents the full result of the one-time detection.
#[derive(Clone, Copy)]
struct DetectionResult {
    method: Method,
    version: Version,
}

/// Lazily initialized detection result. This is the core of the fallback logic.
static KSU_RESULT: OnceLock<Option<DetectionResult>> = OnceLock::new();

// --- Modern `ioctl` Interface Constants and Structs ---

const KSU_INSTALL_MAGIC1: u32 = 0xDEADBEEF;
const KSU_INSTALL_MAGIC2: u32 = 0xCAFEBABE;

const KSU_IOCTL_GET_INFO: u32 = 0x80004b02;
const KSU_IOCTL_UID_GRANTED_ROOT: u32 = 0xc0004b09;
const KSU_IOCTL_UID_SHOULD_UMOUNT: u32 = 0xc0004b0a;
const KSU_IOCTL_GET_MANAGER_UID: u32 = 0x80004b0b;

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

const KERNEL_SU_OPTION: i32 = 0xdeadbeefu32 as i32;
const CMD_GET_VERSION: usize = 2;
const CMD_UID_GRANTED_ROOT: usize = 12;
const CMD_UID_SHOULD_UMOUNT: usize = 13;
const CMD_GET_MANAGER_UID: usize = 16;
const CMD_HOOK_MODE: usize = 0xC0DEAD1A;

/// Represents the detected variant of KernelSU.
#[derive(Clone, Copy, Debug)]
enum KernelSuVariant {
    Official,
    Next,
}

/// Lazily initialized variant for the legacy prctl method.
static LEGACY_VARIANT: OnceLock<KernelSuVariant> = OnceLock::new();
/// Lazily initialized capability flag for the legacy prctl method.
static LEGACY_SUPPORTS_MANAGER_UID: OnceLock<bool> = OnceLock::new();

/// Represents the detected version status of KernelSU.
#[derive(Clone, Copy)]
pub enum Version {
    Supported,
    TooOld,
}

// --- Core Detection and Dispatch Logic ---

/// Detects if KernelSU is active and its version, determining the correct communication method.
/// This function implements the "ioctl-first, prctl-fallback" strategy.
pub fn detect_version() -> Option<Version> {
    // get_or_init ensures the detection logic runs only once.
    // The closure's return value is cached in KSU_RESULT.
    let result = KSU_RESULT.get_or_init(|| {
        // --- Stage 1: Attempt to use the modern ioctl interface ---
        if let Some(fd) = init_driver_fd() {
            let mut cmd = KsuGetInfoCmd {
                version: 0,
                flags: 0,
                features: 0,
            };
            if ksuctl_ioctl(fd, KSU_IOCTL_GET_INFO, &mut cmd).is_ok() {
                let version_code = cmd.version as i32;
                if version_code > 0 {
                    // Success! We are using the ioctl method.
                    let method = Method::Ioctl(fd);
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
                    // If version is too high or ksud is missing, we still consider it "not detected" with this method.
                }
            }
        }

        // --- Stage 2: Fallback to the legacy prctl interface ---
        let mut version_code = 0;
        unsafe {
            libc::prctl(
                KERNEL_SU_OPTION,
                CMD_GET_VERSION,
                &mut version_code as *mut i32,
                0,
                0,
            );
        }

        if version_code > 0 {
            // Success with prctl. Initialize legacy capabilities.
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
        // If both ioctl and prctl fail, KernelSU is not present.
        None
    });

    // After the cache is populated, map the cached result to the function's return type.
    result.as_ref().map(|r| r.version)
}

/// Checks if a UID has been granted root by KernelSU.
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

/// Scans for an existing driver fd, avoiding the reboot syscall if possible.
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

/// Initializes the driver fd, first by scanning and then by calling the reboot syscall.
fn init_driver_fd() -> Option<RawFd> {
    if let Some(fd) = scan_driver_fd() {
        return Some(fd);
    }

    let mut fd: RawFd = -1;
    unsafe {
        libc::syscall(
            libc::SYS_reboot,
            KSU_INSTALL_MAGIC1,
            KSU_INSTALL_MAGIC2,
            0,
            &mut fd,
        );
    }
    if fd >= 0 {
        Some(fd)
    } else {
        None
    }
}

/// Generic ioctl wrapper, matching the style of the official manager.
fn ksuctl_ioctl<T>(fd: RawFd, request: u32, arg: *mut T) -> std::io::Result<()> {
    let ret = unsafe { libc::ioctl(fd, request as _, arg) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn uid_granted_root_ioctl(fd: RawFd, uid: i32) -> bool {
    let mut cmd = KsuUidGrantedRootCmd {
        uid: uid as u32,
        granted: 0,
    };
    ksuctl_ioctl(fd, KSU_IOCTL_UID_GRANTED_ROOT, &mut cmd)
        .map(|_| cmd.granted != 0)
        .unwrap_or(false)
}

fn uid_should_umount_ioctl(fd: RawFd, uid: i32) -> bool {
    let mut cmd = KsuUidShouldUmountCmd {
        uid: uid as u32,
        should_umount: 0,
    };
    ksuctl_ioctl(fd, KSU_IOCTL_UID_SHOULD_UMOUNT, &mut cmd)
        .map(|_| cmd.should_umount != 0)
        .unwrap_or(false)
}

fn uid_is_manager_ioctl(fd: RawFd, uid: i32) -> bool {
    let mut cmd = KsuGetManagerUidCmd { uid: 0 };
    if ksuctl_ioctl(fd, KSU_IOCTL_GET_MANAGER_UID, &mut cmd).is_ok() {
        return uid as u32 == cmd.uid;
    }
    false
}

// --- `prctl` Implementation Details ---

/// Probes and caches capabilities for the legacy prctl method.
fn init_legacy_variant_probe() {
    LEGACY_VARIANT.get_or_init(|| {
        let mut mode: [c_char; 16] = [0; 16];
        unsafe {
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
            libc::prctl(
                KERNEL_SU_OPTION,
                CMD_GET_MANAGER_UID,
                0,
                0,
                &mut result_ok as *mut _ as usize,
            );
        }
        result_ok as u32 == KERNEL_SU_OPTION as u32
    });
}

fn ksu_prctl_bool_query(command: usize, uid: i32) -> Option<bool> {
    let mut result_payload: bool = false;
    let mut result_ok: u32 = 0;
    unsafe {
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

fn uid_granted_root_prctl(uid: i32) -> bool {
    ksu_prctl_bool_query(CMD_UID_GRANTED_ROOT, uid).unwrap_or(false)
}

fn uid_should_umount_prctl(uid: i32) -> bool {
    ksu_prctl_bool_query(CMD_UID_SHOULD_UMOUNT, uid).unwrap_or(false)
}

fn uid_is_manager_prctl(uid: i32) -> bool {
    if *LEGACY_SUPPORTS_MANAGER_UID.get().unwrap_or(&false) {
        let mut manager_uid: u32 = 0;
        let mut result_ok: u32 = 0;
        unsafe {
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

    let manager_path = match LEGACY_VARIANT.get() {
        Some(KernelSuVariant::Official) => "/data/user_de/0/me.weishu.kernelsu",
        Some(KernelSuVariant::Next) => "/data/user_de/0/com.rifsxd.ksunext",
        None => return false,
    };
    if let Ok(s) = rustix::fs::stat(manager_path) {
        return s.st_uid == uid as u32;
    }
    false
}
