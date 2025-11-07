// src/root_impl/kernelsu.rs

//! Detection and interaction logic for the KernelSU root solution.
//!
//! KernelSU communicates its status and settings via ioctl interface through a special fd.
//! This module provides safe wrappers around these ioctl calls.

use crate::constants::{MAX_KSU_VERSION, MIN_KSU_VERSION};
use std::path::Path;
use std::sync::OnceLock;

/* demo: https://github.com/backslashxx/various_stuff/blob/master/ksu_fd/ksu_fd.c */
/* more demo https://github.com/backslashxx/kernelnosu/blob/master/src/su.c */

// --- KernelSU ioctl Interface Constants ---

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

/// Represents the detected version status of KernelSU.
pub enum Version {
    Supported,
    TooOld,
}

/// Global fd cache
static GLOBAL_FD: OnceLock<i32> = OnceLock::new();

/// Gets the cached KernelSU driver fd.
fn get_ksu_fd() -> Option<i32> {
    // If it has been initialized, return directly.
    if let Some(&fd) = GLOBAL_FD.get() {
        if fd != 0 {
            return Some(fd);
        }
    }

    // If this is the first call, initialize fd.
    let mut fd: i32 = 0;
    let result = unsafe {
        libc::syscall(
            libc::SYS_reboot,
            KSU_INSTALL_MAGIC1 as i32,
            KSU_INSTALL_MAGIC2 as i32,
            0,
            &mut fd as *mut i32,
        )
    };
    
    // Check whether fd is valid.
    if fd > 0 {
        let _ = GLOBAL_FD.set(fd);
        Some(fd)
    } else {
        None
    }
}

/// Execute ioctl impl.
fn ksu_ioctl<T>(request: u32, arg: &mut T) -> std::io::Result<()> {
    let fd = match get_ksu_fd() {
        Some(fd) => fd,
        None => return Err(std::io::Error::last_os_error()),
    };

    // Using syscall to execute ioctl impl.
    let result = unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            fd,
            request as i32,
            arg as *mut T,
        )
    };

    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Detects if KernelSU is active and if its version is supported.
pub fn detect_version() -> Option<Version> {
    // 1. Get Kernel Version.
    let mut cmd = KsuGetInfoCmd {
        version: 0,
        flags: 0,
        features: 0,
    };
    
    if ksu_ioctl(KSU_IOCTL_GET_INFO, &mut cmd).is_err() {
        return None;
    }

    let version = cmd.version as i32;

    if version == 0 {
        return None;
    } else if version >= MIN_KSU_VERSION && version <= MAX_KSU_VERSION {
        // 2. Check for `ksud` daemon, which is required for KernelSU to be functional.
        if !Path::new("/data/adb/ksud").exists() {
            return None;
        }

        Some(Version::Supported)
    } else if version >= 1 && version < MIN_KSU_VERSION {
        Some(Version::TooOld)
    } else {
        None
    }
}

/// Checks if a UID has been granted root by KernelSU.
pub fn uid_granted_root(uid: i32) -> bool {
    let mut cmd = KsuUidGrantedRootCmd {
        uid: uid as u32,
        granted: 0,
    };
    
    ksu_ioctl(KSU_IOCTL_UID_GRANTED_ROOT, &mut cmd)
        .map(|_| cmd.granted != 0)
        .unwrap_or(false)
}

/// Checks if a UID is on the unmount list in KernelSU.
pub fn uid_should_umount(uid: i32) -> bool {
    let mut cmd = KsuUidShouldUmountCmd {
        uid: uid as u32,
        should_umount: 0,
    };
    
    ksu_ioctl(KSU_IOCTL_UID_SHOULD_UMOUNT, &mut cmd)
        .map(|_| cmd.should_umount != 0)
        .unwrap_or(false)
}

/// Checks if a UID belongs to the KernelSU manager app.
pub fn uid_is_manager(uid: i32) -> bool {
    let mut cmd = KsuGetManagerUidCmd { uid: 0 };
    if ksu_ioctl(KSU_IOCTL_GET_MANAGER_UID, &mut cmd).is_ok() {
        return uid as u32 == cmd.uid;
    }

    false
}