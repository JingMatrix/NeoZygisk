// src/root_impl/kernelsu.rs

//! Detection and interaction logic for the KernelSU root solution.
//!
//! KernelSU communicates its status and settings via a special `prctl` interface.
//! This module provides safe wrappers around these `prctl` calls.

use crate::constants::{MAX_KSU_VERSION, MIN_KSU_VERSION};
use std::ffi::c_char;
use std::path::Path;
use std::sync::OnceLock;

// --- KernelSU prctl Interface Constants ---

/// The magic number for KernelSU's prctl interface.
const KERNEL_SU_OPTION: i32 = 0xdeadbeefu32 as i32;

/// prctl command to get the kernel version code.
const CMD_GET_VERSION: usize = 2;
/// prctl command to check if a UID is granted root.
const CMD_UID_GRANTED_ROOT: usize = 12;
/// prctl command to check if a UID is on the unmount list.
const CMD_UID_SHOULD_UMOUNT: usize = 13;
/// prctl command to get the manager app's UID.
const CMD_GET_MANAGER_UID: usize = 16;
/// prctl command to get the hook mode (identifies variants like KSU `Next`).
const CMD_HOOK_MODE: usize = 0xC0DEAD1A;

/// Represents the detected version status of KernelSU.
pub enum Version {
    Supported,
    TooOld,
}

/// Represents the detected variant of KernelSU.
#[derive(Clone, Copy, Debug)]
enum KernelSuVariant {
    Official,
    Next,
}

/// Lazily initialized KernelSU variant.
static VARIANT: OnceLock<KernelSuVariant> = OnceLock::new();
/// Lazily initialized flag indicating kernel support for direct manager UID retrieval.
static SUPPORTS_MANAGER_UID_RETRIEVAL: OnceLock<bool> = OnceLock::new();

/// Detects if KernelSU is active and if its version is supported.
///
/// As a side effect of a successful detection, this function also probes for and
/// caches the KernelSU variant and other capabilities for later use.
pub fn detect_version() -> Option<Version> {
    // 1. Get Kernel Version
    let mut version = 0;
    // Safety: prctl is an FFI call. We provide pointers to valid stack variables.
    // The kernel will write the version code into `version`.
    unsafe {
        libc::prctl(
            KERNEL_SU_OPTION,
            CMD_GET_VERSION,
            &mut version as *mut i32,
            0,
            0,
        );
    }

    if !(MIN_KSU_VERSION..=MAX_KSU_VERSION).contains(&version) {
        return if version > 0 {
            Some(Version::TooOld)
        } else {
            None
        };
    }

    // 2. Check for `ksud` daemon, which is required for KernelSU to be functional.
    if !Path::new("/data/adb/ksud").exists() {
        return None;
    }

    // 3. Probe for capabilities and cache them. This runs only on the first successful detection.
    VARIANT.get_or_init(|| {
        let mut mode: [c_char; 16] = [0; 16];
        // Safety: We provide a pointer to a valid buffer. The kernel writes the hook mode string.
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

    SUPPORTS_MANAGER_UID_RETRIEVAL.get_or_init(|| {
        let mut result_ok: i32 = 0;
        // Safety: We provide a pointer to a valid stack variable. The kernel writes a magic
        // value to this pointer if the command is supported.
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

    Some(Version::Supported)
}

/// A safe wrapper for KernelSU's boolean `prctl` commands.
/// Returns `Some(bool)` on success, `None` on failure (kernel interface mismatch).
fn ksu_prctl_bool_query(command: usize, uid: i32) -> Option<bool> {
    let mut result_payload: bool = false;
    let mut result_ok: u32 = 0;
    // Safety: `prctl` is FFI. We provide valid pointers for the kernel to write into.
    unsafe {
        libc::prctl(
            KERNEL_SU_OPTION,
            command,
            uid,
            &mut result_payload as *mut bool as usize,
            &mut result_ok as *mut u32 as usize,
        );
    }
    // The call is considered successful only if the kernel writes back the magic number.
    if result_ok == KERNEL_SU_OPTION as u32 {
        Some(result_payload)
    } else {
        None
    }
}

/// Checks if a UID has been granted root by KernelSU.
pub fn uid_granted_root(uid: i32) -> bool {
    ksu_prctl_bool_query(CMD_UID_GRANTED_ROOT, uid).unwrap_or(false)
}

/// Checks if a UID is on the unmount list in KernelSU.
pub fn uid_should_umount(uid: i32) -> bool {
    ksu_prctl_bool_query(CMD_UID_SHOULD_UMOUNT, uid).unwrap_or(false)
}

/// Checks if a UID belongs to the KernelSU manager app.
pub fn uid_is_manager(uid: i32) -> bool {
    // The most reliable method is asking the kernel directly, if supported.
    if *SUPPORTS_MANAGER_UID_RETRIEVAL.get().unwrap_or(&false) {
        let mut manager_uid: u32 = 0;
        let mut result_ok: u32 = 0;
        // Safety: `prctl` is FFI. We provide valid pointers.
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

    // Fallback: check the known package paths based on the detected variant.
    let manager_path = match VARIANT.get() {
        Some(KernelSuVariant::Official) => "/data/user_de/0/me.weishu.kernelsu",
        Some(KernelSuVariant::Next) => "/data/user_de/0/com.rifsxd.ksunext",
        None => return false, // Should not happen if detect_version was called.
    };

    if let Ok(s) = rustix::fs::stat(manager_path) {
        return s.st_uid == uid as u32;
    }

    false
}
