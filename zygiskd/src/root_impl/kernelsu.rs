use crate::constants::{MAX_KSU_VERSION, MIN_KSU_VERSION};
use crate::utils::LateInit;
use std::ffi::c_char;
use std::path::Path;

const KERNEL_SU_OPTION: u32 = 0xdeadbeefu32;

const CMD_GET_VERSION: usize = 2;
const CMD_UID_GRANTED_ROOT: usize = 12;
const CMD_UID_SHOULD_UMOUNT: usize = 13;
const CMD_GET_MANAGER_UID: usize = 16;
const CMD_HOOK_MODE: usize = 0xC0DEAD1A;

// An enum is needed to represent the different KernelSU variants.
#[derive(Clone, Copy)]
pub enum KernelSuVariant {
    Official,
    Next,
}

static VARIANT: LateInit<KernelSuVariant> = LateInit::new();
static SUPPORTS_MANAGER_UID_RETRIEVAL: LateInit<bool> = LateInit::new();

pub enum Version {
    Supported,
    TooOld,
}

pub fn get_kernel_su() -> Option<Version> {
    let mut version = 0;
    unsafe {
        libc::prctl(
            KERNEL_SU_OPTION as i32,
            CMD_GET_VERSION,
            &mut version as *mut i32,
            0,
            0,
        )
    };

    const MAX_OLD_VERSION: i32 = MIN_KSU_VERSION - 1;
    match version {
        MIN_KSU_VERSION..=MAX_KSU_VERSION => {
            // Check for the `ksud` daemon's existence. If it's not present,
            // KernelSU is not considered active, so we return None.
            if !Path::new("/data/adb/ksud").exists() {
                return None;
            }

            // This block runs once to detect and cache kernel capabilities.
            if !VARIANT.initiated() {
                // Detect kernel variant (Official vs. Next).
                let mut mode: [c_char; 16] = [0; 16];
                unsafe {
                    libc::prctl(
                        KERNEL_SU_OPTION as i32,
                        CMD_HOOK_MODE,
                        mode.as_mut_ptr() as usize,
                        0,
                        0,
                    );
                }
                VARIANT.init(if mode[0] != 0 {
                    KernelSuVariant::Next
                } else {
                    KernelSuVariant::Official
                });

                // Check if the kernel supports direct manager UID retrieval.
                let mut mgr_uid_reply_ok: i32 = 0;
                unsafe {
                    libc::prctl(
                        KERNEL_SU_OPTION as i32,
                        CMD_GET_MANAGER_UID,
                        0,
                        0,
                        &mut mgr_uid_reply_ok as *mut _ as usize,
                    );
                }
                SUPPORTS_MANAGER_UID_RETRIEVAL.init(mgr_uid_reply_ok as u32 == KERNEL_SU_OPTION);
            }

            Some(Version::Supported)
        }
        1..=MAX_OLD_VERSION => Some(Version::TooOld),
        // A version of 0 or any other value means KernelSU is not present or abnormal.
        _ => None,
    }
}

pub fn uid_granted_root(uid: i32) -> bool {
    let mut result: u32 = 0;
    let mut granted = false;
    unsafe {
        libc::prctl(
            KERNEL_SU_OPTION as i32,
            CMD_UID_GRANTED_ROOT,
            uid,
            &mut granted as *mut bool,
            &mut result as *mut u32,
        )
    };
    // The prctl call is valid only if `result` matches `KERNEL_SU_OPTION`.
    if result != KERNEL_SU_OPTION {
        return false;
    }
    granted
}

pub fn uid_should_umount(uid: i32) -> bool {
    let mut result: u32 = 0;
    let mut umount = false;
    unsafe {
        libc::prctl(
            KERNEL_SU_OPTION as i32,
            CMD_UID_SHOULD_UMOUNT,
            uid,
            &mut umount as *mut bool,
            &mut result as *mut u32,
        )
    };
    // The prctl call is valid only if `result` matches `KERNEL_SU_OPTION`.
    if result != KERNEL_SU_OPTION {
        return false;
    }
    umount
}

pub fn uid_is_manager(uid: i32) -> bool {
    // Ensure the static variables are initialized before use.
    if !VARIANT.initiated() {
        get_kernel_su();
    }

    // If supported, getting the manager UID from the kernel is most reliable.
    if *SUPPORTS_MANAGER_UID_RETRIEVAL {
        let mut manager_uid: u32 = 0;
        let mut reply_ok: i32 = 0;
        unsafe {
            libc::prctl(
                KERNEL_SU_OPTION as i32,
                CMD_GET_MANAGER_UID,
                &mut manager_uid as *mut u32,
                0,
                &mut reply_ok as *mut i32,
            )
        };
        return uid as u32 == manager_uid;
    }

    // Fallback to checking the path based on the detected variant.
    let manager_path = match *VARIANT {
        KernelSuVariant::Official => "/data/user_de/0/me.weishu.kernelsu",
        KernelSuVariant::Next => "/data/user_de/0/com.rifsxd.ksunext",
    };

    if let Ok(s) = rustix::fs::stat(manager_path) {
        return s.st_uid == uid as u32;
    }
    false
}
