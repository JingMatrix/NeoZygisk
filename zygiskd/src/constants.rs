// src/constants.rs

//! Defines global constants, enums, and bitflags used throughout the project.

use crate::lp_select;
use bitflags::bitflags;
use konst::primitive::parse_i32;
use konst::unwrap_ctx;
use log::LevelFilter;
use num_enum::TryFromPrimitive;

// --- Versioning Constants ---
// These are set at compile time from environment variables.

/// The minimum compatible version of APatch.
pub const MIN_APATCH_VERSION: i32 = unwrap_ctx!(parse_i32(env!("MIN_APATCH_VERSION")));
/// The minimum compatible version of KernelSU.
pub const MIN_KSU_VERSION: i32 = unwrap_ctx!(parse_i32(env!("MIN_KSU_VERSION")));
/// The maximum compatible version of KernelSU.
pub const MAX_KSU_VERSION: i32 = unwrap_ctx!(parse_i32(env!("MAX_KSU_VERSION")));
/// The minimum compatible version of Magisk.
pub const MIN_MAGISK_VERSION: i32 = unwrap_ctx!(parse_i32(env!("MIN_MAGISK_VERSION")));
/// The version of the NeoZygisk daemon itself.
pub const ZKSU_VERSION: &str = env!("ZKSU_VERSION");

// --- Configuration Constants ---

/// The maximum log level for the daemon. Set to `Trace` for debug builds and `Info` for release builds.
#[cfg(debug_assertions)]
pub const MAX_LOG_LEVEL: LevelFilter = LevelFilter::Trace;
#[cfg(not(debug_assertions))]
pub const MAX_LOG_LEVEL: LevelFilter = LevelFilter::Info;

/// The relative path to the directory where Zygisk modules are stored.
pub const PATH_MODULES_DIR: &str = "..";

// --- IPC Constants ---
// These are magic numbers used in communication with the controller.

/// IPC code indicating that Zygote has been successfully injected.
pub const ZYGOTE_INJECTED: i32 = lp_select!(5, 4);
/// IPC code for sending daemon status information.
pub const DAEMON_SET_INFO: i32 = lp_select!(7, 6);
/// IPC code for sending daemon error information.
pub const DAEMON_SET_ERROR_INFO: i32 = lp_select!(9, 8);
/// IPC code indicating that the Android system server has started.
pub const SYSTEM_SERVER_STARTED: i32 = 10;

/// Defines the set of actions that can be requested from the daemon over its main Unix socket.
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum DaemonSocketAction {
    PingHeartbeat,
    GetProcessFlags,
    CacheMountNamespace,
    UpdateMountNamespace,
    ReadModules,
    RequestCompanionSocket,
    GetModuleDir,
    ZygoteRestart,
    SystemServerStarted,
}

/// Represents the two types of mount namespaces the daemon manages.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum MountNamespace {
    /// A "clean" namespace with all root-related mounts removed.
    Clean,
    /// The root namespace of the system, as seen by Zygote.
    Root,
}

impl TryFrom<u8> for MountNamespace {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MountNamespace::Clean),
            1 => Ok(MountNamespace::Root),
            _ => anyhow::bail!("Invalid MountNamespace value: {}", value),
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ProcessFlags: u32 {
        /// The process has been granted root privileges.
        const PROCESS_GRANTED_ROOT = 1 << 0;
        /// The process is on the denylist and module mounts should be hidden.
        const PROCESS_ON_DENYLIST = 1 << 1;
        /// The process is the root manager application itself.
        const PROCESS_IS_MANAGER = 1 << 27;
        /// The active root solution is APatch.
        const PROCESS_ROOT_IS_APATCH = 1 << 28;
        /// The active root solution is KernelSU.
        const PROCESS_ROOT_IS_KSU = 1 << 29;
        /// The active root solution is Magisk.
        const PROCESS_ROOT_IS_MAGISK = 1 << 30;
    }
}
