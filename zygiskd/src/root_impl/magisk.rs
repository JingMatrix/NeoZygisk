// src/root_impl/magisk.rs

//! Detection and interaction logic for the Magisk root solution.

use crate::constants::MIN_MAGISK_VERSION;
use log::{debug, info};
use std::os::android::fs::MetadataExt;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::{fs, str};

const MAGISK_OFFICIAL_PKG: &str = "com.topjohnwu.magisk";
const MAGISK_THIRD_PARTIES: &[(&str, &str)] = &[
    ("alpha", "io.github.vvb2060.magisk"),
    ("kitsune", "io.github.huskydg.magisk"),
];

/// Represents the detected version status of Magisk.
pub enum Version {
    Supported,
    TooOld,
}

/// Lazily detected package name of the installed Magisk variant.
static MAGISK_VARIANT_PKG: OnceLock<&'static str> = OnceLock::new();

/// Helper to execute a command and capture its stdout.
fn run_command(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?
        .wait_with_output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
}

/// Detects the installed Magisk variant (Official, Alpha, Kitsune, etc.).
fn detect_variant() -> &'static str {
    if let Some(version_str) = run_command("magisk", &["-v"]) {
        for (keyword, pkg_name) in MAGISK_THIRD_PARTIES {
            if version_str.contains(keyword) {
                info!("Detected Magisk variant: {}", keyword);
                return pkg_name;
            }
        }
    }
    info!("Detected official Magisk variant.");
    MAGISK_OFFICIAL_PKG
}

/// Detects if Magisk is installed and if its version is supported.
pub fn detect_version() -> Option<Version> {
    let version_str = run_command("magisk", &["-V"])?;
    let version = version_str.trim().parse::<i32>().ok()?;

    // As a side effect of successful version detection, cache the variant.
    MAGISK_VARIANT_PKG.get_or_init(detect_variant);

    if version >= MIN_MAGISK_VERSION {
        Some(Version::Supported)
    } else {
        Some(Version::TooOld)
    }
}

/// Checks if a UID has been granted root by querying the Magisk database.
pub fn uid_granted_root(uid: i32) -> bool {
    let query = format!("SELECT 1 FROM policies WHERE uid={uid} AND policy=2 LIMIT 1");
    if let Some(output) = run_command("magisk", &["--sqlite", &query]) {
        return !output.trim().is_empty();
    }
    false
}

/// Checks if a UID is on the denylist by querying the Magisk database.
pub fn uid_should_umount(uid: i32) -> bool {
    // 1. Find the primary package name for the given UID.
    let packages_list = match run_command("pm", &["list", "packages", "--uid", &uid.to_string()]) {
        Some(list) => list,
        None => return false,
    };

    let pkg_name = packages_list
        .lines()
        .find_map(|line| line.trim().strip_prefix("package:"))
        .and_then(|pkg| pkg.split(' ').next());

    let pkg_name = match pkg_name {
        Some(name) => name,
        None => return false,
    };

    // 2. Check if that package name is in the denylist table.
    let query = format!("SELECT 1 FROM denylist WHERE package_name=\"{pkg_name}\" LIMIT 1");
    if let Some(output) = run_command("magisk", &["--sqlite", &query]) {
        return !output.trim().is_empty();
    }
    false
}

/// Checks if a UID belongs to the Magisk manager app.
pub fn uid_is_manager(uid: i32) -> bool {
    // First, try to get the 'requester' package name from the database, which is most reliable.
    let query = "SELECT value FROM strings WHERE key=\"requester\" LIMIT 1";
    if let Some(output) = run_command("magisk", &["--sqlite", &query]) {
        if let Some(manager_pkg) = output.trim().strip_prefix("value=") {
            if let Ok(metadata) = fs::metadata(format!("/data/user_de/0/{}", manager_pkg)) {
                return metadata.st_uid() == uid as u32;
            }
        }
    }

    // Fallback to checking the cached variant package name.
    if let Some(pkg_name) = MAGISK_VARIANT_PKG.get() {
        if let Ok(metadata) = fs::metadata(format!("/data/user_de/0/{}", pkg_name)) {
            return metadata.st_uid() == uid as u32;
        }
    }

    debug!("Could not determine Magisk manager UID.");
    false
}
