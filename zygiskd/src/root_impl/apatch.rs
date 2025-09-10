// src/root_impl/apatch.rs

//! Detection and interaction logic for the APatch root solution.

use crate::constants::MIN_APATCH_VERSION;
use anyhow::{Context, Result};
use log::debug;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

const CONFIG_FILE: &str = "/data/adb/ap/package_config";

/// Represents the detected version status of APatch.
pub enum Version {
    Supported,
    TooOld,
}

/// Represents a single entry in the APatch configuration file.
#[derive(Debug)]
struct PackageInfo {
    uid: i32,
    exclude: bool, // Corresponds to denylist
    allow: bool,   // Corresponds to root access
}

/// Detects if APatch is installed and if its version is supported.
pub fn detect_version() -> Option<Version> {
    Command::new("apd")
        .arg("-V")
        .stdout(Stdio::piped())
        .spawn()
        .ok()
        .and_then(|child| child.wait_with_output().ok())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|version_str| version_str.split_whitespace().nth(1)?.parse::<i32>().ok())
        .map(|version| {
            if version >= MIN_APATCH_VERSION {
                Version::Supported
            } else {
                Version::TooOld
            }
        })
}

/// Parses the APatch package configuration file.
fn parse_config_file() -> Result<Vec<PackageInfo>> {
    let file = File::open(CONFIG_FILE).context("Failed to open APatch config file")?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    // Skip the header row.
    reader.read_line(&mut line)?;
    line.clear();

    let mut result = Vec::new();
    while reader.read_line(&mut line)? > 0 {
        let parts: Vec<&str> = line.trim().split(',').collect();
        if parts.len() >= 6 {
            if let (Ok(exclude), Ok(allow), Ok(uid)) = (
                parts[1].parse::<u8>(),
                parts[2].parse::<u8>(),
                parts[3].parse::<i32>(),
            ) {
                result.push(PackageInfo {
                    uid,
                    exclude: exclude == 1,
                    allow: allow == 1,
                });
            }
        }
        line.clear();
    }
    Ok(result)
}

/// Checks if a UID is configured to have root access in APatch.
pub fn uid_granted_root(uid: i32) -> bool {
    match parse_config_file() {
        Ok(packages) => packages.iter().any(|pkg| pkg.uid == uid && pkg.allow),
        Err(e) => {
            debug!("Could not check APatch root grant status: {}", e);
            false
        }
    }
}

/// Checks if a UID is on the denylist in APatch.
pub fn uid_should_umount(uid: i32) -> bool {
    match parse_config_file() {
        Ok(packages) => packages.iter().any(|pkg| pkg.uid == uid && pkg.exclude),
        Err(e) => {
            debug!("Could not check APatch denylist status: {}", e);
            false
        }
    }
}

/// Checks if a UID belongs to the APatch manager app.
pub fn uid_is_manager(uid: i32) -> bool {
    if let Ok(s) = rustix::fs::stat("/data/user_de/0/me.bmax.apatch") {
        return s.st_uid == uid as u32;
    }
    false
}
