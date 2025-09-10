// src/main.rs

//! Main entry point for the NeoZygisk daemon and its companion processes.
//!
//! # Zygiskd Architecture Overview
//!
//! The daemon, injected applications, and companion processes are all distinct,
//! separate processes. This diagram shows their interactions over time.
//!
//! ```ascii
//!                                   Zygiskd Architecture
//!
//! +---------------------------+                                 +-----------------------------+
//! |      Zygiskd Daemon       |                                 |    App Process (Injected)   |
//! +---------------------------+                                 +-----------------------------+
//! |                           |                                 |                             |
//! | 1. Scans /data/adb/modules|                                 |                             |
//! |    & creates sealed memfd |                                 |                             |
//! |                           |                                 |                             |
//! | 2. Listens on Unix socket |                                 |                             |
//! |    (cp32.sock, cp64.sock) |                                 |                             |
//! |                           |                                 |                             |
//! |                           | <-[ 3.    Zygisk connects   ]-- |                             |
//! |                           |                                 |                             |
//! |                           | <-[ 4.  Requests module FDs ]-- |                             |
//! |                           |                                 |                             |
//! |                           | --[ 5.     Sends memfd      ]-> |                             |
//! |                           |                                 |   6. `dlopen`(memfd) &      |
//! |                           |                                 |     runs module code        |
//! |                           |                                 |                             |
//! |                           | <-[ 7.  Requests companion  ]-- |                             |
//! |                           |                                 |                             |
//! | 8. Spawns Companion via   |                                 |                             |
//! |    `fork()` & `exec()`.   |                                 |                             |
//! |    It creates a socket    |                                 |                             |
//! |    pair and gives one     |                                 |                             |
//! |    end to the companion.  |                                 |                             |
//! |           |               |                                 |                             |
//! |           |               | --[ 9. The OTHER socket end ]-> |                             |
//! |           |               |                                 |                             |
//! +-----------|---------------+                                 |                             |
//!             |                                                 |                             |
//!             |                                                 | (Now holds other socket end)|
//!             v                                                 |                             |
//! +---------------------------+                                 |                             |
//! |     Companion Process     |                                 |                             |
//! | (Now holds one socket end)|                                 |                             |
//! |                           |                                 |                             |
//! |                           |                                 |                             |
//! | <=======================[ 10. A direct and private connection ]=========================> |
//! |                         [  is now established. The daemon is  ]                           |
//! |                         [  no longer involved in this chat.   ]                           |
//! +--------------------------------------+          +-----------------------------------------+
//!
//! ```
//!
//! ## Key Steps:
//!
//! 1.  **Scan & Load:** On startup, `zygiskd` discovers modules in `/data/adb/modules`.
//! 2.  **Create Sealed Memfd:** It reads each module's library into a secure, immutable in-memory file (`memfd`).
//! 3.  **Listen & Connect:** The daemon listens on a Unix socket. Zygisk code injected into a newly started application process connects to this socket.
//! 4.  **Request Module FDs:** The app asks the daemon for the file descriptors of all active modules.
//! 5.  **Sends Lib (memfd):** The daemon securely sends the sealed `memfd`s to the app via File Descriptor Passing.
//! 6.  **Load & Run:** The app process uses `dlopen` on the received file descriptor to load the module's code into its own memory space and execute it.
//! 7.  **Request Companion:** If needed, the module code running inside the app asks the daemon to spawn its dedicated companion process.
//! 8.  **Spawn & Distribute (Part 1):** The daemon forks to create a new companion process. It first creates a connected **socket pair**. It gives **one end** of this pair to the companion.
//! 9.  **Distribute (Part 2):** The daemon then sends the **other end** of the socket pair to the App Process that requested it, using secure FD passing.
//! 10. **Direct Connection:** With the brokering complete, the App and Companion processes now hold the two ends of a private communication channel and can communicate directly, efficiently, and securely.
//!
//! This binary has multiple modes of operation based on its command-line arguments:
//! - No arguments: Starts the main `zygiskd` daemon.
//! - `companion <fd>`: Starts a companion process for a Zygisk module.
//! - `version`: Prints the daemon version.
//! - `root`: Detects and prints the current root implementation.

mod companion;
mod constants;
mod dl;
mod root_impl;
mod utils;
mod zygiskd;

use crate::constants::ZKSU_VERSION;
use log::error;

/// Initializes the Android logger with a specific tag.
fn init_android_logger(tag: &str) {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(constants::MAX_LOG_LEVEL)
            .with_tag(tag),
    );
}

/// Parses command-line arguments and dispatches to the correct logic.
fn start() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("companion") => {
            if let Some(fd_str) = args.get(2) {
                if let Ok(fd) = fd_str.parse() {
                    companion::entry(fd);
                } else {
                    error!("Companion: Invalid file descriptor provided.");
                }
            } else {
                error!("Companion: Missing file descriptor argument.");
            }
        }
        Some("version") => {
            println!("NeoZygisk daemon {}", ZKSU_VERSION);
        }
        Some("root") => {
            root_impl::setup();
            println!("Detected root implementation: {:?}", root_impl::get());
        }
        _ => {
            // Default to starting the main daemon.
            if let Err(e) = main_daemon_entry() {
                error!("Zygiskd daemon failed: {:?}", e);
            }
        }
    }
}

/// The main entry point for the Zygisk daemon.
/// It sets up the environment and launches the core daemon logic.
fn main_daemon_entry() -> anyhow::Result<()> {
    // We must be in the root mount namespace to function correctly.
    utils::switch_mount_namespace(1)?;
    // Detect and globally set the root implementation.
    root_impl::setup();
    log::info!("Current root implementation: {:?}", root_impl::get());
    zygiskd::main()
}

fn main() {
    // Use the binary name as the log tag.
    let arg0 = std::env::args().next().unwrap_or_default();
    let process_name = arg0.split('/').last().unwrap_or("zygiskd");
    init_android_logger(process_name);

    start();
}
