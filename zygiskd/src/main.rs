// src/main.rs

//! Main entry point for the ShamrockZygisk daemon and its companion processes.
//!
//! # Zygiskd Architecture Overview
//!
//! The daemon, injected applications, and companion processes are all distinct,
//! separate processes. This diagram shows their interactions over time, focusing
//! on how a direct connection is brokered between an App and a Companion.
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
//! |   (cp32.sock, cp64.sock)  |                                 |                             |
//! |                           | <-[ 3.    Zygisk connects   ]-- |                             |
//! |                           |                                 |                             |
//! |                           | <-[ 4.  Requests module FDs ]-- |                             |
//! |                           |                                 |                             |
//! |                           | --[ 5.     Sends memfd      ]-> |                             |
//! |                           |                                 |   6. `dlopen`(memfd) &      |
//! |                           |                                 |     runs module code        |
//! |                           |                                 |                             |
//! |                           | <-[ 7. Requests companion   ]-- | (Using its existing socket) |
//! |                           |                                 |                             |
//! | 8. `fork()` & `exec()`s a |                                 |                             |
//! |    new Companion process. -----------------+                |                             |
//! |           |               |                |                |                             |
//! +-----------|---------------+                |                +-----------------------------+
//!             |                                |                                ^
//!             v                                |                                |
//! +---------------------------+                |                                |
//! |     Companion Process     |                |                                |
//! +---------------------------+                |                                |
//! |                           |                V                                |
//! | <-[ 9. HANDOFF: Daemon  ]-+ (Zygiskd acts as broker, passing the FD)        |
//! |    [ passes the App's   ] |                                                 |
//! |    [ connection FD here.] |                                                 |
//! |                           |                                                 |
//! | <=======================[ 10. Direct connection is now live ]===============+
//! |                         [   using the App's original socket.]
//! |                         [   The daemon is out of the loop.  ]
//! +---------------------------+
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
//! 7.  **Request Companion:** If needed, the module code running inside the app asks the daemon to spawn its dedicated companion process. This request is sent over its **existing socket connection**.
//! 8.  **Spawn Companion:** The daemon forks and executes itself to create a new companion process.
//! 9.  **Connection Handoff:** This is the critical brokering step. The daemon takes the **file descriptor** from the app's original connection and securely **passes this FD to the new companion process** over a private control socket.
//! 10. **Direct Connection:** The companion receives the file descriptor and now holds the other end of the app's original socket. It can now communicate directly with the app. The daemon's brokering job is complete, and it is no longer involved in their conversation. This handoff is efficient and seamless from the app's perspective.
//!
//! This binary has multiple modes of operation based on its command-line arguments:
//! - No arguments: Starts the main `zygiskd` daemon.
//! - `companion <fd>`: Starts a companion process for a Zygisk module.
//! - `version`: Prints the daemon version.
//! - `root`: Detects and prints the current root implementation.

mod companion;
mod constants;
mod dl;
mod mount;
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
            println!("ShamrockZygisk daemon {}", ZKSU_VERSION);
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
    mount::switch_mount_namespace(1)?;
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
