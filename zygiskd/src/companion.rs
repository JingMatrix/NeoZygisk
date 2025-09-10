// src/companion.rs

//! Entry point and logic for a module's companion process.
//!
//! A companion process is a dedicated process spawned by `zygiskd` to host a module's
//! companion code. This isolates the module's long-running tasks from the main daemon.
//! The companion receives requests from the module code (running inside target apps)
//! via Unix sockets.

use crate::dl;
use std::ffi::CString;
use crate::utils::{UnixStreamExt, is_socket_alive};
use anyhow::{Context, Result};
use log::{debug, error, info, trace};
use passfd::FdPassingExt;
use rustix::fs::fstat;
use std::ffi::c_void;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::thread;

/// The function signature for a module's companion entry point.
type ZygiskCompanionEntryFn = unsafe extern "C" fn(i32);

/// The main entry point for a companion process.
///
/// This function is executed when the daemon is launched with the "companion" argument.
pub fn entry(fd: i32) {
    info!("Companion process started with fd={}", fd);
    if let Err(e) = run_companion(fd) {
        error!("Companion process failed: {:?}", e);
    }
    info!("Companion process exiting.");
}

/// Core logic for the companion process.
fn run_companion(fd: i32) -> Result<()> {
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };

    // 1. Receive module name and library FD from the main daemon.
    let name = stream.read_string().context("Failed to read module name")?;
    let library_fd = stream.recv_fd().context("Failed to receive library FD")?;

    // 2. Dynamically load the module library and find its companion entry point.
    let entry_fn = match load_module_entry(library_fd) {
        Ok(Some(entry)) => {
            debug!("Companion entry point found for module `{}`", name);
            // Signal success back to the daemon.
            stream.write_u8(1).context("Failed to send success reply")?;
            entry
        }
        Ok(None) => {
            debug!("Module `{}` has no companion entry point.", name);
            // Signal that there's no entry point, then exit.
            stream
                .write_u8(0)
                .context("Failed to send 'no entry' reply")?;
            return Ok(());
        }
        Err(e) => {
            // Signal failure and exit.
            stream.write_u8(0).context("Failed to send failure reply")?;
            return Err(e).context(format!("Failed to load module `{}`", name));
        }
    };

    // 3. Main loop: wait for requests from the module code injected in apps.
    loop {
        // Block until the daemon socket is readable or closed.
        if !is_socket_alive(&stream) {
            info!(
                "Daemon socket closed, terminating companion for `{}`.",
                name
            );
            break;
        }

        // Receive a client socket FD from the daemon.
        let client_fd = stream.recv_fd().context("Failed to receive client FD")?;
        trace!(
            "New companion request for module `{}` on fd=`{}`",
            name, client_fd
        );

        // Let the client know we've received the request.
        let mut client_stream = unsafe { UnixStream::from_raw_fd(client_fd) };
        client_stream
            .write_u8(1)
            .context("Failed to write ack to client")?;

        // Spawn a new thread to handle this client.
        thread::spawn(move || {
            handle_client(client_stream, entry_fn);
        });
    }

    Ok(())
}

/// Handles a single client connection in a separate thread.
///
/// # Safety
/// This function calls the module's C ABI entry point, which is inherently unsafe.
/// The `entry` function is responsible for all interaction with the client socket.
fn handle_client(stream: UnixStream, entry: ZygiskCompanionEntryFn) {
    // Stat the socket before handing it off to the module.
    let pre_stat = match fstat(&stream) {
        Ok(s) => Some(s),
        Err(_) => None,
    };

    // Call into the module's code.
    unsafe {
        entry(stream.as_raw_fd());
    }

    // After the module code returns, check if the file descriptor is still valid
    // and points to the same underlying file. This prevents us from accidentally
    // closing a new file descriptor if the module closed the original one and
    // the OS reused the FD number.
    if let Some(st0) = pre_stat {
        if let Ok(st1) = fstat(&stream) {
            // If the device and inode numbers don't match, the FD has been reused.
            if st0.st_dev != st1.st_dev || st0.st_ino != st1.st_ino {
                // Forget the stream to avoid closing the wrong FD.
                std::mem::forget(stream);
            }
        } else {
            // If fstat fails now, the FD is definitely closed or invalid.
            std::mem::forget(stream);
        }
    }
    // If we get here, the stream (and its FD) will be dropped and closed automatically.
}

/// Loads a shared library from a file descriptor and resolves the companion entry symbol.
///
/// # Safety
/// This function calls `dlopen` and `dlsym`, which are unsafe FFI functions.
/// The provided `fd` must be a valid, open file descriptor to a shared library.
fn load_module_entry(fd: RawFd) -> Result<Option<ZygiskCompanionEntryFn>> {
    let _owned_fd = unsafe { OwnedFd::from_raw_fd(fd) }; // Ensure FD is closed on scope exit.
    let path = format!("/proc/self/fd/{}", fd);

    unsafe {
        let handle = dl::dlopen(&path, libc::RTLD_NOW)?;
        let symbol = CString::new("zygisk_companion_entry")?;
        let entry_ptr = libc::dlsym(handle, symbol.as_ptr());

        if entry_ptr.is_null() {
            Ok(None)
        } else {
            let fn_ptr = std::mem::transmute::<*mut c_void, ZygiskCompanionEntryFn>(entry_ptr);
            Ok(Some(fn_ptr))
        }
    }
}
