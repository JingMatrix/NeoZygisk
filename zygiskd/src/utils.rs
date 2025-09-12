// src/utils.rs

//! A collection of utility functions for platform-specific operations.
//!
//! This module provides helpers for:
//! - Interacting with Android properties and SELinux contexts.
//! - Low-level Unix socket and pipe I/O.
//! - A trait (`UnixStreamExt`) for simplified socket communication.

use anyhow::Result;
use rustix::net::{
    AddressFamily, SendFlags, SocketAddrUnix, SocketType, bind, connect, listen, sendto, socket,
};
use rustix::thread as rustix_thread;
use std::ffi::{CString, c_char};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::{
    fs,
    io::{Read, Write},
};

// --- Platform-specific Macros ---

/// Selects an expression based on the target pointer width (32-bit vs 64-bit).
#[cfg(target_pointer_width = "64")]
#[macro_export]
macro_rules! lp_select {
    ($lp32:expr, $lp64:expr) => {
        $lp64
    };
}
#[cfg(target_pointer_width = "32")]
#[macro_export]
macro_rules! lp_select {
    ($lp32:expr, $lp64:expr) => {
        $lp32
    };
}

/// Selects an expression based on the build profile (debug vs release).
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! debug_select {
    ($debug:expr, $release:expr) => {
        $debug
    };
}
#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! debug_select {
    ($debug:expr, $release:expr) => {
        $release
    };
}

// --- SELinux and Android Property Utilities ---

/// Sets the SELinux context for socket creation for the current thread.
pub fn set_socket_create_context(context: &str) -> Result<()> {
    // Try the modern path first.
    let path = "/proc/thread-self/attr/sockcreate";
    if fs::write(path, context).is_ok() {
        return Ok(());
    }
    // Fallback for older kernels.
    let fallback_path = format!(
        "/proc/self/task/{}/attr/sockcreate",
        rustix_thread::gettid().as_raw_nonzero()
    );
    fs::write(fallback_path, context)?;
    Ok(())
}

/// Gets the current SELinux context of the process.
pub fn get_current_attr() -> Result<String> {
    let s = fs::read_to_string("/proc/self/attr/current")?;
    Ok(s.trim().to_string())
}

/// Changes the SELinux context of a file using the `chcon` command.
pub fn chcon(path: &str, context: &str) -> Result<()> {
    Command::new("chcon").arg(context).arg(path).status()?;
    Ok(())
}

/// Retrieves an Android system property value.
pub fn get_property(name: &str) -> Result<String> {
    let name = CString::new(name)?;
    let mut buf = vec![0u8; 92]; // PROP_VALUE_MAX
    let len = unsafe { __system_property_get(name.as_ptr(), buf.as_mut_ptr() as *mut c_char) };
    if len > 0 {
        Ok(String::from_utf8_lossy(&buf[..len as usize]).to_string())
    } else {
        Ok(String::new())
    }
}

// --- Unix Socket and IPC Extensions ---

/// An extension trait for `UnixStream` to simplify reading and writing common data types.
pub trait UnixStreamExt {
    fn read_u8(&mut self) -> Result<u8>;
    fn read_u32(&mut self) -> Result<u32>;
    fn read_usize(&mut self) -> Result<usize>;
    fn read_string(&mut self) -> Result<String>;
    fn write_u8(&mut self, value: u8) -> Result<()>;
    fn write_u32(&mut self, value: u32) -> Result<()>;
    fn write_usize(&mut self, value: usize) -> Result<()>;
    fn write_string(&mut self, value: &str) -> Result<()>;
}

impl UnixStreamExt for UnixStream {
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_ne_bytes(buf))
    }

    fn read_usize(&mut self) -> Result<usize> {
        let mut buf = [0u8; std::mem::size_of::<usize>()];
        self.read_exact(&mut buf)?;
        Ok(usize::from_ne_bytes(buf))
    }

    fn read_string(&mut self) -> Result<String> {
        let len = self.read_usize()?;
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;
        Ok(String::from_utf8(buf)?)
    }

    fn write_u8(&mut self, value: u8) -> Result<()> {
        self.write_all(&[value])?;
        Ok(())
    }

    fn write_u32(&mut self, value: u32) -> Result<()> {
        self.write_all(&value.to_ne_bytes())?;
        Ok(())
    }

    fn write_usize(&mut self, value: usize) -> Result<()> {
        self.write_all(&value.to_ne_bytes())?;
        Ok(())
    }

    fn write_string(&mut self, value: &str) -> Result<()> {
        self.write_usize(value.len())?;
        self.write_all(value.as_bytes())?;
        Ok(())
    }
}

/// Creates a `UnixListener` bound to a given path, handling file cleanup and SELinux contexts.
pub fn unix_listener_from_path(path: &str) -> Result<UnixListener> {
    let _ = fs::remove_file(path);
    let addr = SocketAddrUnix::new(path)?;
    let socket = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    bind(&socket, &addr)?;
    listen(&socket, 10)?; // Backlog of 10
    chcon(path, "u:object_r:zygisk_file:s0")?;
    Ok(UnixListener::from(socket))
}

/// Sends a datagram packet to a Unix socket path.
pub fn unix_datagram_sendto(path: &str, buf: &[u8]) -> Result<()> {
    set_socket_create_context(&get_current_attr()?)?;
    let addr = SocketAddrUnix::new(path.as_bytes())?;
    let socket = socket(AddressFamily::UNIX, SocketType::DGRAM, None)?;
    connect(&socket, &addr)?;
    sendto(socket, buf, SendFlags::empty(), &addr)?;
    set_socket_create_context("u:r:zygote:s0")?;
    Ok(())
}

/// Checks if a Unix socket is still alive and connected using `poll`.
pub fn is_socket_alive(stream: &UnixStream) -> bool {
    let pfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let mut pfds = [pfd];
    // A timeout of 0 makes poll return immediately.
    let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 1, 0) };
    if ret < 0 {
        return false;
    }
    // If `revents` has any flag other than POLLIN (e.g., POLLHUP, POLLERR), the socket is dead.
    pfds[0].revents & !libc::POLLIN == 0
}

// --- FFI for Android System APIs ---
unsafe extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> u32;
    // Other __system_property functions could be declared here if needed.
}
