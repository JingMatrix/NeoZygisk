// src/utils.rs

//! A collection of utility functions for platform-specific operations.
//!
//! This module provides helpers for:
//! - Interacting with Android properties and SELinux contexts.
//! - Managing and caching Linux mount namespaces.
//! - Low-level Unix socket and pipe I/O.
//! - A trait (`UnixStreamExt`) for simplified socket communication.

use crate::{constants::MountNamespace, root_impl};
use anyhow::{Result, bail};
use log::{debug, error, trace};
use procfs::process::{MountInfo, Process};
use rustix::net::{
    AddressFamily, SendFlags, SocketAddrUnix, SocketType, bind, connect, listen, sendto, socket,
};
use rustix::thread as rustix_thread;
use std::ffi::{CString, c_char};
use std::io::Error;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::sync::OnceLock;
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

// --- Mount Namespace Management ---

/// Switches the current thread into the mount namespace of a given process.
pub fn switch_mount_namespace(pid: i32) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let mnt_ns_file = fs::File::open(format!("/proc/{}/ns/mnt", pid))?;
    rustix_thread::move_into_link_name_space(
        mnt_ns_file.as_fd(),
        Some(rustix_thread::LinkNameSpaceType::Mount),
    )?;
    // `setns` can change the current working directory, so we restore it.
    std::env::set_current_dir(cwd)?;
    Ok(())
}

/// File descriptors that hold open references to the clean and root mount namespaces,
/// preventing them from being destroyed even if all processes within them terminate.
static CLEAN_MNT_NS_FD: OnceLock<OwnedFd> = OnceLock::new();
static ROOT_MNT_NS_FD: OnceLock<OwnedFd> = OnceLock::new();

/// Saves a handle to a specific mount namespace (`Clean` or `Root`) so it can be entered later.
///
/// This is a complex operation required to prepare an environment for Zygisk modules.
///
/// # Arguments
/// * `pid` - The PID of a process in the target mount namespace (e.g., Zygote's PID).
///           If -1, this function assumes the namespace has already been cached and just returns the FD.
/// * `namespace_type` - The type of namespace to cache.
///
/// # Mechanism
/// 1. A child process is forked.
/// 2. The child switches into the target process's mount namespace.
/// 3. If a `Clean` namespace is requested, the child performs an additional `unshare(CLONE_NEWNS)`
///    and then unmounts all Magisk/KernelSU/APatch-related filesystems to create a "clean" state.
/// 4. The parent process waits for the child to finish setting up the namespace. A pipe is used
///    for synchronization.
/// 5. The parent then opens `/proc/<child_pid>/ns/mnt`, which gives it a file descriptor
///    to the child's newly prepared namespace.
/// 6. This file descriptor is stored in one of the static `OnceLock` variables, keeping the
///    namespace alive indefinitely.
pub fn save_mount_namespace(pid: i32, namespace_type: MountNamespace) -> Result<i32> {
    let ns_fd_cell = match namespace_type {
        MountNamespace::Clean => &CLEAN_MNT_NS_FD,
        MountNamespace::Root => &ROOT_MNT_NS_FD,
    };

    if let Some(fd) = ns_fd_cell.get() {
        return Ok(fd.as_raw_fd());
    }

    if pid == -1 {
        bail!(
            "Mount namespace of type {:?} requested but not yet cached.",
            namespace_type
        );
    }

    // Create a pipe for synchronization between parent and child.
    let (pipe_reader, pipe_writer) = rustix::pipe::pipe()?;

    match unsafe { libc::fork() } {
        0 => {
            // --- Child Process ---
            // Close the side of the pipe we don't use.
            drop(pipe_reader);
            // Switch into the target process's namespace.
            switch_mount_namespace(pid).unwrap();

            if namespace_type == MountNamespace::Clean {
                // Create a new, private mount namespace for ourselves.
                unsafe {
                    rustix_thread::unshare_unsafe(rustix_thread::UnshareFlags::NEWNS).unwrap();
                }
                // Clean up root implemantation and module mounts.
                clean_mount_namespace().unwrap();
            }

            // Signal to the parent that setup is complete.
            let sig: [u8; 1] = [0];
            rustix::io::write(pipe_writer, &sig).unwrap();

            // Wait indefinitely. The parent will kill us after it has the FD.
            // A simple sleep loop is fine here.
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
        child_pid if child_pid > 0 => {
            // --- Parent Process ---
            drop(pipe_writer);

            // Wait for the signal from the child.
            let mut buf: [u8; 1] = [0];
            rustix::io::read(pipe_reader, &mut buf)?;
            trace!("Child {} finished setting up mount namespace.", child_pid);

            let ns_path = format!("/proc/{}/ns/mnt", child_pid);
            let ns_file = fs::File::open(&ns_path)?;

            // We have the FD, we can now terminate the child process.
            unsafe { libc::kill(child_pid, libc::SIGKILL) };
            unsafe { libc::waitpid(child_pid, std::ptr::null_mut(), 0) };

            let raw_fd = ns_file.as_raw_fd();
            ns_fd_cell
                .set(ns_file.into())
                .map_err(|_| anyhow::anyhow!("Failed to set OnceLock for namespace FD"))?;

            match namespace_type {
                MountNamespace::Clean => trace!("CLEAN_MNT_NS_FD cached as {}", raw_fd),
                MountNamespace::Root => trace!("ROOT_MNT_NS_FD cached as {}", raw_fd),
            }

            Ok(raw_fd)
        }
        _ => bail!(Error::last_os_error()),
    }
}

/// Unmounts filesystems related to root solutions (Magisk, APatch, KernelSU)
/// from the current mount namespace.
fn clean_mount_namespace() -> Result<()> {
    let mount_infos = Process::myself()?.mountinfo()?;
    let mut unmount_targets: Vec<MountInfo> = Vec::new();

    let root_source = match root_impl::get() {
        root_impl::RootImpl::APatch => Some("APatch"),
        root_impl::RootImpl::KernelSU => Some("KSU"),
        root_impl::RootImpl::Magisk => Some("magisk"),
        _ => None,
    };

    let ksu_module_source: Option<String> =
        if matches!(root_impl::get(), root_impl::RootImpl::KernelSU) {
            mount_infos
                .iter()
                .find(|info| info.mount_point.as_path().to_str() == Some("/data/adb/modules"))
                .and_then(|info| info.mount_source.clone())
                .filter(|source| source.starts_with("/dev/block/loop"))
        } else {
            None
        };

    for info in mount_infos {
        let path_str = info.mount_point.to_str().unwrap_or("");
        let mount_source_str = info.mount_source.as_deref();

        let should_unmount = info.root.starts_with("/adb/modules")
            || path_str.starts_with("/data/adb/modules")
            || (root_source.is_some() && mount_source_str == root_source)
            || (ksu_module_source.is_some() && info.mount_source == ksu_module_source);

        if should_unmount {
            unmount_targets.push(info);
        }
    }

    // Unmount in reverse order of mnt_id to handle nested mounts correctly.
    unmount_targets.sort_by_key(|a| std::cmp::Reverse(a.mnt_id));

    for target in unmount_targets {
        let path = target.mount_point.to_str().unwrap_or("");
        debug!("Unmounting {} (mnt_id: {})", path, target.mnt_id);
        if let Ok(path_cstr) = CString::new(path.to_string()) {
            unsafe {
                if libc::umount2(path_cstr.as_ptr(), libc::MNT_DETACH) == -1 {
                    error!("Failed to unmount {}: {}", path, Error::last_os_error());
                }
            }
        }
    }
    Ok(())
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
