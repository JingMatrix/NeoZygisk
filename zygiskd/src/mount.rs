// src/mount.rs

//! Manages Linux mount namespaces for the NeoZygisk daemon.
//!
//! This module provides a unified API for caching, cleaning, and switching
//! between different mount namespaces, which is crucial for isolating Zygisk
//! modules and providing them with a clean environment.

use anyhow::{Result, bail};
use log::{debug, error, trace};
use procfs::process::{MountInfo, Process};
use rustix::thread as rustix_thread;
use std::ffi::CString;
use std::fs;
use std::io::Error;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::sync::OnceLock;

use crate::root_impl;

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

/// Manages the lifecycle and caching of mount namespace file descriptors.
///
/// This manager is responsible for creating and holding onto file descriptors
/// that represent specific mount namespaces, preventing them from being destroyed.
pub struct MountNamespaceManager {
    clean_mnt_ns_fd: OnceLock<OwnedFd>,
    root_mnt_ns_fd: OnceLock<OwnedFd>,
}

impl MountNamespaceManager {
    /// Creates a new, empty `MountNamespaceManager`.
    pub fn new() -> Self {
        Self {
            clean_mnt_ns_fd: OnceLock::new(),
            root_mnt_ns_fd: OnceLock::new(),
        }
    }

    fn get_namespace_storage(&self, namespace_type: MountNamespace) -> &OnceLock<OwnedFd> {
        match namespace_type {
            MountNamespace::Clean => &self.clean_mnt_ns_fd,
            MountNamespace::Root => &self.root_mnt_ns_fd,
        }
    }

    /// Gets the cached file descriptor for a given namespace type, if it exists.
    pub fn get_namespace_fd(&self, namespace_type: MountNamespace) -> Option<RawFd> {
        self.get_namespace_storage(namespace_type)
            .get()
            .map(|fd| fd.as_raw_fd())
    }

    /// Caches a handle to a specific mount namespace (`Clean` or `Root`).
    ///
    /// # Arguments
    /// * `pid` - The PID of a process currently in the target mount namespace.
    /// * `namespace_type` - The type of namespace to save.
    pub fn save_mount_namespace(&self, pid: i32, namespace_type: MountNamespace) -> Result<RawFd> {
        let ns_fd_cell = self.get_namespace_storage(namespace_type);
        if let Some(fd) = ns_fd_cell.get() {
            return Ok(fd.as_raw_fd());
        }

        // Create a pipe for synchronization between parent and child.
        let (pipe_reader, pipe_writer) = rustix::pipe::pipe()?;

        match unsafe { libc::fork() } {
            0 => {
                // --- Child Process ---
                drop(pipe_reader); // Close the side of the pipe we don't use.
                switch_mount_namespace(pid).unwrap();

                if namespace_type == MountNamespace::Clean {
                    // Create a new, private mount namespace for ourselves.
                    unsafe {
                        rustix_thread::unshare_unsafe(rustix_thread::UnshareFlags::NEWNS).unwrap();
                    }
                    // Unmount all root and module mounts.
                    Self::clean_mount_namespace().unwrap();
                }

                // Signal to the parent that setup is complete.
                let sig: [u8; 1] = [0];
                rustix::io::write(pipe_writer, &sig).unwrap();

                // Wait indefinitely. The parent will kill us after it has the FD.
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
                unsafe {
                    libc::kill(child_pid, libc::SIGKILL);
                    libc::waitpid(child_pid, std::ptr::null_mut(), 0);
                }

                let raw_fd = ns_file.as_raw_fd();
                ns_fd_cell
                    .set(ns_file.into())
                    .map_err(|_| anyhow::anyhow!("Failed to set OnceLock for namespace FD"))?;

                trace!("{:?} namespace cached as FD {}", namespace_type, raw_fd);
                Ok(raw_fd)
            }
            _ => bail!(Error::last_os_error()),
        }
    }

    /// Unmounts filesystems related to root solutions from the current mount namespace.
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
}

impl Default for MountNamespaceManager {
    fn default() -> Self {
        Self::new()
    }
}
