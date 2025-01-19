use anyhow::{Result, bail};
use log::{debug, error, trace};
use procfs::process::Process;
use rustix::net::{
    AddressFamily, SendFlags, SocketAddrUnix, SocketType, bind_unix, connect_unix, listen,
    sendto_unix, socket,
};
use rustix::path::Arg;
use rustix::thread::gettid;
use std::ffi::{CStr, CString, c_char, c_void};
use std::io::Error;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::sync::OnceLock;
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
};

use crate::constants::MountNamespace;
use crate::root_impl;

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

pub struct LateInit<T> {
    cell: OnceLock<T>,
}

impl<T> LateInit<T> {
    pub const fn new() -> Self {
        LateInit {
            cell: OnceLock::new(),
        }
    }

    pub fn init(&self, value: T) {
        assert!(self.cell.set(value).is_ok())
    }

    pub fn initiated(&self) -> bool {
        self.cell.get().is_some()
    }
}

impl<T> std::ops::Deref for LateInit<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.cell.get().unwrap()
    }
}

pub fn set_socket_create_context(context: &str) -> Result<()> {
    let path = "/proc/thread-self/attr/sockcreate";
    match fs::write(path, context) {
        Ok(_) => Ok(()),
        Err(_) => {
            let path = format!(
                "/proc/self/task/{}/attr/sockcreate",
                gettid().as_raw_nonzero()
            );
            fs::write(path, context)?;
            Ok(())
        }
    }
}

pub fn get_current_attr() -> Result<String> {
    let s = fs::read("/proc/self/attr/current")?;
    Ok(s.to_string_lossy().to_string())
}

pub fn chcon(path: &str, context: &str) -> Result<()> {
    Command::new("chcon").arg(context).arg(path).status()?;
    Ok(())
}

pub fn get_property(name: &str) -> Result<String> {
    let name = CString::new(name)?;
    let mut buf = vec![0u8; 92];
    let prop = unsafe {
        __system_property_get(name.as_ptr(), buf.as_mut_ptr() as *mut c_char);
        CStr::from_bytes_until_nul(&buf)?
    };
    Ok(prop.to_string_lossy().to_string())
}

pub fn switch_mount_namespace(pid: i32) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let mnt = fs::File::open(format!("/proc/{}/ns/mnt", pid))?;
    rustix::thread::move_into_link_name_space(mnt.as_fd(), None)?;
    std::env::set_current_dir(cwd)?;
    Ok(())
}

// save mount namespaces for all application process
static CLEAN_MNT_NS_FD: LateInit<i32> = LateInit::new();
static ROOT_MNT_NS_FD: LateInit<i32> = LateInit::new();
static MODULE_MNT_NS_FD: LateInit<i32> = LateInit::new();

// Use `man 7 namespaces` to read the Linux manual about namespaces.
// In the section `The /proc/pid/ns/ directory`, it is explained that:
// opening one of the files in this directory (or a file that is bind
// mounted to one of these files) returns a file handle for the corresponding
// namespace of the process specified by pid. As long as this file descriptor
// remains open, the namespace will remain alive, even if all processes in the
// namespace terminate.
pub fn save_mount_namespace(pid: i32, namespace_type: MountNamespace) -> Result<i32> {
    // We shall use CLEAN_MNT_NS_FD and ROOT_MNT_NS_FD to keep the namespace file handle.
    let is_initialized = match namespace_type {
        MountNamespace::Clean => CLEAN_MNT_NS_FD.initiated(),
        MountNamespace::Root => ROOT_MNT_NS_FD.initiated(),
        MountNamespace::Module => MODULE_MNT_NS_FD.initiated(),
    };

    if !is_initialized {
        if pid == -1 {
            bail!(
                "Caching not finished [Clean, Root, Module]: [{}, {}, {}]",
                CLEAN_MNT_NS_FD.initiated(),
                ROOT_MNT_NS_FD.initiated(),
                MODULE_MNT_NS_FD.initiated()
            );
        }
        // Use a pipe to keep the forked child process open
        // till the namespace is read.

        let mut pipes = [0; 2];
        unsafe {
            libc::pipe(pipes.as_mut_ptr());
        }
        let (reader, writer) = (pipes[0], pipes[1]);
        match unsafe { libc::fork() } {
            0 => {
                // Child process
                switch_mount_namespace(pid)?;
                if namespace_type != MountNamespace::Root {
                    unsafe {
                        libc::unshare(libc::CLONE_NEWNS);
                    }
                    revert_unmount(namespace_type == MountNamespace::Module)?;
                }
                let mut mypid = 0;
                while mypid != unsafe { libc::getpid() } {
                    write_int(writer, 0)?;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    mypid = read_int(reader)?;
                }
                std::process::exit(0);
            }
            child if child > 0 => {
                // Parent process
                trace!("waiting {child} to cache mount namespace");
                if read_int(reader)? == 0 {
                    trace!("{child} finished caching mount namespace");
                }
                let ns_path = format!("/proc/{}/ns/mnt", child);
                let ns_file = fs::OpenOptions::new().read(true).open(&ns_path)?;
                write_int(writer, child)?;
                unsafe {
                    if libc::close(reader) == -1
                        || libc::close(writer) == -1
                        || libc::waitpid(child, std::ptr::null_mut(), 0) == -1
                    {
                        bail!(Error::last_os_error());
                    }
                };
                match namespace_type {
                    MountNamespace::Clean => {
                        CLEAN_MNT_NS_FD.init(ns_file.as_raw_fd());
                        trace!("CLEAN_MNT_NS_FD updated to {}", *CLEAN_MNT_NS_FD);
                    }
                    MountNamespace::Root => {
                        ROOT_MNT_NS_FD.init(ns_file.as_raw_fd());
                        trace!("ROOT_MNT_NS_FD updated to {}", *ROOT_MNT_NS_FD);
                    }
                    MountNamespace::Module => {
                        MODULE_MNT_NS_FD.init(ns_file.as_raw_fd());
                        trace!("MODULE_MNT_NS_FD updated to {}", *MODULE_MNT_NS_FD);
                    }
                };
                std::mem::forget(ns_file);
            }
            _ => bail!(Error::last_os_error()),
        }
    }
    match namespace_type {
        MountNamespace::Clean if CLEAN_MNT_NS_FD.initiated() => Ok(*CLEAN_MNT_NS_FD),
        MountNamespace::Root if ROOT_MNT_NS_FD.initiated() => Ok(*ROOT_MNT_NS_FD),
        MountNamespace::Module if MODULE_MNT_NS_FD.initiated() => Ok(*MODULE_MNT_NS_FD),
        _ => Ok(0),
    }
}

fn revert_unmount(modules_only: bool) -> Result<()> {
    let mount_infos = Process::myself().unwrap().mountinfo().unwrap();
    let mut targets: Vec<String> = Vec::new();
    let mount_source = match root_impl::get_impl() {
        root_impl::RootImpl::APatch => "APatch",
        root_impl::RootImpl::KernelSU => "KSU",
        root_impl::RootImpl::Magisk => "magisk",
        _ => panic!("wrong root impl: {:?}", root_impl::get_impl()),
    };
    for info in mount_infos {
        let path = info.mount_point.to_str().unwrap().to_string();
        let should_unmount: bool = if modules_only {
            path.starts_with("/debug_ramdisk") && mount_source != "magisk"
        } else {
            info.root.starts_with("/adb/modules")
                || path.starts_with("/data/adb/modules")
                || info.mount_source == Some(mount_source.to_string())
        };
        if should_unmount {
            targets.push(path);
        }
    }
    targets.reverse();
    for path in targets {
        unsafe {
            if libc::umount2(CString::new(path.clone())?.as_ptr(), libc::MNT_DETACH) == -1 {
                error!("failed to to unmount {}", path);
                bail!(Error::last_os_error());
            } else {
                debug!("Unmounted {}", path);
            }
        }
    }
    Ok(())
}

fn write_int(fd: libc::c_int, value: i32) -> Result<()> {
    unsafe {
        if libc::write(
            fd,
            &value as *const _ as *const c_void,
            std::mem::size_of::<i32>(),
        ) == -1
        {
            bail!(Error::last_os_error());
        }
    };
    Ok(())
}

fn read_int(fd: libc::c_int) -> Result<i32> {
    let mut buf = [0u8; 4];
    unsafe {
        if libc::read(
            fd,
            buf.as_mut_ptr() as *mut c_void,
            std::mem::size_of::<i32>(),
        ) == -1
        {
            bail!(Error::last_os_error());
        }
    };
    let value = i32::from_le_bytes(buf);
    Ok(value)
}

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
        self.write_all(&value.to_ne_bytes())?;
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

pub fn unix_listener_from_path(path: &str) -> Result<UnixListener> {
    let _ = fs::remove_file(path);
    let addr = SocketAddrUnix::new(path)?;
    let socket = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    bind_unix(&socket, &addr)?;
    listen(&socket, 2)?;
    chcon(path, "u:object_r:zygisk_file:s0")?;
    Ok(UnixListener::from(socket))
}

pub fn unix_datagram_sendto(path: &str, buf: &[u8]) -> Result<()> {
    // FIXME: shall we set create context every time?
    set_socket_create_context(get_current_attr()?.as_str())?;
    let addr = SocketAddrUnix::new(path.as_bytes())?;
    let socket = socket(AddressFamily::UNIX, SocketType::DGRAM, None)?;
    connect_unix(&socket, &addr)?;
    sendto_unix(socket, buf, SendFlags::empty(), &addr)?;
    set_socket_create_context("u:r:zygote:s0")?;
    Ok(())
}

pub fn check_unix_socket(stream: &UnixStream, block: bool) -> bool {
    unsafe {
        let mut pfd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = if block { -1 } else { 0 };
        libc::poll(&mut pfd, 1, timeout);
        if pfd.revents & !libc::POLLIN != 0 {
            return false;
        }
    }
    return true;
}

unsafe extern "C" {
    fn __android_log_print(prio: i32, tag: *const c_char, fmt: *const c_char, ...) -> i32;
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> u32;
    fn __system_property_set(name: *const c_char, value: *const c_char) -> u32;
    fn __system_property_find(name: *const c_char) -> *const c_void;
    fn __system_property_wait(
        info: *const c_void,
        old_serial: u32,
        new_serial: *mut u32,
        timeout: *const libc::timespec,
    ) -> bool;
    fn __system_property_serial(info: *const c_void) -> u32;
}
