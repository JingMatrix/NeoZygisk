// src/zygiskd.rs

//! The core logic for the Zygisk daemon (`zygiskd`).
//!
//! This module is responsible for:
//! - Initializing paths and communication channels.
//! - Loading Zygisk modules from the designated directory.
//! - Listening on a Unix domain socket for requests from the Zygisk injector.
//! - Handling requests such as providing module libraries, querying process flags,
//!   and managing companion processes.

use crate::constants::{DaemonSocketAction, ProcessFlags, ZKSU_VERSION};
use crate::mount::{MountNamespace, MountNamespaceManager};
use crate::utils::{self, UnixStreamExt};
use crate::{constants, lp_select, root_impl};
use anyhow::{Context as AnyhowContext, Result, bail};
use log::{debug, error, info, trace, warn};
use passfd::FdPassingExt;
use rustix::io::{FdFlags, fcntl_setfd};
use std::fs;
use std::io::Error;
use std::os::fd::AsRawFd;
use std::os::fd::{AsFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::{
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    process::Command,
    sync::{Arc, Mutex, OnceLock, RwLock},
    thread,
};

/// Represents a loaded Zygisk module.
struct Module {
    name: String,
    lib_fd: OwnedFd,
    /// A handle to the module's companion process socket, if it exists and is running.
    companion: Mutex<Option<UnixStream>>,
}

/// The shared context for the daemon, containing all loaded modules and a mount namespace manager
struct AppContext {
    /// The live module snapshot, replaced wholesale by `RefreshModules`.
    ///
    /// Under a temp root the daemon outlives module promotions, hot installs and whole
    /// root sessions, so the set it serves has to be replaceable. Handing each request an
    /// `Arc` of the snapshot keeps in-flight work on the set it started with, and retiring
    /// a snapshot drops its companions with it.
    modules: RwLock<Arc<Vec<Module>>>,
    mount_manager: Arc<MountNamespaceManager>,
}

impl AppContext {
    /// Takes a reference to the current snapshot. Held only long enough to clone the
    /// `Arc`, so a refresh is never blocked by a slow reader.
    fn modules(&self) -> Arc<Vec<Module>> {
        Arc::clone(&self.modules.read().unwrap())
    }

    /// Rescans the module directory and publishes the result.
    ///
    /// The new snapshot is built completely before anything is published, so a scan that
    /// fails leaves the daemon serving the previous set rather than an empty or partial
    /// one. Returns the number of modules now live.
    fn refresh_modules(&self) -> Result<usize> {
        let modules = load_modules().context("Failed to rescan the module directory")?;
        let count = modules.len();
        let names: Vec<_> = modules.iter().map(|m| m.name.clone()).collect();
        // The status readout is written from what the daemon reports, so a refreshed set
        // has to be reported again or the module list the user sees keeps naming the one
        // the daemon served at startup.
        if let Err(e) = send_startup_info(&modules) {
            warn!("Failed to report the refreshed module list: {:?}", e);
        }
        // The previous snapshot is dropped once the last in-flight reader releases it,
        // which closes its library memfds and its companion sockets. A companion whose
        // socket is closed has no remaining caller, so it exits on its own.
        *self.modules.write().unwrap() = Arc::new(modules);
        info!("Module snapshot refreshed: {} module(s) {:?}", count, names);
        Ok(count)
    }
}

// Global paths, initialized once at startup.
static TMP_PATH: OnceLock<String> = OnceLock::new();
static CONTROLLER_SOCKET: OnceLock<String> = OnceLock::new();
static DAEMON_SOCKET_PATH: OnceLock<String> = OnceLock::new();

/// The main function for the zygiskd daemon.
pub fn main(tmp_path: Option<&str>) -> Result<()> {
    info!("Welcome to NeoZygisk ({}) !", ZKSU_VERSION);

    initialize_globals(tmp_path)?;
    // Lenient at startup where a refresh is strict: the daemon serves the heartbeat, the
    // process flags and the mount namespaces too, and all of those are worth having even
    // when the module set could not be read. A later `RefreshModules` can still pick it up.
    let modules = load_modules().unwrap_or_else(|e| {
        warn!("Starting with no modules: {:?}", e);
        Vec::new()
    });
    send_startup_info(&modules)?;

    let mount_manager = Arc::new(MountNamespaceManager::new());
    let context = Arc::new(AppContext {
        modules: RwLock::new(Arc::new(modules)),
        mount_manager,
    });
    let listener = create_daemon_socket()?;

    info!("Daemon listening on {}", DAEMON_SOCKET_PATH.get().unwrap());

    // Main event loop: accept and handle incoming connections.
    for stream in listener.incoming() {
        let stream = stream.context("Failed to accept incoming connection")?;
        let context = Arc::clone(&context);
        if let Err(e) = handle_connection(stream, context) {
            warn!("Error handling connection: {}", e);
        }
    }

    Ok(())
}

/// Handles a single incoming connection from Zygisk.
fn handle_connection(mut stream: UnixStream, context: Arc<AppContext>) -> Result<()> {
    // Only root and system may talk to the daemon: zygote (uid 0) throughout injection and
    // the pre-specialization window, a late-injected system_server (uid 1000), and the root
    // tracer. SO_PEERCRED is recorded by the kernel at connect() time and cannot be spoofed.
    //
    // This is the same boundary `sepolicy.rule` draws -- it grants the socket to the zygote
    // and system_server domains and to nothing else -- and the same one the Zygisk API
    // documents: `connectCompanion()` and `getModuleDir()` work from the pre[XXX]Specialize
    // callbacks and not afterwards, "due to SELinux and UID". A module calling either once
    // its process has dropped to the app uid is refused here as well, and sees the -1 the
    // API already defines for a connection that could not be made. Nothing legitimate is
    // lost: an app reaches its companion over an fd handed to it before the drop, which
    // never re-enters this accept path.
    const AID_ROOT: u32 = 0;
    const AID_SYSTEM: u32 = 1000;
    match rustix::net::sockopt::socket_peercred(&stream) {
        Ok(cred) => {
            let uid = cred.uid.as_raw();
            if uid != AID_ROOT && uid != AID_SYSTEM {
                warn!(
                    "Rejecting daemon connection from untrusted peer: {:?}",
                    cred
                );
                return Ok(());
            }
        }
        Err(e) => {
            warn!(
                "Rejecting daemon connection: cannot read peer credentials: {}",
                e
            );
            return Ok(());
        }
    }

    let action = stream.read_u8()?;
    let action = DaemonSocketAction::try_from(action)
        .with_context(|| format!("Invalid daemon action code: {}", action))?;
    trace!("New daemon action: {:?}", action);

    match action {
        // These actions are lightweight and handled synchronously.
        DaemonSocketAction::CacheMountNamespace => {
            let pid = stream.read_u32()? as i32;
            context
                .mount_manager
                .save_mount_namespace(pid, MountNamespace::Clean)?;
            context
                .mount_manager
                .save_mount_namespace(pid, MountNamespace::Root)?;
        }
        DaemonSocketAction::PingHeartbeat => {
            let value = constants::ZYGOTE_INJECTED;
            utils::unix_datagram_sendto(CONTROLLER_SOCKET.get().unwrap(), &value.to_le_bytes())?;
        }
        DaemonSocketAction::ZygoteRestart => {
            info!("Zygote restarted, dropping companions and rescanning modules.");
            // Drop the companions first and unconditionally: they served a framework that
            // no longer exists, and leaving it to the snapshot swap would strand them if
            // the rescan failed.
            for module in context.modules().iter() {
                module.companion.lock().unwrap().take();
            }
            // This is the only refresh a zygote restart gets, so a module installed while
            // the system was up would otherwise wait for a full reboot. A bare stop and
            // start runs no boot script at all, and `ksud soft-reboot` -- which does replay
            // post-fs-data and post-mount -- stops zygote before it does, so post-mount.sh
            // finds no live zygote and sends no rearm.
            //
            // It is also the only safe point to swap the set: a module handle is an index
            // into the list its process read at startup, and a zygote restart takes
            // system_server and every app holding one down with it.
            if let Err(e) = context.refresh_modules() {
                warn!("Serving the previous module snapshot: {:?}", e);
            }
        }
        DaemonSocketAction::SystemServerStarted => {
            let value = constants::SYSTEM_SERVER_STARTED;
            utils::unix_datagram_sendto(CONTROLLER_SOCKET.get().unwrap(), &value.to_le_bytes())?;
        }
        DaemonSocketAction::RefreshModules => {
            // Synchronous: the rearm path waits for this before injecting anything.
            let ok = match context.refresh_modules() {
                Ok(_) => 1u8,
                Err(e) => {
                    warn!("Failed to refresh the module snapshot: {:?}", e);
                    0u8
                }
            };
            stream.write_u8(ok)?;
        }
        // Heavier actions are spawned into a separate thread.
        _ => {
            thread::spawn(move || {
                if let Err(e) = handle_threaded_action(action, stream, &context) {
                    warn!(
                        "Error handling daemon action '{:?}': {:?}\nBacktrace: {}",
                        action,
                        e,
                        e.backtrace()
                    );
                }
            });
        }
    }
    Ok(())
}

/// Handles potentially long-running actions in a dedicated thread.
fn handle_threaded_action(
    action: DaemonSocketAction,
    mut stream: UnixStream,
    context: &AppContext,
) -> Result<()> {
    match action {
        DaemonSocketAction::GetProcessFlags => handle_get_process_flags(&mut stream),
        DaemonSocketAction::UpdateMountNamespace => {
            handle_update_mount_namespace(&mut stream, context)
        }
        DaemonSocketAction::ReadModules => handle_read_modules(&mut stream, context),
        DaemonSocketAction::RequestCompanionSocket => {
            handle_request_companion_socket(&mut stream, context)
        }
        DaemonSocketAction::GetModuleDir => handle_get_module_dir(&mut stream, context),
        // Other cases are handled synchronously and won't reach here.
        _ => unreachable!(),
    }
}

/// Initializes global path variables from the daemon work directory.
fn initialize_globals(tmp_path: Option<&str>) -> Result<()> {
    let tmp_path = match tmp_path {
        // The normal path: the loader passes the work directory via `--workdir`.
        Some(path) if !path.is_empty() => path.to_owned(),
        Some(_) => bail!("TMP_PATH daemon argument is empty"),
        // Escape hatch for manual invocation without `--workdir`.
        None => std::env::var("TMP_PATH").context("TMP_PATH environment variable not set")?,
    };
    TMP_PATH.set(tmp_path).unwrap();

    CONTROLLER_SOCKET
        .set(format!("{}/init_monitor", TMP_PATH.get().unwrap()))
        .unwrap();
    DAEMON_SOCKET_PATH
        .set(format!(
            "{}/{}",
            TMP_PATH.get().unwrap(),
            lp_select!("/cp32.sock", "/cp64.sock")
        ))
        .unwrap();
    Ok(())
}

/// Sends initial status information to the controller.
fn send_startup_info(modules: &[Module]) -> Result<()> {
    let mut msg = Vec::<u8>::new();
    let info = match root_impl::get() {
        root_impl::RootImpl::APatch
        | root_impl::RootImpl::KernelSU
        | root_impl::RootImpl::Magisk => {
            msg.extend_from_slice(&constants::DAEMON_SET_INFO.to_le_bytes());
            let module_names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
            // Indented one level, to stand as its own block in the status readout, with
            // module names one level deeper again under their count.
            if !module_names.is_empty() {
                format!(
                    "\tRoot: {:?}\n\tModules ({}):\n\t\t{}",
                    root_impl::get(),
                    modules.len(),
                    module_names.join("\n\t\t")
                )
            } else {
                format!("\tRoot: {:?}", root_impl::get())
            }
        }
        _ => {
            msg.extend_from_slice(&constants::DAEMON_SET_ERROR_INFO.to_le_bytes());
            format!("\t\tInvalid root implementation: {:?}", root_impl::get())
        }
    };
    msg.extend_from_slice(&(info.len() as u32 + 1).to_le_bytes());
    msg.extend_from_slice(info.as_bytes());
    msg.push(0); // Null terminator
    utils::unix_datagram_sendto(CONTROLLER_SOCKET.get().unwrap(), &msg)
        .context("Failed to send startup info to controller")
}

/// Detects the device architecture.
fn get_arch() -> Result<&'static str> {
    let system_arch = utils::get_property("ro.product.cpu.abi")?;
    if system_arch.contains("arm") {
        Ok(lp_select!("armeabi-v7a", "arm64-v8a"))
    } else if system_arch.contains("x86") {
        Ok(lp_select!("x86", "x86_64"))
    } else {
        bail!("Unsupported system architecture: {}", system_arch)
    }
}

/// Scans the module directory, loads valid modules, and creates memfds for their libraries.
fn load_modules() -> Result<Vec<Module>> {
    let arch = get_arch()?;
    debug!("Daemon architecture: {arch}");

    let mut modules = Vec::new();
    let dir = match fs::read_dir(constants::PATH_MODULES_DIR) {
        Ok(dir) => dir,
        // No module directory at all means no modules, which is the normal state on a
        // build with no root framework. Anything else is a failure to read a directory
        // that does exist, and must be reported rather than passed off as an empty set:
        // `refresh_modules` would otherwise retire every live module and call it success.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!("No module directory at {}", constants::PATH_MODULES_DIR);
            return Ok(modules);
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("Failed to read {}", constants::PATH_MODULES_DIR));
        }
    };

    for entry in dir.flatten() {
        let name = entry.file_name().into_string().unwrap_or_default();
        let so_path = entry.path().join(format!("zygisk/{arch}.so"));
        let disabled_flag = entry.path().join("disable");

        if !so_path.exists() || disabled_flag.exists() {
            continue;
        }

        info!("Loading module `{}`...", name);
        match create_library_fd(&so_path) {
            Ok(lib_fd) => {
                modules.push(Module {
                    name,
                    lib_fd,
                    companion: Mutex::new(None),
                });
            }
            Err(e) => {
                warn!("Failed to create memfd for `{}`: {}", name, e);
            }
        };
    }

    Ok(modules)
}

/// Creates a sealed, read-only memfd containing the module's shared library.
/// This is a security measure to prevent the library from being tampered with after loading.
fn create_library_fd(so_path: &Path) -> Result<OwnedFd> {
    let opts = memfd::MemfdOptions::default().allow_sealing(true);
    let memfd = opts.create("zygisk-module")?;

    // Copy the library content into the memfd.
    let file = fs::File::open(so_path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut writer = memfd.as_file();
    std::io::copy(&mut reader, &mut writer)?;

    // Apply seals to make the memfd immutable.
    let mut seals = memfd::SealsHashSet::new();
    seals.insert(memfd::FileSeal::SealShrink);
    seals.insert(memfd::FileSeal::SealGrow);
    seals.insert(memfd::FileSeal::SealWrite);
    seals.insert(memfd::FileSeal::SealSeal);

    if let Err(e) = memfd.add_seals(&seals) {
        // Ignore errors for the sake of compatibility
        warn!("Failed to add seals : {}", e);
    }

    Ok(OwnedFd::from(memfd.into_file()))
}

/// Creates and binds the main daemon Unix socket.
fn create_daemon_socket() -> Result<UnixListener> {
    utils::set_socket_create_context("u:r:zygote:s0")?;
    let listener = utils::unix_listener_from_path(DAEMON_SOCKET_PATH.get().unwrap())?;
    Ok(listener)
}

/// Spawns a companion process for a module.
///
/// This involves forking, setting up a communication channel (Unix socket pair),
/// and re-executing the daemon binary with special arguments (`companion <fd>`).
fn spawn_companion(name: &str, lib_fd: RawFd) -> Result<Option<UnixStream>> {
    let (mut daemon_sock, companion_sock) = UnixStream::pair()?;

    // FIXME: A more robust way to get the current executable path is desirable.
    let self_exe = std::env::args().next().unwrap();
    let nice_name = self_exe.split('/').last().unwrap_or("zygiskd");

    // The fork/exec logic is now handled directly here.
    // # Safety
    // This is highly unsafe because it uses `fork()` and `exec()`. The child
    // process must not call any non-async-signal-safe functions before `exec()`.
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            // Fork failed
            bail!(Error::last_os_error());
        }

        if pid == 0 {
            // --- Child Process ---
            drop(daemon_sock); // Child doesn't need the daemon's end of the socket.

            // The companion socket FD must be passed to the new process,
            // so we must remove the `FD_CLOEXEC` flag.
            fcntl_setfd(companion_sock.as_fd(), FdFlags::empty())
                .expect("Failed to clear CLOEXEC on companion socket");

            // The first argument (`arg0`) is used to set a descriptive process name.
            let arg0 = format!("{}-{}", nice_name, name);
            let companion_fd_str = format!("{}", companion_sock.as_raw_fd());

            // exec replaces the current process; it does not return on success.
            let err = Command::new(&self_exe)
                .arg0(arg0)
                .arg("companion")
                .arg(companion_fd_str)
                .exec();

            // If exec returns, it's always an error.
            bail!("exec failed: {}", err);
        }

        // --- Parent Process ---
        drop(companion_sock); // Parent doesn't need the companion's end of the socket.

        // Now, establish communication with the newly spawned companion.
        daemon_sock.write_string(name)?;
        daemon_sock.send_fd(lib_fd)?;

        // Wait for the companion's response to know if it loaded the module successfully.
        match daemon_sock.read_u8()? {
            0 => Ok(None),              // Module has no companion entry point or failed to load.
            1 => Ok(Some(daemon_sock)), // Companion is ready.
            _ => bail!("Invalid response from companion setup"),
        }
    }
}

// --- Action Handlers ---

fn handle_get_process_flags(stream: &mut UnixStream) -> Result<()> {
    let uid = stream.read_u32()? as i32;
    let mut flags = ProcessFlags::empty();

    if root_impl::uid_is_manager(uid) {
        flags |= ProcessFlags::PROCESS_IS_MANAGER;
    } else {
        if root_impl::uid_granted_root(uid) {
            flags |= ProcessFlags::PROCESS_GRANTED_ROOT;
        }
        if root_impl::uid_should_umount(uid) {
            flags |= ProcessFlags::PROCESS_ON_DENYLIST;
        }
    }

    match root_impl::get() {
        root_impl::RootImpl::APatch => flags |= ProcessFlags::PROCESS_ROOT_IS_APATCH,
        root_impl::RootImpl::KernelSU => flags |= ProcessFlags::PROCESS_ROOT_IS_KSU,
        root_impl::RootImpl::Magisk => flags |= ProcessFlags::PROCESS_ROOT_IS_MAGISK,
        _ => (), // No flag for None, TooOld, or Multiple
    }

    trace!("Flags for UID {}: {:?}", uid, flags);
    stream.write_u32(flags.bits())?;
    Ok(())
}

fn handle_update_mount_namespace(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    let namespace_type = MountNamespace::try_from(stream.read_u8()?)?;
    if let Some(fd) = context.mount_manager.get_namespace_fd(namespace_type) {
        // Namespace is already cached, send the FD to the client.
        // SUCCESS: Send Status '1', then the FD.
        stream.write_u8(1)?;
        stream.send_fd(fd)?;
    } else {
        // FAILURE: Send Status '0'.
        // Do NOT send an FD or random u32 bytes, just stop here.
        warn!("Namespace {:?} is not cached yet.", namespace_type);
        stream.write_u8(0)?;
    }
    Ok(())
}

fn handle_read_modules(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    // One snapshot for the whole reply, so the count written first always matches the
    // number of entries that follow even if a refresh lands mid-reply.
    let modules = context.modules();
    stream.write_usize(modules.len())?;
    for module in modules.iter() {
        stream.write_string(&module.name)?;
        stream.send_fd(module.lib_fd.as_raw_fd())?;
    }
    Ok(())
}

/// Resolves a client-supplied module index against a snapshot.
///
/// The index comes from a previous `ReadModules` reply, so a client holding one from a
/// retired snapshot can present an index this one no longer has.
fn module_at(modules: &Arc<Vec<Module>>, index: usize) -> Result<&Module> {
    modules
        .get(index)
        .with_context(|| format!("Module index {} is out of range ({})", index, modules.len()))
}

fn handle_request_companion_socket(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    let index = stream.read_usize()?;
    let modules = context.modules();
    let module = match module_at(&modules, index) {
        Ok(module) => module,
        Err(e) => {
            warn!("{}", e);
            // Tell the client no companion is available rather than dropping the
            // connection, which is what it already handles.
            stream.write_u8(0)?;
            return Ok(());
        }
    };
    let mut companion = module.companion.lock().unwrap();

    // Check if the existing companion socket is still alive.
    if let Some(sock) = companion.as_ref() {
        if !utils::is_socket_alive(sock) {
            error!(
                "Companion for module `{}` appears to have crashed.",
                module.name
            );
            companion.take();
        }
    }

    // If no companion exists, try to spawn one.
    if companion.is_none() {
        match spawn_companion(&module.name, module.lib_fd.as_raw_fd()) {
            Ok(Some(sock)) => {
                trace!("Spawned new companion for `{}`.", module.name);
                *companion = Some(sock);
            }
            Ok(None) => {
                warn!(
                    "Module `{}` does not have a companion entry point.",
                    module.name
                );
            }
            Err(e) => {
                warn!("Failed to spawn companion for `{}`: {}", module.name, e);
            }
        };
    }

    // Send the companion FD to the client if available.
    if let Some(sock) = companion.as_ref() {
        if let Err(e) = sock.send_fd(stream.as_raw_fd()) {
            error!(
                "Failed to send companion socket FD for module `{}`: {}",
                module.name, e
            );
            // Inform client of failure.
            stream.write_u8(0)?;
        }
        // If successful, the companion itself will notify the client.
    } else {
        // Inform client that no companion is available.
        stream.write_u8(0)?;
    }
    Ok(())
}

fn handle_get_module_dir(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    let index = stream.read_usize()?;
    let modules = context.modules();
    let module = module_at(&modules, index)?;
    let dir_path = format!("{}/{}", constants::PATH_MODULES_DIR, module.name);
    let dir = fs::File::open(dir_path)?;
    stream.send_fd(dir.as_raw_fd())?;
    Ok(())
}
