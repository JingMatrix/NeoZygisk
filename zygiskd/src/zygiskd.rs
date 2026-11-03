// src/zygiskd.rs

//! The core logic for the Zygisk daemon (`zygiskd`).
//!
//! This module is responsible for:
//! - Initializing paths and communication channels.
//! - Loading Zygisk modules from the designated directory.
//! - Listening on a Unix domain socket for requests from the Zygisk injector.
//! - Handling requests such as providing module libraries, querying process flags,
//!   and managing companion processes.

use crate::constants::{self, DaemonSocketAction, ProcessFlags, ZKSU_VERSION};
use crate::exclude;
use crate::mount::{MountNamespace, MountNamespaceManager};
use crate::utils::{self, UnixStreamExt};
use crate::{lp_select, root_impl};
use anyhow::{Context as AnyhowContext, Result, bail};
use log::{debug, error, info, trace, warn};
use serde_json;
use passfd::FdPassingExt;
use std::collections::HashMap;
use std::fs;
use std::io::Error;
use std::mem::size_of;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::{
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{
        atomic::{fence, Ordering},
        Arc, Mutex, OnceLock, RwLock,
    },
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
    zn_companions: Mutex<HashMap<PathBuf, UnixStream>>,
    zn_states: Mutex<HashMap<PathBuf, (u32, u32)>>,
    /// Companions spawned and not yet waited for. A companion is a child of a daemon
    /// that never exits, so one that exits stays a zombie until `reap_companions` runs.
    pending_companions: Mutex<Vec<Child>>,
}

impl AppContext {
    /// Takes a reference to the current snapshot. Held only long enough to clone the
    /// `Arc`, so a refresh is never blocked by a slow reader.
    fn modules(&self) -> Arc<Vec<Module>> {
        Arc::clone(&self.modules.read().unwrap())
    }

    fn reap_companions(&self) {
        self.pending_companions
            .lock()
            .unwrap()
            .retain_mut(|child| match child.try_wait() {
                Ok(None) => true,
                Ok(Some(status)) => {
                    if !status.success() {
                        warn!("Companion {} exited: {}", child.id(), status);
                    }
                    false
                }
                Err(e) => {
                    warn!("Cannot wait for companion {}: {}", child.id(), e);
                    false
                }
            });
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
        self.reap_companions();
        info!("Module snapshot refreshed: {} module(s) {:?}", count, names);
        Ok(count)
    }
}

// Global paths, initialized once at startup.
static TMP_PATH: OnceLock<String> = OnceLock::new();
static CONTROLLER_SOCKET: OnceLock<String> = OnceLock::new();
static DAEMON_SOCKET_PATH: OnceLock<String> = OnceLock::new();
static SHARED_MEMORY: OnceLock<SharedShm> = OnceLock::new();

struct SharedShm {
    fd: OwnedFd,
    layout: *mut constants::ShmLayout,
    len: usize,
    write_lock: Mutex<()>,
}

unsafe impl Send for SharedShm {}
unsafe impl Sync for SharedShm {}

impl SharedShm {
    fn layout(&self) -> &constants::ShmLayout {
        // The mapping outlives this object and every shared field is accessed atomically.
        unsafe { &*self.layout }
    }
}

impl Drop for SharedShm {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.layout as *mut _, self.len);
        }
    }
}

/// The main function for the zygiskd daemon.
pub fn main(tmp_path: Option<&str>) -> Result<()> {
    info!("Welcome to NyaZygisk ({}) !", ZKSU_VERSION);

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
        zn_companions: Mutex::new(HashMap::new()),
        zn_states: Mutex::new(HashMap::new()),
        pending_companions: Mutex::new(Vec::new()),
    });
    let listener = create_daemon_socket()?;
    spawn_config_watcher();

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
    let action = stream.read_u8()?;
    let action = DaemonSocketAction::try_from(action)
        .with_context(|| format!("Invalid daemon action code: {}", action))?;
    trace!("New daemon action: {:?}", action);

    match action {
        // These actions are lightweight and handled synchronously.
        DaemonSocketAction::CacheMountNamespace => {
            let pid = stream.read_u32()? as i32;
            // Only the zygote/root context legitimately calls this, for its own pid,
            // before dropping privileges to the forked child's app uid, and a late-injected
            // system_server (uid 1000) for itself. Reject anyone else so an
            // already-specialized app can't poison another pid's cached mount namespace entry.
            const AID_SYSTEM: u32 = 1000;
            if !matches!(utils::peer_uid(&stream), Some(0) | Some(AID_SYSTEM)) {
                warn!("CacheMountNamespace: rejecting request from untrusted peer for pid {}", pid);
            } else {
                context
                    .mount_manager
                    .save_mount_namespace(pid, MountNamespace::Clean)?;
                context
                    .mount_manager
                    .save_mount_namespace(pid, MountNamespace::Root)?;
            }
        }
        DaemonSocketAction::PingHeartbeat => {
            let value = constants::ZYGOTE_INJECTED;
            utils::unix_datagram_sendto(CONTROLLER_SOCKET.get().unwrap(), &value.to_le_bytes())?;
        }
        DaemonSocketAction::ZygoteRestart => {
            info!("Zygote restarted, dropping companions, resetting mount namespaces, and rescanning modules.");
            context.mount_manager.reset();
            // Drop the companions first and unconditionally: they served a framework that
            // no longer exists, and leaving it to the snapshot swap would strand them if
            // the rescan failed.
            for module in context.modules().iter() {
                module.companion.lock().unwrap().take();
            }
            context.zn_companions.lock().unwrap().clear();
            context.zn_states.lock().unwrap().clear();
            write_zn_state_file(&HashMap::new());
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
        DaemonSocketAction::RequestZnCompanionSocket => {
            handle_request_zn_companion_socket(&mut stream, context)
        }
        DaemonSocketAction::GetModuleDir => handle_get_module_dir(&mut stream, context),
        DaemonSocketAction::GetSharedMemoryFd => handle_get_shared_memory_fd(&mut stream),
        DaemonSocketAction::GetZnPlan => handle_get_zn_plan(&mut stream, context),
        DaemonSocketAction::ReportZnModule => handle_report_zn_module(&mut stream, context),
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
    initialize_shared_memory()?;
    Ok(())
}

fn get_kernel_version() -> String {
    Command::new("/system/bin/uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn get_device_sdk() -> String {
    utils::get_property("ro.build.version.sdk").unwrap_or_else(|_| "Unknown".to_string())
}

fn get_device_abi() -> String {
    let abi = utils::get_property("ro.product.cpu.abi").unwrap_or_else(|_| "Unknown".to_string());
    let arch = std::env::consts::ARCH;
    format!("{} ({})", abi, arch)
}

/// Sends initial status information to the controller.
fn send_startup_info(modules: &[Module]) -> Result<()> {
    let mut msg = Vec::<u8>::new();
    let info = match root_impl::get() {
        root_impl::RootImpl::APatch
        | root_impl::RootImpl::KernelSU
        | root_impl::RootImpl::Magisk => {
            msg.extend_from_slice(&constants::DAEMON_SET_INFO.to_le_bytes());
            
            let mut module_entries = Vec::new();
            for m in modules {
                module_entries.push(serde_json::json!({
                    "name": m.name,
                    "type": "zygisk",
                    "target": "zygote",
                    "companion": false
                }));
            }

            // Scan for Zygisk Next modules (zn_modules.txt)
            if let Ok(dir) = fs::read_dir(constants::PATH_MODULES_DIR) {
                for entry in dir.flatten() {
                    let name = entry.file_name().into_string().unwrap_or_default();
                    let zn_file = entry.path().join("zn_modules.txt");
                    let disabled = entry.path().join("disable");
                    let remove = entry.path().join("remove");
                    if zn_file.exists() && !disabled.exists() && !remove.exists() {
                        let mut targets = Vec::new();
                        let mut has_companion = false;
                        if let Ok(content) = fs::read_to_string(&zn_file) {
                            for line in content.lines() {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() >= 2 {
                                    targets.push(parts[0].to_string());
                                    if parts.iter().any(|&p| p == "companion") {
                                        has_companion = true;
                                    }
                                }
                            }
                        }
                        module_entries.push(serde_json::json!({
                            "name": name,
                            "type": "next",
                            "target": if targets.is_empty() { "unknown".to_string() } else { targets.join(", ") },
                            "companion": has_companion
                        }));
                    }
                }
            }

            let modules_json =
                serde_json::to_string(&module_entries).unwrap_or_else(|_| "[]".to_string());
            format!(
                "root_implementation={:?}\nmodules_count={}\nmodules_list={}\ndevice_kernel={}\ndevice_sdk={}\ndevice_abi={}",
                root_impl::get(),
                module_entries.len(),
                modules_json,
                get_kernel_version(),
                get_device_sdk(),
                get_device_abi()
            )
        }
        _ => {
            msg.extend_from_slice(&constants::DAEMON_SET_ERROR_INFO.to_le_bytes());
            format!("root_implementation=Invalid({:?})", root_impl::get())
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
    } else if system_arch.contains("riscv64") {
        Ok("riscv64")
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

/// Spawns a companion process for a module: this binary re-executed as
/// `companion <fd>`, holding one end of a socket pair.
fn spawn_companion(context: &AppContext, name: &str, lib_fd: RawFd) -> Result<Option<UnixStream>> {
    let (mut daemon_sock, companion_sock) = UnixStream::pair()?;

    // FIXME: A more robust way to get the current executable path is desirable.
    let self_exe = std::env::args().next().unwrap();
    let nice_name = self_exe.split('/').last().unwrap_or("zygiskd");

    let companion_fd = companion_sock.as_raw_fd();
    let mut command = Command::new(&self_exe);
    command
        .arg0(format!("{}-{}", nice_name, name))
        .arg("companion")
        .arg(companion_fd.to_string());
    // The socket is the one fd that has to survive exec, and clearing the flag is all a
    // child forked from a multi-threaded process should do before it is replaced.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(companion_fd, libc::F_SETFD, 0) == -1 {
                return Err(Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command.spawn().context("Failed to spawn companion")?;
    context.pending_companions.lock().unwrap().push(child);
    // The companion owns its copy now. Keeping ours would deny the read below the EOF it
    // needs when a companion dies before answering.
    drop(companion_sock);

    daemon_sock.write_string(name)?;
    daemon_sock.send_fd(lib_fd)?;

    // Wait for the companion's response to know if it loaded the module successfully.
    match daemon_sock.read_u8()? {
        0 => Ok(None),              // Module has no companion entry point or failed to load.
        1 => Ok(Some(daemon_sock)), // Companion is ready.
        _ => bail!("Invalid response from companion setup"),
    }
}

// --- Action Handlers ---

fn handle_get_process_flags(stream: &mut UnixStream) -> Result<()> {
    let uid = stream.read_u32()? as i32;

    // Legitimate callers ask this while still running as zygote/root, before dropping
    // privileges to `uid`. An already-specialized app connecting directly to this
    // socket would otherwise be able to probe any other uid's root-grant/denylist
    // state, so it gets an empty, uncached answer instead.
    if utils::peer_uid(stream) != Some(0) {
        warn!("GetProcessFlags: rejecting request from non-root peer for uid {}", uid);
        stream.write_u32(0)?;
        return Ok(());
    }

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
        if let Some(unmount) = u32::try_from(uid).ok().and_then(exclude::lookup) {
            flags |= ProcessFlags::PROCESS_EXCLUDED;
            if unmount {
                flags |= ProcessFlags::PROCESS_ON_DENYLIST;
            }
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
    if uid >= 0 {
        cache_process_flags(uid as u32, flags.bits());
    }
    Ok(())
}

fn handle_update_mount_namespace(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    let namespace_type = MountNamespace::try_from(stream.read_u8()?)?;

    // Only the zygote/root context, mid-specialize, legitimately needs to setns()
    // into the cached namespaces (setns itself would fail without CAP_SYS_ADMIN for
    // anyone else), but there's no reason to hand the fd out at all to a peer that
    // isn't root.
    if utils::peer_uid(stream) != Some(0) {
        warn!("UpdateMountNamespace: rejecting request from non-root peer");
        stream.write_u8(0)?;
        return Ok(());
    }

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
    // Every injected process comes through here, which is what keeps a companion that
    // died between refreshes from staying a zombie for long.
    context.reap_companions();
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
        match spawn_companion(context, &module.name, module.lib_fd.as_raw_fd()) {
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

fn handle_request_zn_companion_socket(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    let lib_path = PathBuf::from(stream.read_string()?);

    let mut table = context.zn_companions.lock().unwrap();

    if let Some(sock) = table.get(&lib_path) {
        if !utils::is_socket_alive(sock) {
            warn!("ZN companion for `{}` appears to have crashed.", lib_path.display());
            table.remove(&lib_path);
        }
    }

    if !table.contains_key(&lib_path) {
        match spawn_zn_companion(context, &lib_path) {
            Ok(Some(sock)) => {
                trace!("Spawned new ZN companion for `{}`.", lib_path.display());
                table.insert(lib_path.clone(), sock);
            }
            Ok(None) => {
                warn!("ZN module `{}` does not have a companion entry point.", lib_path.display());
            }
            Err(e) => {
                warn!("Failed to spawn ZN companion for `{}`: {}", lib_path.display(), e);
            }
        }
    }

    if let Some(sock) = table.get(&lib_path) {
        if let Err(e) = sock.send_fd(stream.as_raw_fd()) {
            error!("Failed to send ZN companion FD for `{}`: {}", lib_path.display(), e);
            stream.write_u8(0)?;
        }
        // If successful, the companion itself will notify the client.
    } else {
        stream.write_u8(0)?;
    }
    Ok(())
}

fn spawn_zn_companion(context: &AppContext, lib_path: &Path) -> Result<Option<UnixStream>> {
    let (mut daemon_sock, companion_sock) = UnixStream::pair()?;
    let self_exe = std::env::args().next().unwrap();

    let companion_fd = companion_sock.as_raw_fd();
    let mut command = Command::new(&self_exe);
    command
        .arg0("zygiskd-zn-companion")
        .arg("zn-companion")
        .arg(lib_path)
        .arg(companion_fd.to_string());
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(companion_fd, libc::F_SETFD, 0) == -1 {
                return Err(Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command.spawn().context("Failed to spawn ZN companion")?;
    context.pending_companions.lock().unwrap().push(child);
    drop(companion_sock);

    match daemon_sock.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(daemon_sock)),
        _ => bail!("Invalid response from ZN companion setup"),
    }
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

struct ZnPlanModule {
    lib_path: String,
    companion: bool,
    lib_fd: OwnedFd,
}

fn is_elf_matching_arch(path: &Path) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    use std::io::Read;
    let mut header = [0u8; 5];
    if file.read_exact(&mut header).is_err() {
        return false;
    }
    if &header[..4] != b"\x7FELF" {
        return false;
    }
    let expected_class = if cfg!(target_pointer_width = "64") { 2 } else { 1 };
    header[4] == expected_class
}

fn scan_zn_modules_for_target(process_name: &str, process_path: &str) -> Result<Vec<ZnPlanModule>> {
    let mut results = Vec::new();
    let dir = match fs::read_dir(constants::PATH_MODULES_DIR) {
        Ok(d) => d,
        Err(e) => {
            warn!("Failed to read modules directory for ZN: {}", e);
            return Ok(results);
        }
    };

    let mut seen_libs = std::collections::HashSet::new();

    for entry in dir.flatten() {
        let mod_dir = entry.path();
        let disabled = mod_dir.join("disable");
        let remove = mod_dir.join("remove");
        let zn_file = mod_dir.join("zn_modules.txt");

        if !zn_file.exists() || disabled.exists() || remove.exists() {
            continue;
        }

        let content = match fs::read_to_string(&zn_file) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read {}: {}", zn_file.display(), e);
                continue;
            }
        };

        for line in content.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 2 {
                continue;
            }

            let first = tokens[0];
            let target_matches = if let Some(target_name) = first.strip_prefix("name=") {
                if target_name == "zygote" || target_name == "zygote64" || target_name == "zygote32" {
                    process_name.contains("zygote") || process_name.contains("app_process")
                } else {
                    process_name == target_name
                }
            } else if let Some(target_path) = first.strip_prefix("path=") {
                process_path == target_path
            } else {
                false
            };

            if !target_matches {
                continue;
            }

            let companion = tokens[1..tokens.len() - 1].contains(&"companion");
            let lib_subpath = tokens.last().unwrap();

            let candidate = if lib_subpath.starts_with('/') {
                PathBuf::from(lib_subpath)
            } else {
                mod_dir.join(lib_subpath)
            };

            let canonical_mod = match fs::canonicalize(&mod_dir) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let canonical_lib = match fs::canonicalize(&candidate) {
                Ok(p) => p,
                Err(_) => continue,
            };

            if !canonical_lib.starts_with(&canonical_mod) || canonical_lib == canonical_mod {
                warn!(
                    "ZN module lib `{}` is outside module dir `{}`",
                    canonical_lib.display(),
                    canonical_mod.display()
                );
                continue;
            }

            if !is_elf_matching_arch(&canonical_lib) {
                trace!(
                    "Skipping ZN module lib `{}`: architecture mismatch",
                    canonical_lib.display()
                );
                continue;
            }

            let lib_path_str = canonical_lib.to_string_lossy().into_owned();
            if seen_libs.contains(&lib_path_str) {
                continue;
            }

            match create_library_fd(&canonical_lib) {
                Ok(lib_fd) => {
                    info!(
                        "ZN: prepared module `{}` for {} (companion={})",
                        lib_path_str, process_name, companion
                    );
                    seen_libs.insert(lib_path_str.clone());
                    results.push(ZnPlanModule {
                        lib_path: lib_path_str,
                        companion,
                        lib_fd,
                    });
                }
                Err(e) => {
                    warn!("Failed to create memfd for ZN module `{}`: {}", lib_path_str, e);
                }
            }
        }
    }

    Ok(results)
}

fn handle_get_zn_plan(stream: &mut UnixStream, _context: &AppContext) -> Result<()> {
    let process_name = stream.read_string()?;
    let process_path = stream.read_string()?;
    debug!("GetZnPlan request for process: name={}, path={}", process_name, process_path);

    let matching = scan_zn_modules_for_target(&process_name, &process_path)?;
    stream.write_usize(matching.len())?;

    for m in matching {
        stream.write_string(&m.lib_path)?;
        stream.write_u8(if m.companion { 1 } else { 0 })?;
        stream.send_fd(m.lib_fd.as_raw_fd())?;
    }
    Ok(())
}

fn write_zn_state_file(states: &HashMap<PathBuf, (u32, u32)>) {
    let Some(tmp) = TMP_PATH.get() else { return };
    let mut lines: Vec<String> = states
        .iter()
        .map(|(path, (injected, failed))| {
            let state = if *failed > 0 { "failed" } else if *injected > 0 { "injected" } else { "unknown" };
            format!("{} {}", state, path.display())
        })
        .collect();
    lines.sort();
    let target = format!("{}/zn_modules_state", tmp);
    let staging = format!("{}.tmp", target);
    let result = fs::write(&staging, lines.join("\n") + "\n").and_then(|_| fs::rename(&staging, &target));
    if let Err(e) = result {
        warn!("Failed to write {}: {}", target, e);
    }
}

fn handle_report_zn_module(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    let lib_path = PathBuf::from(stream.read_string()?);
    let injected = stream.read_u8()? != 0;

    // Only paths inside the modules directory are tracked; anything else is not a ZN module we handed out.
    let modules_dir = fs::canonicalize(constants::PATH_MODULES_DIR)?;
    if lib_path.strip_prefix(&modules_dir).is_ok() {
        let mut states = context.zn_states.lock().unwrap();
        let entry = states.entry(lib_path.clone()).or_insert((0, 0));
        if injected {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
        info!(
            "ZN: module `{}` {} (injected={}, failed={})",
            lib_path.display(),
            if injected { "injected" } else { "failed to load" },
            entry.0,
            entry.1
        );
        write_zn_state_file(&states);
    } else {
        warn!("ZN: ignoring report for `{}` outside the modules directory", lib_path.display());
    }
    stream.write_u8(1)?;
    Ok(())
}

fn handle_get_shared_memory_fd(stream: &mut UnixStream) -> Result<()> {
    if let Some(shm) = SHARED_MEMORY.get() {
        stream.write_u8(1)?;
        stream.send_fd(shm.fd.as_raw_fd())?;
    } else {
        stream.write_u8(0)?;
    }
    Ok(())
}

fn initialize_shared_memory() -> Result<()> {
    let size = size_of::<constants::ShmLayout>();
    let memfd = memfd::MemfdOptions::default()
        .allow_sealing(true)
        .create("zygisk-shm")?;

    {
        let file = memfd.as_file();
        file.set_len(size as u64)?;
    }

    let mut seals = memfd::SealsHashSet::new();
    seals.insert(memfd::FileSeal::SealShrink);
    seals.insert(memfd::FileSeal::SealGrow);
    seals.insert(memfd::FileSeal::SealSeal);
    if let Err(e) = memfd.add_seals(&seals) {
        warn!("Failed to add seals to shared memory memfd: {}", e);
    }

    let owned_fd = OwnedFd::from(memfd.into_file());
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            owned_fd.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        bail!(
            "mmap shared memory failed: {}",
            Error::last_os_error()
        );
    }

    let layout = unsafe { &mut *(ptr as *mut constants::ShmLayout) };
    layout.version.store(0, Ordering::Relaxed);
    for entry in layout.entries.iter_mut() {
        entry.uid.store(u32::MAX, Ordering::Relaxed);
        entry.flags.store(0, Ordering::Relaxed);
    }

    SHARED_MEMORY
        .set(SharedShm {
            fd: owned_fd,
            layout: ptr as *mut _,
            len: size,
            write_lock: Mutex::new(()),
        })
        .map_err(|_| {
            unsafe {
                libc::munmap(ptr, size);
            }
            anyhow::anyhow!("Shared memory already initialized")
        })?;

    Ok(())
}

/// Drops every cached entry so the next `GetProcessFlags` of each uid reaches the daemon.
fn invalidate_process_flag_cache() {
    if let Some(shm) = SHARED_MEMORY.get() {
        let _guard = shm.write_lock.lock().unwrap();
        let layout = shm.layout();
        let base_version = layout.version.load(Ordering::Relaxed);
        layout
            .version
            .store(base_version.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);

        for entry in layout.entries.iter() {
            entry.uid.store(u32::MAX, Ordering::Relaxed);
            entry.flags.store(0, Ordering::Relaxed);
        }

        layout
            .version
            .store(base_version.wrapping_add(2), Ordering::Release);
    }
}

/// Flushes the flag cache whenever the WebUI rewrites `config.prop`; otherwise a cached
/// answer would keep serving the old exclusion list until the daemon restarts.
fn spawn_config_watcher() {
    thread::spawn(|| {
        let mut last = exclude::config_mtime();
        loop {
            thread::sleep(std::time::Duration::from_secs(1));
            let current = exclude::config_mtime();
            if current != last {
                last = current;
                // Re-read first so a miss right after the flush sees the new list.
                exclude::refresh();
                invalidate_process_flag_cache();
                debug!("config.prop changed, process flag cache flushed");
            }
        }
    });
}

fn cache_process_flags(uid: u32, flags: u32) {
    if let Some(shm) = SHARED_MEMORY.get() {
        let _guard = shm.write_lock.lock().unwrap();
        let layout = shm.layout();
        let base_version = layout.version.load(Ordering::Relaxed);
        layout
            .version
            .store(base_version.wrapping_add(1), Ordering::Relaxed);
        // Publish the odd version before any entry update becomes visible.
        fence(Ordering::Release);

        let mask = constants::SHM_HASH_MAP_SIZE - 1;
        let mut index = (uid as usize) & mask;
        let start_index = index;
        let mut inserted = false;

        loop {
            let entry = &layout.entries[index];
            let current_uid = entry.uid.load(Ordering::Relaxed);
            if current_uid == u32::MAX || current_uid == uid {
                entry.uid.store(uid, Ordering::Relaxed);
                entry.flags.store(flags, Ordering::Relaxed);
                inserted = true;
                break;
            }

            index = (index + 1) & mask;
            if index == start_index {
                break;
            }
        }

        if !inserted {
            warn!("Shared memory cache is full; could not cache uid {}", uid);
        }

        layout
            .version
            .store(base_version.wrapping_add(2), Ordering::Release);
    }
}
