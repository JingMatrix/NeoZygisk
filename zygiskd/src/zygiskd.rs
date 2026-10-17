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
use std::fs;
use std::os::fd::AsRawFd;
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::{
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    process::Command,
    sync::{Arc, Mutex, OnceLock},
    thread,
};

/// Represents a loaded Zygisk module.
struct Module {
    name: String,
    lib_fd: OwnedFd,
    /// A handle to the module's companion process socket, if it exists and is running.
    companion: Mutex<CompanionState>,
}

#[derive(Default)]
struct CompanionState {
    socket: Option<UnixStream>,
    /// Requests accepted before a restart must not recreate an old companion.
    retired: bool,
}

/// The shared context for the daemon, containing all loaded modules and a mount namespace manager
struct AppContext {
    modules: Vec<Module>,
    mount_manager: Arc<MountNamespaceManager>,
}

// Global paths, initialized once at startup.
static TMP_PATH: OnceLock<String> = OnceLock::new();
static CONTROLLER_SOCKET: OnceLock<String> = OnceLock::new();
static DAEMON_SOCKET_PATH: OnceLock<String> = OnceLock::new();

/// The main function for the zygiskd daemon.
pub fn main(tmp_path: Option<&str>) -> Result<()> {
    info!("Welcome to NeoZygisk ({}) !", ZKSU_VERSION);

    initialize_globals(tmp_path)?;
    let modules = load_modules()?;
    send_startup_info(&modules)?;

    let mount_manager = Arc::new(MountNamespaceManager::new());
    let mut context = Arc::new(AppContext {
        modules,
        mount_manager,
    });
    let listener = create_daemon_socket()?;

    info!("Daemon listening on {}", DAEMON_SOCKET_PATH.get().unwrap());

    // Main event loop: accept and handle incoming connections.
    for stream in listener.incoming() {
        let stream = stream.context("Failed to accept incoming connection")?;
        if let Err(e) = handle_connection(stream, &mut context) {
            warn!("Error handling connection: {}", e);
        }
    }

    Ok(())
}

/// Handles a single incoming connection from Zygisk.
fn handle_connection(mut stream: UnixStream, context: &mut Arc<AppContext>) -> Result<()> {
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
            info!("Zygote restarted, refreshing modules and cleaning up companions.");
            // This runs in the accept loop before any post-restart requests are
            // dispatched. Already dispatched requests retain their own snapshot.
            refresh_modules(context, Path::new(constants::PATH_MODULES_DIR), get_arch()?)?;
            if let Err(e) = send_startup_info(&context.modules) {
                warn!("Failed to update module status after restart: {}", e);
            }
        }
        DaemonSocketAction::SystemServerStarted => {
            let value = constants::SYSTEM_SERVER_STARTED;
            utils::unix_datagram_sendto(CONTROLLER_SOCKET.get().unwrap(), &value.to_le_bytes())?;
        }
        // Heavier actions are spawned into a separate thread.
        _ => {
            let context = Arc::clone(context);
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
            if !module_names.is_empty() {
                format!(
                    "\t\tRoot: {:?}\n\t\tModules ({}):\n\t\t\t{}",
                    root_impl::get(),
                    modules.len(),
                    module_names.join("\n\t\t\t")
                )
            } else {
                format!("\t\tRoot: {:?}", root_impl::get())
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
    load_modules_from(Path::new(constants::PATH_MODULES_DIR), arch, false)
}

/// Cold boot keeps the existing best-effort loading behavior. A refresh must
/// finish completely before publishing a replacement for the active snapshot.
fn load_modules_from(root: &Path, arch: &str, strict: bool) -> Result<Vec<Module>> {
    let mut modules = Vec::new();
    let dir = match fs::read_dir(root) {
        Ok(dir) => dir,
        Err(e) => {
            if strict {
                return Err(e).context("Failed to scan modules for refresh");
            }
            warn!("Failed to read modules directory: {}", e);
            return Ok(modules);
        }
    };

    for entry in dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) if strict => return Err(e).context("Failed to enumerate modules for refresh"),
            Err(_) => continue,
        };
        let name = entry.file_name().into_string().unwrap_or_default();
        let so_path = entry.path().join(format!("zygisk/{arch}.so"));
        let disabled_flag = entry.path().join("disable");

        let (library_exists, disabled) = if strict {
            (
                so_path
                    .try_exists()
                    .context("Failed to inspect module library")?,
                disabled_flag
                    .try_exists()
                    .context("Failed to inspect module disable flag")?,
            )
        } else {
            (so_path.exists(), disabled_flag.exists())
        };
        if !library_exists || disabled {
            continue;
        }

        info!("Loading module `{}`...", name);
        match create_library_fd(&so_path) {
            Ok(lib_fd) => {
                modules.push(Module {
                    name,
                    lib_fd,
                    companion: Mutex::new(CompanionState::default()),
                });
            }
            Err(e) => {
                if strict {
                    return Err(e).context(format!("Failed to refresh module `{}`", name));
                }
                warn!("Failed to create memfd for `{}`: {}", name, e);
            }
        };
    }

    Ok(modules)
}

fn refresh_modules(context: &mut Arc<AppContext>, root: &Path, arch: &str) -> Result<()> {
    let modules = load_modules_from(root, arch, true);
    for module in &context.modules {
        let mut companion = module.companion.lock().unwrap();
        companion.socket.take();
        // Preserve the old usable snapshot on a failed scan, but still perform
        // the companion reset that the previous restart handler provided.
        companion.retired = modules.is_ok();
    }
    let modules = modules.context("Module refresh failed; retaining previous libraries")?;
    *context = Arc::new(AppContext {
        modules,
        mount_manager: Arc::clone(&context.mount_manager),
    });
    Ok(())
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

    // Construct arguments before spawning; a dedicated owner waits even when
    // setup fails or a restart drops the control socket much later.
    let mut command = Command::new(&self_exe);
    command
        .arg0(format!("{}-{}", nice_name, name))
        .arg("companion")
        .arg(companion_sock.as_raw_fd().to_string());
    crate::child::spawn_and_reap(command, companion_sock.into())
        .context("Failed to spawn companion")?;

    daemon_sock.write_string(name)?;
    daemon_sock.send_fd(lib_fd)?;
    match daemon_sock.read_u8()? {
        0 => Ok(None),              // No companion entry point or failed to load.
        1 => Ok(Some(daemon_sock)), // Companion is ready.
        _ => bail!("Invalid response from companion setup"),
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
    stream.write_usize(context.modules.len())?;
    for module in &context.modules {
        stream.write_string(&module.name)?;
        stream.send_fd(module.lib_fd.as_raw_fd())?;
    }
    Ok(())
}

fn handle_request_companion_socket(stream: &mut UnixStream, context: &AppContext) -> Result<()> {
    let index = stream.read_usize()?;
    let Some(module) = context.modules.get(index) else {
        stream.write_u8(0)?;
        return Ok(());
    };
    let mut state = module.companion.lock().unwrap();
    if state.retired {
        stream.write_u8(0)?;
        return Ok(());
    }
    let companion = &mut state.socket;

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
    let module = context.modules.get(index).context("Invalid module index")?;
    let dir_path = format!("{}/{}", constants::PATH_MODULES_DIR, module.name);
    let dir = fs::File::open(dir_path)?;
    stream.send_fd(dir.as_raw_fd())?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::FileExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const ARCH: &str = "arm64-v8a";
    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "neozygisk-modules-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn library(&self, name: &str, content: &[u8]) -> PathBuf {
            let path = self.0.join(name).join("zygisk").join(format!("{ARCH}.so"));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, content).unwrap();
            path
        }

        fn context(&self) -> Arc<AppContext> {
            Arc::new(AppContext {
                modules: load_modules_from(&self.0, ARCH, false).unwrap(),
                mount_manager: Arc::new(MountNamespaceManager::new()),
            })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn contents(fd: &OwnedFd) -> Vec<u8> {
        let file = fs::File::from(fd.try_clone().unwrap());
        let mut bytes = vec![0; file.metadata().unwrap().len() as usize];
        file.read_exact_at(&mut bytes, 0).unwrap();
        bytes
    }

    #[test]
    fn refresh_updates_sealed_library_and_keeps_inflight_snapshot_consistent() {
        let fixture = Fixture::new();
        fixture.library("module", b"previous library");
        let mut current = fixture.context();
        let inflight = Arc::clone(&current);
        fixture.library("module", b"updated library with a different length");
        refresh_modules(&mut current, &fixture.0, ARCH).unwrap();
        assert_eq!(contents(&inflight.modules[0].lib_fd), b"previous library");
        assert_eq!(
            contents(&current.modules[0].lib_fd),
            b"updated library with a different length"
        );
        assert!(!Arc::ptr_eq(&current, &inflight));
        assert!(Arc::ptr_eq(&current.mount_manager, &inflight.mount_manager));
        let file = fs::File::from(current.modules[0].lib_fd.try_clone().unwrap());
        assert_eq!(
            file.write_at(b"x", 0).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );

        // Exercise the actual response framing and SCM_RIGHTS transfer, not
        // just the cache fields. A request owns one complete generation.
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let worker = thread::spawn(move || handle_read_modules(&mut server, &inflight));
        assert_eq!(client.read_usize().unwrap(), 1);
        assert_eq!(client.read_string().unwrap(), "module");
        use std::os::fd::FromRawFd;
        let received = unsafe { OwnedFd::from_raw_fd(client.recv_fd().unwrap()) };
        assert_eq!(contents(&received), b"previous library");
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn restart_rescans_added_disabled_removed_and_reenabled_modules() {
        let fixture = Fixture::new();
        fixture.library("one", b"1");
        let mut current = fixture.context();
        fixture.library("two", b"2");
        fs::write(fixture.0.join("one/disable"), b"").unwrap();
        refresh_modules(&mut current, &fixture.0, ARCH).unwrap();
        assert_eq!(current.modules.len(), 1);
        assert_eq!(current.modules[0].name, "two");
        fs::remove_dir_all(fixture.0.join("two")).unwrap();
        fs::remove_file(fixture.0.join("one/disable")).unwrap();
        refresh_modules(&mut current, &fixture.0, ARCH).unwrap();
        assert_eq!(current.modules.len(), 1);
        assert_eq!(current.modules[0].name, "one");
    }

    #[test]
    fn failed_refresh_preserves_complete_snapshot_and_still_closes_companion() {
        let fixture = Fixture::new();
        let path = fixture.library("module", b"working library");
        let mut current = fixture.context();
        let previous = Arc::clone(&current);
        let (mut peer, companion) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        current.modules[0].companion.lock().unwrap().socket = Some(companion);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap(); // Existing path, but copying it must fail.
        assert!(refresh_modules(&mut current, &fixture.0, ARCH).is_err());
        assert!(Arc::ptr_eq(&current, &previous));
        assert_eq!(contents(&current.modules[0].lib_fd), b"working library");
        assert!(!current.modules[0].companion.lock().unwrap().retired);
        assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
        assert!(refresh_modules(&mut current, &fixture.0.join("missing"), ARCH).is_err());
        assert!(Arc::ptr_eq(&current, &previous));
        fs::remove_dir(&path).unwrap();
        std::os::unix::fs::symlink(path.file_name().unwrap(), &path).unwrap();
        // An inspection error must not silently turn an enabled module into a
        // missing module and publish a partial replacement list.
        assert!(refresh_modules(&mut current, &fixture.0, ARCH).is_err());
        assert!(Arc::ptr_eq(&current, &previous));
    }

    #[test]
    fn retired_worker_cannot_start_an_old_companion_and_invalid_ids_do_not_panic() {
        let fixture = Fixture::new();
        fixture.library("module", b"library");
        let mut current = fixture.context();
        let previous = Arc::clone(&current);
        let (mut peer, companion) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        previous.modules[0].companion.lock().unwrap().socket = Some(companion);
        refresh_modules(&mut current, &fixture.0, ARCH).unwrap();
        assert!(previous.modules[0].companion.lock().unwrap().retired);
        assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
        for (context, index) in [(&previous, 0), (&current, usize::MAX)] {
            let (mut server, mut client) = UnixStream::pair().unwrap();
            client.write_usize(index).unwrap();
            handle_request_companion_socket(&mut server, context).unwrap();
            assert_eq!(client.read_u8().unwrap(), 0);
        }
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_usize(usize::MAX).unwrap();
        assert!(handle_get_module_dir(&mut server, &current).is_err());
    }

    #[test]
    fn repeated_refreshes_release_previous_snapshots() {
        let fixture = Fixture::new();
        fixture.library("module", b"first");
        let mut current = fixture.context();
        for generation in 0..64 {
            let previous = Arc::downgrade(&current);
            fixture.library("module", generation.to_string().as_bytes());
            refresh_modules(&mut current, &fixture.0, ARCH).unwrap();
            assert!(previous.upgrade().is_none());
            assert_eq!(
                contents(&current.modules[0].lib_fd),
                generation.to_string().as_bytes()
            );
        }
    }
}
