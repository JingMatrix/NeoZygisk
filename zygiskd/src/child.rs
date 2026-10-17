//! Spawn a daemon child with an owner that waits for its exit on every path.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

/// The waiter is created before the child, so failure to create a thread cannot
/// leave a running child without an owner. Only this child's status is consumed;
/// mount-namespace helpers and other Command users retain their own waiters.
pub fn spawn_and_reap(mut command: Command, inherited_fd: OwnedFd) -> io::Result<u32> {
    let fd = inherited_fd.as_raw_fd();
    // Only async-signal-safe work is allowed between fork and exec. Command
    // handles exec failures and reaps a child whose exec did not succeed.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let (started_tx, started_rx) = mpsc::sync_channel(1);
    thread::Builder::new().spawn(move || {
        let child = command.spawn();
        // The child owns its inherited copy after exec. Keeping the parent's
        // endpoint here would prevent EOF on a failed companion handshake.
        drop(inherited_fd);
        match child {
            Ok(mut child) => {
                let _ = started_tx.send(Ok(child.id()));
                loop {
                    match child.wait() {
                        Ok(_) => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            log::warn!("Failed to wait for companion {}: {}", child.id(), e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                let _ = started_tx.send(Err(e));
            }
        }
    })?;
    started_rx
        .recv()
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "companion spawn worker exited"))?
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn assert_reaped(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::path::Path::new(&format!("/proc/{pid}")).exists() {
            assert!(Instant::now() < deadline, "child {pid} was not reaped");
            thread::sleep(Duration::from_millis(5));
        }
        let result = unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) };
        assert_eq!(result, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn reaps_success_failure_and_signal_without_stealing_other_children() {
        let mut unrelated = Command::new("/bin/sh")
            .args(["-c", "exit 42"])
            .spawn()
            .unwrap();
        let mut children = Vec::new();
        for script in ["exit 0", "exit 1", "kill -TERM $$"]
            .into_iter()
            .cycle()
            .take(48)
        {
            let (peer, socket) = UnixStream::pair().unwrap();
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]);
            children.push(spawn_and_reap(command, socket.into()).unwrap());
            drop(peer);
        }
        assert_eq!(unrelated.wait().unwrap().code(), Some(42));
        for pid in children {
            assert_reaped(pid);
        }
    }

    #[test]
    fn exec_failure_is_reported_and_closes_the_parent_endpoint() {
        let (mut peer, socket) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let command = Command::new("/no-such-neozygisk-test-executable");
        let error = spawn_and_reap(command, socket.into()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
    }

    #[test]
    fn waiter_does_not_keep_companion_socket_open_after_exit() {
        let (mut peer, socket) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        let pid = spawn_and_reap(command, socket.into()).unwrap();
        assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
        assert_reaped(pid);
    }

    #[test]
    fn companion_inherits_socket_and_is_reaped_when_restart_closes_peer() {
        let (mut peer, socket) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--ignored", "--exact", "child::tests::socket_child"])
            .env(
                "NEOZYGISK_TEST_COMPANION_FD",
                socket.as_raw_fd().to_string(),
            )
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let pid = spawn_and_reap(command, socket.into()).unwrap();
        let mut ready = [0u8; 5];
        peer.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"ready");
        drop(peer);
        assert_reaped(pid);
    }

    #[test]
    #[ignore = "companion subprocess fixture, launched by the socket inheritance test"]
    fn socket_child() {
        let fd = std::env::var("NEOZYGISK_TEST_COMPANION_FD")
            .unwrap()
            .parse()
            .unwrap();
        let mut socket = unsafe { UnixStream::from_raw_fd(fd) };
        socket.write_all(b"ready").unwrap();
        assert_eq!(socket.read(&mut [0u8; 1]).unwrap(), 0);
    }
}
