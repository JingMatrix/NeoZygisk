# Late Injection Mode

> Status: experimental. This mode is not part of a normal NeoZygisk release.
> It still requires a permissive SELinux policy to allow the control-socket
> connection (see [Requirements](#requirements)).

## Overview

NeoZygisk normally bootstraps from the early boot sequence: a `monitor` process is
started during the root solution's init phase and `ptrace`s zygote before it
specializes any app. This is impossible in environments where those early
init-phase hooks are unavailable (for example AOSP `userdebug` builds, or root
solutions with incomplete boot-stage support) — by the time the module's scripts
run, zygote and `system_server` are already alive and specialized.

Late injection covers that case by attaching to the already-running processes:

| Mode | Trace target | Purpose |
| --- | --- | --- |
| `--spawn` | a freshly restarted zygote | the normal boot-time path (used internally by `monitor`) |
| `--standalone` | a running `zygote64` / `zygote32` | inject after boot; also starts the daemon control socket |
| `--system_server` | a running `system_server` | drive a synthetic `server_specialize` for the already-started process |

## How it works

* Attach to a running process. `PTRACE_SEIZE` does not stop a running target, so the
  tracer issues an explicit `PTRACE_INTERRUPT`, and omits `PTRACE_O_EXITKILL` so the
  target is never killed if the tracer exits.
* Resume cleanly. A process interrupted inside a blocking syscall would otherwise hit
  the kernel's syscall-restart path; the tracer clears the syscall state in the
  working registers before the remote call and restores the original registers on
  detach.
* system_server specialization. Because `system_server` already finished its real
  specialization, the injected library reconstructs the process state (UID/GID,
  capabilities, a temporary `JNIEnv`) and fires the Zygisk `server_specialize`
  lifecycle manually, tagging it with `RuntimeFlags::LATE_INJECT`.

## Requirements

### Permissive SELinux

NeoZygisk depends on a set of custom SELinux rules shipped in
`module/src/sepolicy.rule` — most importantly executable-memory access for the
injected hook code (`allow zygote zygote process execmem`,
`allow system_server system_server process execmem`) and access to the control
socket (`allow zygote zygisk_file sock_file { read write }`), alongside several file
and namespace accesses. On a real Magisk/KernelSU/APatch device the root solution
loads these rules at boot.

The central obstacle to late injection is that these environments provide no
mechanism to load custom sepolicy rules. Since the rules NeoZygisk requires cannot be
applied, it cannot run under an enforcing policy, and the device must be set
permissive (`setenforce 0`).

Relocating the runtime directory under `/data/system` is an attempt to shrink that
gap: living in an already-accessible domain (`system_data_file`) removes the need for
the custom file-access rules a `/data/adb` location would otherwise require. It
cannot, however, grant `execmem` or the socket-connection rule, so it does not lift
the permissive requirement. In that sense the relocation turns out to be futile — it
only narrows the missing rule set and documents the attempt; permissive SELinux is
still mandatory. The security consequence of running without that gate is covered in
[Security: socket peer admission](#security-socket-peer-admission).

### An emulated Magisk environment

NeoZygisk's daemon identifies the active root solution by invoking the `magisk`
binary and querying its database (`zygiskd/src/root_impl/magisk.rs`), and module
scripts routinely call other Magisk-provided utilities. None of these exist on a bare
AOSP build, so they must be emulated with shims placed on `PATH`. Without the `magisk`
shim and database the daemon recognizes no root solution and process flags are empty;
without `unshare`, mount-namespace-sensitive modules — Vector in particular — will not
run correctly.

A minimal `magisk` shim, placed somewhere on `PATH` so `which magisk` resolves:

```sh
#!/system/bin/sh
case "$1" in
  -v)       echo "30.0:MAGISK" ;;               # variant string, read by `magisk -v`
  -V)       echo "30000" ;;                     # version code, must be >= MIN_MAGISK_VERSION
  --sqlite) sqlite3 /data/adb/magisk.db "$2" ;; # database queries
  *)        exit 1 ;;
esac
```

A crafted `/data/adb/magisk.db` providing the tables the daemon reads:

```sql
CREATE TABLE IF NOT EXISTS policies (uid INT, policy INT, until INT, logging INT, notification INT, PRIMARY KEY(uid));
CREATE TABLE IF NOT EXISTS denylist (package_name TEXT, process TEXT, PRIMARY KEY(package_name, process));
CREATE TABLE IF NOT EXISTS settings (key TEXT, value INT, PRIMARY KEY(key));
CREATE TABLE IF NOT EXISTS strings  (key TEXT, value TEXT, PRIMARY KEY(key));

-- Grant root to a uid (policy 2 == ALLOW), read by uid_granted_root:
INSERT OR REPLACE INTO policies (uid, policy, until, logging, notification) VALUES (10234, 2, 0, 1, 1);

-- Identify the manager package, read by uid_is_manager via the `requester` key:
INSERT OR REPLACE INTO strings (key, value) VALUES ('requester', 'com.example.manager');
```

A `resetprop` shim, mapping Magisk's property tool onto the stock `setprop`/`getprop`
(module scripts use it to set or clear system properties):

```sh
#!/system/bin/sh
delete=0; prop=""; value=""
while [ "$1" ]; do
  case "$1" in
    --delete) delete=1 ;;
    -*)       ;;                                    # ignore -p/-n and friends
    *)        [ -z "$prop" ] && prop="$1" || value="$1" ;;
  esac
  shift
done
[ -z "$prop" ] && exit 0
[ "$delete" = 1 ] && exec /system/bin/setprop "$prop" "" \
                  || exec /system/bin/setprop "$prop" "$value"
```

An `unshare` shim. Magisk ships a GNU-style `unshare` that understands
`--propagation slave`, which toybox's `unshare` does not; the shim translates it into
an `rslave` remount. This is required to run Vector correctly:

```sh
#!/system/bin/sh
args=""; slave=0
while [ "$1" ]; do
  case "$1" in
    --propagation)              shift; [ "$1" = slave ] && slave=1 ;;
    -m|-i|-n|-p|-u|-U|-r|-f|-a|-C) args="$args $1" ;;
    *)                          break ;;            # remainder is the command to run
  esac
  shift
done
if [ "$slave" = 1 ]; then
  exec /system/bin/unshare $args /system/bin/sh -c 'mount -o rslave none /; exec "$@"' -- "$@"
else
  exec /system/bin/unshare $args "$@"
fi
```

## Security: socket peer admission

On an enforcing device the control socket is restricted to the `zygote` domain by
`sepolicy.rule`, so the connecting process is trusted by construction. Late injection
requires a permissive policy and a world-accessible (`0777`) socket, which removes that
gate, so the daemon authenticates peers itself.

Every connection the daemon legitimately accepts is opened while the caller is still
root or system at `connect()` time: zygote (uid 0) during injection and the whole
pre-specialization window — module FDs, mount namespaces and the companion *request*
are all obtained there — system_server (uid 1000) on the late path, and the root tracer
(uid 0). The loader makes no daemon connection after a process drops to its app uid, and
the app↔companion channel is a handed-off descriptor that never reconnects to the
daemon. The daemon therefore admits only peers the kernel reports via `SO_PEERCRED` as
uid 0 or 1000, and rejects everything else with a warning.

Residual risk: a permissive policy also stops the kernel enforcing SELinux domain
transitions, so a process that can already run as root or system may still connect and
supply unverified request data — for example a self-declared app `uid` in
`GetProcessFlags`, or an out-of-range module `index` in `RequestCompanionSocket` /
`GetModuleDir` (which is not bounds-checked). This requires the caller to already hold
root or system — inside the trust boundary — so it is bounded, but it cannot be closed
while the policy is permissive.

Note for module authors: because the gate admits only root/system peers, a module must
obtain its companion socket and module directory during `preAppSpecialize` (while still
privileged), not from `postAppSpecialize` (app uid). This matches the connection model
documented in `zygiskd/src/main.rs`.

By the way — a companion fd kept open in a target app is also reachable by that app's
own code. The module and the app share one process and fd table with no isolation
between them, so the app can enumerate `/proc/self/fd`, recognize the socket (its peer
is root via `SO_PEERCRED`), and speak the companion protocol itself. A companion is
therefore root code serving a possibly hostile caller: validate every request, expose
the narrowest operations you can, and close the fd as soon as the work is done rather
than parking a root channel in an untrusted process. The fd survives specialization
only because the module exempts it from `sanitize_fds()` (`api->exemptFd`), so keeping
it open is a deliberate choice with a deliberate cost.

## Triggering late injection

A minimal post-boot trigger, run from a root shell once the device is fully booted.
The tracer binary lives at `<module>/bin/zygisk-ptrace64` (or `…32`).

```sh
# 1. Allow the control-socket connection, and put the shims (magisk, resetprop,
#    unshare) on PATH so the daemon detects the emulated root solution and module
#    scripts find the Magisk utilities they expect.
setenforce 0
export PATH=/path/to/shims:$PATH

# 2. Inject the running zygote. In --standalone the tracer also forks the
#    daemon and starts listening on the control socket before injecting.
./bin/zygisk-ptrace64 trace "$(pidof zygote64)" --standalone &

# 3. Inject the already-running system_server.
./bin/zygisk-ptrace64 trace "$(pidof system_server)" --system_server
```

## Module contract

A module can detect that it was started this way and adjust its bootstrap. The flag
is defined in `loader/src/injector/system_server.hpp`:

```cpp
enum RuntimeFlags : uint32_t {
    // Safely out of the way of AOSP's own runtime flag bits.
    LATE_INJECT = 1 << 30,
};
```

```cpp
// Native Zygisk module
void onServerSpecialize(ServerSpecializeArgs *args) override {
    const bool late_inject = args->runtime_flags & RuntimeFlags::LATE_INJECT;
    if (late_inject) {
        // The framework is already up: bootstrap manually (resolve the live
        // ClassLoader, fire boot-completed callbacks, …) instead of relying on
        // the normal launch sequence.
    }
}
```

A reference module-side implementation lives in Vector (a refactored LSPosed):
<https://github.com/JingMatrix/Vector/pull/564#issue-4050922152>.

The Vector-side changes are neutral and have been merged. The NeoZygisk-side changes
remain a pull request, because there is no complete solution for the sepolicy
requirement and the unverified-input risks documented above are inherent to running
under a permissive policy.
