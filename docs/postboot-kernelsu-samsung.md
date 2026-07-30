# Post-boot KernelSU sessions on Samsung

This note records a working NeoZygisk lifecycle for a KernelSU session that is acquired after Android has already booted. It is based on a bootloader-locked Samsung device where KernelSU is late-loaded by an exploit rather than started during the normal boot sequence.

The tested path does **not** inject the already-running zygote. It attaches one monitor to init and waits for a user-initiated KernelSU Manager Soft Reboot to create a new zygote under that monitor.

## Tested environment

```text
Device: Samsung Galaxy S25 Ultra SM-S938B
Build: BP4A.251205.006.S938BXXSBCZG3
Kernel: 6.6.98-android15-8-pd6ff1cd-abogkiS938BXXSBCZG3-4k
ABI: arm64-v8a
Bootloader: locked
Root: temporary KernelSU loaded after boot by Root My Galaxy
```

## Constraints found on the device

### The normal module boot hooks have already passed

KernelSU becomes active after Android, zygote and system_server are already running. A provider that only relies on the normal early module lifecycle therefore starts too late to observe the current zygote creation.

### Samsung DEFEX rejected the persistent module path

The zygote could not open the injection library from the persistent module directory under `/data/adb`. Staging the live library and sockets under the kernel-backed tmpfs path below passed the device's DEFEX path check:

```text
/dev/.neozygisk
```

The persistent module remains under `/data/adb/modules/zygisksu`; only the live runtime is staged under `/dev`.

### A targeted zygote restart was not safe

A test using `setprop ctl.restart zygote` caused Samsung's **Device Services Uninstalled** failure state. Android did not recover normally and a full device reboot was required.

For that reason the working path contains no targeted zygote restart, `ctl.start` recovery, process kill, device reboot or module-initiated KernelSU Soft Reboot.

## Working lifecycle

1. Late-load KernelSU and verify its control channel.
2. Stage the NeoZygisk runtime atomically under `/dev/.neozygisk`.
3. Start exactly one monitor and attach it to init.
4. Leave the current zygote untouched.
5. Let the user initiate **Soft Reboot** from KernelSU Manager once.
6. Verify the new zygote, daemon, sockets and mapped library after Android returns.

The monitor bootstrap is idempotent. Reuse is allowed only when there is exactly one monitor, init points to it, the live monitor executable is not marked `(deleted)`, and the running native generation matches the installed files.

## Update-generation guards

A provider update must not be activated by Soft Reboot while an older monitor is still alive in the same kernel boot.

This failure was reproduced during testing: a newer package replaced the module files while the previous monitor and `/dev` runtime remained active. The following Soft Reboot left the runtime in this state:

```text
monitor: stopped(zygote crashed)
zygote64: unknown
daemon64: running
```

The daemon remaining alive was not proof of a healthy injection. The verifier also had to be changed because its old `status` command printed a stored success result instead of checking the live state.

The safe update rule is:

1. install the provider update without using Soft Reboot;
2. perform a full device reboot;
3. late-load KernelSU again;
4. use KernelSU Manager Soft Reboot once;
5. run live verification.

The same full-reboot requirement applies after a deleted monitor executable, native-generation mismatch, recorded zygote crash or explicit `FULL_REBOOT_REQUIRED` result.

## Live health checks

The tested implementation requires all of the following before reporting success:

- exactly one monitor attached to init;
- monitor executable not marked `(deleted)`;
- SHA-256 of the live monitor executable matching the installed tracer;
- SHA-256 of the staged runtime library matching the installed library;
- no `stopped(zygote crashed)` runtime state;
- injected `zygote64`;
- running `zygiskd64`;
- responsive Android activity service;
- `cp64.sock` present;
- `/dev/.neozygisk/lib64/libzygisk.so` mapped in the live zygote.

`status` performs a fresh live check. It does not treat a previous success file as the current state.

## Hardware result

After a full reboot, the normal exploit, the guarded provider package and one user-initiated KernelSU Manager Soft Reboot, live verification returned:

```text
PHASE=3.2
RESULT=INJECTION_VERIFIED
DETAIL=healthy same-generation NeoZygisk state verified
WORK=/dev/.neozygisk
RESTART_TRIGGERED_BY_MODULE=0
TARGETED_ZYGOTE_RESTART_USED=0
GLOBAL_SOFT_REBOOT_USED_BY_MODULE=0
MANUAL_KERNELSU_SOFT_REBOOT_REQUIRED=0
FULL_REBOOT_REQUIRED=0
BOOTSTRAP_RESULT=HEALTHY
MONITOR_HEALTHY=1
MONITOR_PID=13835
INIT_TRACER=13835
MONITOR_EXE_DELETED=0
MONITOR_BINARY_MATCH=1
RUNTIME_LIBRARY_MATCH=1
RUNTIME_MONITOR_CRASHED=0
ZYGOTE_PID=24563
SYSTEM_SERVER_PID=24853
DAEMON_PID=24565
RUNTIME_PROP_INJECTED=1
RUNTIME_PROP_DAEMON_RUNNING=1
ACTIVITY_READY=1
CP64_SOCKET_READY=1
LIBRARY_MAPPED_IN_ZYGOTE=1
```

The runtime reported one tracing monitor, an injected `zygote64`, a running daemon and two loaded modules:

```text
Root: KernelSU
Modules (2):
  zygisk-assistant
  zygisk_lsposed
```

Both Zygisk Assistant and LSPosed were functional after the Soft Reboot.

## Relationship to standalone late injection

This lifecycle is different from injecting into an already-running zygote. It deliberately leaves the current zygote untouched and relies on the next zygote creation produced by the external KernelSU module lifecycle.

That makes it narrower than a general standalone injection mode, but it avoids remote injection into a live Android zygote on the tested production firmware. The result may still be useful as hardware evidence for late-loaded root environments and as a reference for update-generation safety.

A complete reference implementation and release history are available in the `igorcv88/NeoZygisk-PostBoot` fork. The upstreamable parts are the lifecycle, runtime-path option and fail-closed generation checks; fork branding and release automation are not required by the design.
