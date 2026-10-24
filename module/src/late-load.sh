#!/system/bin/sh

# KernelSU runs this instead of post-fs-data.sh when the kernel module was loaded into an
# already-running system (`ksud late-load`, the temp root that a full reboot discards).
#
# Late load covers every case where NeoZygisk is asked to arm itself after the window it
# normally relies on has passed: a temp root, and a build with no root solution at all,
# such as AOSP userdebug, where nothing runs at boot and the trigger is a root shell.
# Both arrive at the same state, zygote and system_server already running and specialized,
# so both go through one entry point, `zygisk-ptrace64 ctl rearm`. That asks the running
# monitor to start the daemon if it is gone, have it rebuild its module snapshot, then
# live-attach whichever of zygote and system_server are up without our hooks. It is
# idempotent and a no-op when nothing is running, so the same call serves a normal boot, a
# module refresh and a re-applied root session.
#
# Modules have been promoted and their sepolicy rules loaded by the time this stage runs,
# but the metamodule has not mounted anything yet and zygote has been running since the
# real boot. So this stage only bootstraps, and post-mount.sh sends the rearm once
# mounting has happened and there is a complete module set to inject.
#
# Processes that were already running stay uninjected: they were forked from a zygote with
# no hooks, and nothing can retrofit them. Apps started after the attach are injected
# normally, which is the trade this mode makes to avoid disturbing a running system. A
# failed attach is not escalated either -- the target is resumed rather than killed, and
# the failure is reported in the status file.
#
# ksud loads each module's sepolicy.rule during late load, so a temp root needs no
# permissive policy and nothing here touches SELinux. A userdebug build cannot load custom
# policy at all, so there `setenforce 0` is left to whoever triggers the injection.

MODDIR=${0%/*}

log -p i -t "zygisk-sh" "late-load: bootstrapping NeoZygisk on a running system"

# Shares the bootstrap with the normal path. post-fs-data.sh never recreates the work
# directory, so a monitor left over from a previous root session keeps its control socket
# and injected processes keep the library they already mapped.
. "$MODDIR/post-fs-data.sh"
