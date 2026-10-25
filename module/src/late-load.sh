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
# Under ksud or apd this stage only bootstraps. Modules have been promoted and their
# sepolicy rules loaded by the time it runs, but the metamodule has not mounted anything
# yet, so the rearm waits for post-mount.sh, and the manager runs the later stages itself.
# With no root framework there is nothing to mount and nobody to run them, so this script
# is the whole sequence and takes them on.
#
# Processes that were already running stay uninjected: they were forked from a zygote with
# no hooks, and nothing can retrofit them. Apps started after the attach are injected
# normally, which is the trade this mode makes to avoid disturbing a running system. A
# failed attach is not escalated either -- the target is resumed rather than killed, and
# the status file simply never shows it as injected.
#
# ksud loads each module's sepolicy.rule during late load, so a temp root needs no
# permissive policy and nothing here touches SELinux. A userdebug build cannot load custom
# policy at all, so there `setenforce 0` is left to whoever triggers the injection.

MODDIR=${0%/*}

log -p i -t "zygisk-sh" "late-load: bootstrapping NeoZygisk on a running system"

# Shares the bootstrap with the normal path. post-fs-data.sh never recreates the work
# directory, so a monitor left over from a previous root session keeps its control socket
# and injected processes keep the library they already mapped. Nothing is left holding this
# script's stdout: the monitor it backgrounds would otherwise keep a calling shell waiting
# on it for the rest of the session.
. "$MODDIR/post-fs-data.sh" </dev/null >/dev/null 2>&1

# ksud exports KSU and apd exports APATCH to every stage script they run, and both go on to
# run post-mount.sh and each module's service.sh themselves. Neither being set means this
# script was started from a root shell on a build with no root framework, such as AOSP
# userdebug, where nothing else ever will.
if [ "$KSU" ] || [ "$APATCH" ]; then
  exit 0
fi

log -p i -t "zygisk-sh" "late-load: no root framework, running the remaining stages"

# In the order a manager would: the rearm first, so the injection is armed before module
# daemons start looking for it, then the service stage that starts them.
sh "$MODDIR/post-mount.sh"
sh "$MODDIR/service.sh"
