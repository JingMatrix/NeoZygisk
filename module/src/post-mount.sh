#!/system/bin/sh

# Runs after the metamodule has mounted the module set.
#
# This is where a boot arms a system that is already up. On a normal boot nothing is
# running yet, so it does nothing and the monitor injects zygote as init spawns it. When
# the system is already up -- a KernelSU late-load, a re-applied temp root -- this is the
# first moment at which the module set is both final and mounted, so it is where the
# running zygote and system_server get attached. A hot install re-runs no boot stage at
# all and is handled on its own by hotinstall.sh.

MODDIR=${0%/*}
if [ "$ZYGISK_ENABLED" ]; then
  exit 0
fi

if [ -f "$MODDIR/bin/zygisk-ptrace64" ]; then
  TRACER="$MODDIR/bin/zygisk-ptrace64"
elif [ -f "$MODDIR/bin/zygisk-ptrace32" ]; then
  TRACER="$MODDIR/bin/zygisk-ptrace32"
else
  log -p e -t "zygisk-sh" "No tracer binary found in $MODDIR/bin"
  exit 1
fi

# Gate on a live zygote so a normal boot stays silent. Both ABI names are checked because
# app_process calls itself "zygote64" when built LP64 and "zygote" otherwise. The monitor
# works out which ABIs to attach once it is asked.
if [ -z "$(pidof zygote64)$(pidof zygote)" ]; then
  exit 0
fi

log -p i -t "zygisk-sh" "post-mount: system already running, arming NeoZygisk"

# The monitor refreshes the daemon's module snapshot and attaches whatever is up and not
# yet injected. It is idempotent, so running it on every boot costs nothing.
if ! "$TRACER" ctl rearm; then
  log -p e -t "zygisk-sh" "post-mount: no monitor answered, injection not armed"
  exit 1
fi
