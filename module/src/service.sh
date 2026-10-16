#!/system/bin/sh

DEBUG=@DEBUG@

MODDIR=${0%/*}
if [ "$ZYGISK_ENABLED" ]; then
  exit 0
fi

cd "$MODDIR"

if [ "$(which magisk)" ]; then
  for file in ../*; do
    if [ -d "$file" ] && [ -d "$file/zygisk" ] && ! [ -f "$file/disable" ]; then
      if [ -f "$file/service.sh" ]; then
        cd "$file"
        log -p i -t "zygisk-sh" "Manually trigger service.sh for $file"
        sh "$(realpath ./service.sh)" &
        cd "$MODDIR"
      fi
    fi
  done
fi

# Late-load roots (e.g. KernelSU temp root) only run service.sh, so post-fs-data.sh
# never started the monitor. Start it now and restart zygote so it gets injected.
#
# A daemon that survived from an earlier state (previous temp root, module flash,
# failed reload) keeps its ONE-TIME module scan forever: zygote restarts alone then
# inject nothing, and every zygisk module silently stops working. Detect that state
# by whether the running zygote actually has the zygisk lib mapped: if not, reset
# to a fresh monitor+daemon pair (module list gets re-scanned) and restart zygote.
# On normal boots zygote is already injected and this is a no-op.
need_restart=0
if ! pidof zygisk-ptrace64 >/dev/null && ! pidof zygisk-ptrace32 >/dev/null; then
  need_restart=1
fi
for zpid in $(pidof zygote64 zygote32 2>/dev/null); do
  if ! grep -q "neozygisk/lib64/libzygisk" /proc/$zpid/maps 2>/dev/null; then
    need_restart=1
    log -p w -t "zygisk-sh" "zygote not injected - resetting stale zygisk monitor/daemon"
    kill $(pidof zygiskd64 zygiskd32 zygisk-ptrace64 zygisk-ptrace32) 2>/dev/null
    sleep 1
    break
  fi
done
if [ "$need_restart" != 0 ]; then
  sh "$MODDIR/post-fs-data.sh" </dev/null >/dev/null 2>&1
  sleep 1
  setprop ctl.restart zygote
fi
