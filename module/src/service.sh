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
if ! pidof zygisk-ptrace64 >/dev/null && ! pidof zygisk-ptrace32 >/dev/null; then
  log -p w -t "zygisk-sh" "monitor not running, starting it from service.sh"
  sh "$MODDIR/post-fs-data.sh" </dev/null >/dev/null 2>&1
  sleep 1
  setprop ctl.restart zygote
fi
