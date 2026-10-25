#!/system/bin/sh

DEBUG=@DEBUG@

MODDIR=${0%/*}
if [ "$ZYGISK_ENABLED" ]; then
  exit 0
fi

cd "$MODDIR"

# ksud and apd run every enabled module's service.sh themselves, and announce themselves
# through KSU and APATCH. Magisk runs only those of the modules it mounts, which leaves out
# the Zygisk-only ones, and a build with no root framework runs none at all, so fan out
# whenever nothing else will. Late-start injection is not handled here: it belongs to
# post-mount.sh, which runs at the one point where the module set is final and mounted.
if [ -z "$KSU$APATCH" ]; then
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
