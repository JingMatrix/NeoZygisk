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


# Sync description from runtime prop
(
  # Wait for runtime prop
  RUNTIME_PROP="/data/adb/neozygisk/module.prop"
  count=0
  while [ ! -f "$RUNTIME_PROP" ] && [ $count -lt 20 ]; do
    sleep 0.5
    count=$((count + 1))
  done
  
  sleep 2

  if [ -f "$RUNTIME_PROP" ]; then
    # Extract description from runtime prop
    DESC=$(grep "^description=" "$RUNTIME_PROP")
    if [ ! -z "$DESC" ]; then
       # Replace description in installed prop
       sed -i "s|^description=.*|$DESC|" "$MODDIR/module.prop"
    fi
  fi
) &
