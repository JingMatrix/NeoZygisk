#!/system/bin/sh

DEBUG=@DEBUG@

MODDIR=${0%/*}
if [ "$ZYGISK_ENABLED" ]; then
	exit 0
fi

cd "$MODDIR"

# Magisk only runs the service.sh of modules it mounts itself, so fan out to the Zygisk
# modules on its behalf. Late-start injection is not handled here: it belongs to
# post-mount.sh, which runs at the one point where the module set is final and mounted.
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
