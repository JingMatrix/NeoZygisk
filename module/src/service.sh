#!/system/bin/sh

DEBUG=@DEBUG@

MODDIR="$(dirname "$(realpath "$0")")"
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

if [ ! -z $(pidof system_server) ]; then
	log -p i -t "zygisk-sh" "Maually inject into system_server $(pidof system_server)"
	./bin/zygisk-ptrace64 trace $(pidof system_server) --system_server
fi
