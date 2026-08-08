#!/system/bin/sh

DEBUG=@DEBUG@

MODDIR="$(dirname "$(realpath "$0")")"
if [ "$ZYGISK_ENABLED" ]; then
	exit 0
fi

cd "$MODDIR"

system_server_pid=$(pidof system_server)

if [ "$(which magisk)" ]; then
	for file in ../*; do
		if [ -d "$file" ] && [ -d "$file/zygisk" ] && ! [ -f "$file/disable" ]; then
			if [ -f "$file/service.sh" ]; then
				cd "$file"
				log -p i -t "zygisk-sh" "Manually trigger service.sh for $file"
				if [ -z "$system_server_pid" ]; then
					sh "$(realpath ./service.sh)" &
				else
					sh "$(realpath ./service.sh)" --late-inject &
				fi
				cd "$MODDIR"
			fi
		fi
	done
fi

if [ -n "$system_server_pid" ]; then
	if [ -f "$MODDIR/bin/zygisk-ptrace64" ]; then
		TRACER="$MODDIR/bin/zygisk-ptrace64"
	elif [ -f "$MODDIR/bin/zygisk-ptrace32" ]; then
		TRACER="$MODDIR/bin/zygisk-ptrace32"
	else
		log -p e -t "zygisk-sh" "No tracer binary found in $MODDIR/bin"
		exit 1
	fi
	log -p i -t "zygisk-sh" "Manually inject into system_server $system_server_pid"
	"$TRACER" trace "$system_server_pid" --system_server
fi
