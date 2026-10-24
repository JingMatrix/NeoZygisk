#!/system/bin/sh

MODDIR=${0%/*}
if [ "$ZYGISK_ENABLED" ]; then
	exit 0
fi

cd "$MODDIR"

if [ "$(which magisk)" ]; then
	for file in ../*; do
		if [ -d "$file" ] && [ -d "$file/zygisk" ] && ! [ -f "$file/disable" ]; then
			if [ -f "$file/post-fs-data.sh" ]; then
				cd "$file"
				log -p i -t "zygisk-sh" "Manually trigger post-fs-data.sh for $file"
				sh "$(realpath ./post-fs-data.sh)"
				cd "$MODDIR"
			fi
		fi
	done
fi

create_sys_perm() {
	mkdir -p $1
	chmod 555 $1
	chcon u:object_r:system_file:s0 $1
	chown system:system $1
}

TMP_PATH=@WORK_DIRECTORY@

if [ -d $TMP_PATH ]; then
	rm -rf $TMP_PATH
fi

create_sys_perm $TMP_PATH

if [ -f $MODDIR/lib64/libzygisk.so ]; then
	create_sys_perm $TMP_PATH/lib64
	cp $MODDIR/lib64/libzygisk.so $TMP_PATH/lib64/libzygisk.so
	chcon u:object_r:system_file:s0 $TMP_PATH/lib64/libzygisk.so
	chown system:system $TMP_PATH/lib64/libzygisk.so
fi

if [ -f $MODDIR/lib/libzygisk.so ]; then
	create_sys_perm $TMP_PATH/lib
	cp $MODDIR/lib/libzygisk.so $TMP_PATH/lib/libzygisk.so
	chcon u:object_r:system_file:s0 $TMP_PATH/lib/libzygisk.so
	chown system:system $TMP_PATH/lib/libzygisk.so
fi

[ "$DEBUG" = true ] && export RUST_BACKTRACE=1

# app_process names itself "zygote64" when built LP64 and "zygote" otherwise, so the
# 32-bit branch only applies to 32-bit-only devices. On a 64/32 device the secondary
# 32-bit zygote is not covered by the standalone path; only the monitor path sees it.
if [ -f "$MODDIR/bin/zygisk-ptrace64" ]; then
	TRACER="$MODDIR/bin/zygisk-ptrace64"
	ZYGOTE="zygote64"
elif [ -f "$MODDIR/bin/zygisk-ptrace32" ]; then
	TRACER="$MODDIR/bin/zygisk-ptrace32"
	ZYGOTE="zygote"
else
	log -p e -t "zygisk-sh" "No tracer binary found in $MODDIR/bin"
	exit 1
fi

if [ -z "$(pidof system_server)" ]; then
	# Normal boot: supervise zygote from the start and inject as it spawns.
	"$TRACER" monitor &
else
	# Late injection: the system is already up, so attach to the running zygote.
	ZYGOTE_PID="$(pidof "$ZYGOTE")"
	if [ -z "$ZYGOTE_PID" ]; then
		log -p e -t "zygisk-sh" "Cannot inject: no running $ZYGOTE found"
		exit 1
	fi
	"$TRACER" trace "$ZYGOTE_PID" --standalone &
fi
