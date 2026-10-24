#!/system/bin/sh

# Early-boot bootstrap: stage the work directory and start the monitor, which then waits
# for init to fork zygote and injects it as it spawns.
#
# This script is also the shared bootstrap for the late-load path: late-load.sh sources it
# on a system that is already up. It must therefore be safe to run while a previous monitor
# and its injected processes are alive, which rules out recreating the work directory from
# scratch -- the live control socket and the mapped libzygisk.so both live in it.

DEBUG=@DEBUG@

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

TMP_PATH=@WORK_DIRECTORY@

# The work directory has to be traversable by uid 1000: a late-injected system_server
# dlopens the library and connects to the control socket in its own context, and that is a
# DAC check which no SELinux setting relaxes. Hence system:system ownership and a mode that
# grants search to all. Root still writes here through CAP_DAC_OVERRIDE.
create_sys_perm() {
	mkdir -p "$1"
	chmod 555 "$1"
	chcon u:object_r:system_file:s0 "$1"
	chown system:system "$1"
}

# Install a library without disturbing the copy a running process may already have mapped.
# Writing in place would either fail with ETXTBSY or mutate a mapped file; renaming over it
# publishes the new inode and leaves existing mappings on the old one, which is released
# when the last of those processes exits.
install_lib() {
	src="$1"
	dst="$2"
	[ -f "$src" ] || return 0
	create_sys_perm "${dst%/*}"
	cp -f "$src" "$dst.new" || return 1
	chmod 644 "$dst.new"
	chcon u:object_r:system_file:s0 "$dst.new"
	chown system:system "$dst.new"
	mv -f "$dst.new" "$dst"
}

create_sys_perm "$TMP_PATH"
install_lib "$MODDIR/lib64/libzygisk.so" "$TMP_PATH/lib64/libzygisk.so"
install_lib "$MODDIR/lib/libzygisk.so" "$TMP_PATH/lib/libzygisk.so"

[ "$DEBUG" = true ] && export RUST_BACKTRACE=1

if [ -f "$MODDIR/bin/zygisk-ptrace64" ]; then
	TRACER="$MODDIR/bin/zygisk-ptrace64"
elif [ -f "$MODDIR/bin/zygisk-ptrace32" ]; then
	TRACER="$MODDIR/bin/zygisk-ptrace32"
else
	log -p e -t "zygisk-sh" "No tracer binary found in $MODDIR/bin"
	exit 1
fi

# Unconditional: the monitor enforces the single-owner invariant itself and a redundant
# one exits immediately, so neither this script nor a soft reboot has to probe for it.
"$TRACER" monitor &
