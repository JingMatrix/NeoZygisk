MODDIR=${0%/*}/..

export TMP_PATH=@WORK_DIRECTORY@

exec $MODDIR/bin/zygisk-ptrace64 ctl $*
