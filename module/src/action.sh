#!/system/bin/sh

TRACER=${0%/*}/bin/zygisk-ptrace64
[ -f "$TRACER" ] || TRACER=${0%/*}/bin/zygisk-ptrace32
exec "$TRACER" status
