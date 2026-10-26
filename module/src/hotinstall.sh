#!/system/bin/sh

# A shim: the rules live in the tracer, which a manager cannot call directly because it
# invokes boot stages by file name. One tracer is installed, for the ABI it injects.
TRACER=${0%/*}/bin/zygisk-ptrace64
[ -f "$TRACER" ] || TRACER=${0%/*}/bin/zygisk-ptrace32
exec "$TRACER" stage hotinstall
