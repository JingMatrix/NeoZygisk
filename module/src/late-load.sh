#!/system/bin/sh

# Arms NeoZygisk on a system that is already up, by hand or from `ksud late-load`. Run it
# with --help for the options; everything it does lives in the tracer.
TRACER=${0%/*}/bin/zygisk-ptrace64
[ -f "$TRACER" ] || TRACER=${0%/*}/bin/zygisk-ptrace32
exec "$TRACER" stage late-load "$@"
