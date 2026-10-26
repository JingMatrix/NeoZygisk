#!/system/bin/sh

# A shim: every rule this stage follows lives in the tracer, which the managers cannot call
# directly because they invoke boot stages by file name. One tracer is installed, the 64-bit
# one on a 64-bit device, and it injects that ABI's zygote only.
TRACER=${0%/*}/bin/zygisk-ptrace64
[ -f "$TRACER" ] || TRACER=${0%/*}/bin/zygisk-ptrace32
exec "$TRACER" stage service
