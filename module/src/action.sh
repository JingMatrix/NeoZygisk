printf "Status of ShamrockZygisk\n\n"

cat @WORK_DIRECTORY@/module.prop

if [[ -z "$MMRL" ]] && ([[ -n "$KSU" ]] || [[ -n "$APATCH" ]]); then
	# Avoid instant exit on KernelSU or APatch
	sleep 5
fi
