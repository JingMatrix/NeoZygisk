printf "Status of NeoZygisk\n\n"

cat @WORK_DIRECTORY@/module.prop

if [[ -z $MMRL ]] && ([[ -n $KSU ]] || [[ -n $APATCH ]]); then
	# Avoid instant exit on KSU or APATCH
	sleep 10
fi
