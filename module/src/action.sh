
printf "Status of NeoZygisk\n\n"

cat @WORK_DIRECTORY@/module.prop

if [ -z $MMRL ] && { [ $KSU = true ] || [ $APATCH = true ]; }; then
	# Avoid instant exit on KSU or APATCH
	sleep 10
fi
