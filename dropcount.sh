#!/bin/bash
function PRINTCNT() {
if [ "$KEY" != "" ]; then
	if [ "$KEY" = "0" ]; then
		echo -e "$CNT:\tInvalid packet length"
	elif [ "$KEY" = "1" ]; then
		echo -e "$CNT:\tInvalid VLAN tag"
	elif [ "$KEY" = "2" ]; then
		echo -e "$CNT:\tInvalid/rejected IHL IPv4 field"
	elif [ "$KEY" = "3" ]; then
		echo -e "$CNT:\tRejected IPv6 fragments"
	else
		echo -en "$CNT:\t"
		cat "$(dirname ${BASH_SOURCE[0]})/installed-rules.txt" | head -n $(( $KEY - 3 )) | tail -n1
	fi
fi
CNT=0
}
bpftool map show | grep drop_cnt_map | awk '{ print $1 }' | tr -d ':' | while read IF; do
	bpftool map dump id "$IF" | {
		KEY=""
		CNT=0
		while read LINE; do
			case "$LINE" in
				"key:") ;;
				"value"*)
					CNT=$(( $CNT + $(echo "$LINE" | awk '{ print "0x" $11 $10 $9 $8 $7 $6 $5 $4 }') ))
					;;
				"Found "*) ;;
				*)
					PRINTCNT
					KEY=$((16#$(echo "$LINE" | awk '{ print $4 $3 $2 $1 }')))
					;;
			esac
		done
		PRINTCNT
	}
done
