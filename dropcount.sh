#!/bin/bash
function PRINTCNT() {
if [ "$KEY" != "" ]; then
	if [ "$KEY" = "0x00000000" ]; then
		echo "Invalid packet length: $CNT"
	elif [ "$KEY" = "0x00000001" ]; then
		echo "Invalid VLAN tag: $CNT"
	elif [ "$KEY" = "0x00000002" ]; then
		echo "Invalid/rejected IHL IPv4 field: $CNT"
	elif [ "$KEY" = "0x00000003" ]; then
		echo "Rejected IPv6 fragments: $CNT"
	else
		echo "$KEY: $CNT"
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
					KEY=$(echo "$LINE" | awk '{ print "0x" $4 $3 $2 $1 }')
					;;
			esac
		done
		PRINTCNT
	}
done
