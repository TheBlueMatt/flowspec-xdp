#!/bin/bash
function PRINTCNT() {
if [ "$1" != "" ]; then
	if [ "$1" = "0" ]; then
		echo -e "$2\t$3\tInvalid packet length"
	elif [ "$1" = "1" ]; then
		echo -e "$2\t$3\tInvalid VLAN tag"
	elif [ "$1" = "2" ]; then
		echo -e "$2\t$3\tInvalid/rejected IHL IPv4 field"
	elif [ "$1" = "3" ]; then
		echo -e "$2\t$3\tRejected IPv6 fragments"
	else
		echo -en "$2\t$3\t"
		cat "$(dirname ${BASH_SOURCE[0]})/installed-rules.txt" | head -n $(( $1 - 3 )) | tail -n1
	fi
fi
CNT=0
}
MAP_CONTENTS="$(bpftool map show | grep drop_cnt_map | awk '{ print $1 }' | tr -d ':' | while read IF; do
	bpftool map dump id "$IF" | grep "bytes\|packets\|key" | grep -v '\(bytes\|packets\)": 0\(,\)*$'
done)"
echo "$MAP_CONTENTS" | {
	declare -a BYTES
	declare -a PACKETS
	KEY=""
	while read LINE; do
		case "$LINE" in
			*"key"*)
				KEY=$(echo "$LINE" | awk '{ print $2 }' | tr -d ',')
				if [ "${BYTES["${KEY}"]}" = "" ]; then
					BYTES["${KEY}"]=0
					PACKETS["${KEY}"]=0
				fi
				;;
			*"bytes"*)
				BYTES["${KEY}"]=$(( ${BYTES["$KEY"]} + $(echo "$LINE" | awk '{ print $2 }' | tr -d ',') ))
				;;
			*"packets"*)
				PACKETS["$KEY"]=$(( ${PACKETS["$KEY"]} + $(echo "$LINE" | awk '{ print $2 }' | tr -d ',') ))
				;;
		esac
	done
	echo -e "pkts\tKBytes\tRule"
	for C in "${!BYTES[@]}"; do
		PRINTCNT $C "${PACKETS["$C"]}" "$(( ${BYTES["$C"]} / 1000 ))"
	done
}
