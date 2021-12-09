#!/bin/bash
MAP_CONTENTS="$(bpftool map show | grep drop_cnt_map | awk '{ print $1 }' | tr -d ':' | while read IF; do
	bpftool map dump id "$IF" | grep "bytes\|packets\|key" | grep -v '\(bytes\|packets\)": 0\(,\)*$' | tr -d ','
done)"
echo "$MAP_CONTENTS" | {
	declare -a BYTES
	declare -a PACKETS
	TOTAL_PACKETS=0
	TOTAL_BYTES=0
	KEY=""
	while read LINE; do
		case "$LINE" in
			*"key"*)
				KEY=${LINE:7}
				if [ "${BYTES["${KEY}"]}" = "" ]; then
					BYTES["${KEY}"]=0
					PACKETS["${KEY}"]=0
				fi
				;;
			*"bytes"*)
				BYTES["${KEY}"]=$(( ${BYTES["$KEY"]} + ${LINE:9} ))
				TOTAL_BYTES=$(( $TOTAL_BYTES + ${LINE:9} ))
				;;
			*"packets"*)
				PACKETS["$KEY"]=$(( ${PACKETS["$KEY"]} + ${LINE:11} ))
				TOTAL_PACKETS=$(( $TOTAL_PACKETS + ${LINE:11} ))
				;;
		esac
	done
	echo -e "pkts\tKBytes\tRule"
	echo -e "${TOTAL_PACKETS}\t$(( ${TOTAL_BYTES} / 1000 ))\tTotal"
	echo -e "${PACKETS[0]}\t$(( ${BYTES[0]} / 1000 ))\tInvalid packet length"
	echo -e "${PACKETS[1]}\t$(( ${BYTES[1]} / 1000 ))\tInvalid VLAN tag"
	echo -e "${PACKETS[2]}\t$(( ${BYTES[2]} / 1000 ))\tInvalid/rejected IHL IPv4 field"
	echo -e "${PACKETS[3]}\t$(( ${BYTES[3]} / 1000 ))\tRejected IPv6 fragments"
	C=4
	while read LINE; do
		echo -e "${PACKETS["$C"]}\t$(( ${BYTES["$C"]} / 1000 ))\t$LINE"
		C=$(( $C + 1 ))
	done < "$(dirname ${BASH_SOURCE[0]})/installed-rules.txt"
}
