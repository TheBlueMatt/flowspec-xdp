#!/bin/bash
set -e

RULES="$(birdc show route table flowspec4 primary all)
$(birdc show route table flowspec6 primary all)"

echo "$RULES" | ./genrules.py --8021q=drop-vlan --v6frag=ignore-parse-if-rule --ihl=drop-options
clang -std=c99 -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O3 -emit-llvm -c xdp.c -o - | llc -O3 -march=bpf -filetype=obj -o xdp

echo "Before unload drop count was:"
./dropcount.sh || echo "Not loaded"

ip link set "$1" xdp off
ip link set "$1" xdpgeneric off
# Note that sometimes the automated fallback does not work properly so we have to || generic here
ip link set "$1" xdpoffload obj xdp sec xdp_drop || (
	echo "Failed to install in NIC, testing in driver..." && ip link set "$1" xdpdrv obj xdp sec xdp_drop || (
		echo "Failed to install in driver, using generic..." && ip link set "$1" xdpgeneric obj xdp sec xdp_drop
	)
)
echo "$RULES" | grep "^flow. {" > installed-rules.txt
