#!/bin/bash
set -e

CLANG_ARGS=""
XDP_SECTION="xdp_drop"
if [ "$2" != "" ]; then
	CLANG_ARGS="-DHAVE_WRAPPER"
	XDP_SECTION="$3"
	if [ ! -f "$2" -o "$3" = "" ]; then
		echo "To use a wrapper C file, call as $0 interface path/to/wrapper.c xdp_section wrapper-clang-args"
		exit 1
	fi
fi

RULES="$(birdc show route table flowspec4 primary all)
$(birdc show route table flowspec6 primary all)"

echo "const uint8_t COMPILE_TIME_RAND[] = { $(dd if=/dev/urandom of=/dev/stdout bs=1 count=8 2>/dev/null | hexdump -e '4/1 "0x%02x, "') };" > rand.h

echo "$RULES" | ./genrules.py --8021q=drop-vlan --v6frag=ignore-parse-if-rule --ihl=parse-options
clang $CLANG_ARGS -g -std=c99 -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -Wno-unused-function -O3 -emit-llvm -c xdp.c -o xdp.bc
if [ "$2" != "" ]; then
	clang $4 -g -std=c99 -pedantic -Wall -Wextra -Wno-pointer-arith -O3 -emit-llvm -c "$2" -o wrapper.bc
	llvm-link xdp.bc wrapper.bc | llc -O3 -march=bpf -filetype=obj -o xdp
else
	cat xdp.bc | llc -O3 -march=bpf -filetype=obj -o xdp
fi

echo "Before unload drop count was:"
./dropcount.sh || echo "Not loaded"

ip link set "$1" xdp off
ip link set "$1" xdpgeneric off
# Note that sometimes the automated fallback does not work properly so we have to || generic here
ip link set "$1" xdpoffload obj xdp sec $XDP_SECTION || (
	echo "Failed to install in NIC, testing in driver..." && ip link set "$1" xdpdrv obj xdp sec $XDP_SECTION || (
		echo "Failed to install in driver, using generic..." && ip link set "$1" xdpgeneric obj xdp sec $XDP_SECTION
	)
)
echo "$RULES" | grep "^flow. {" > installed-rules.txt
