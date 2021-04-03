#!/bin/bash

set -e

TEST_PKT='#define TEST \
"\x00\x17\x10\x95\xe8\x96\x00\x0d\xb9\x50\x11\x4c\x08\x00\x45\x00" \
"\x00\x8c\x7d\x0f\x00\x00\x40\x11\x3a\x31\x48\xe5\x68\xce\x67\x63" \
"\xaa\x0a\xdd\x9d\x10\x92\x00\x78\xc3\xaa\x04\x00\x00\x00\x47\x89" \
"\x49\xb1\x1f\x0e\x00\x00\x00\x00\x00\x00\xa7\xee\xab\xa4\xc6\x09" \
"\xe7\x0f\x41\xfc\xd5\x75\x1d\xc4\x97\xfa\xd7\x96\x8c\x1f\x19\x54" \
"\xa7\x74\x08\x5c\x28\xfe\xd9\x32\x4b\xe0\x62\x55\xeb\xb4\x1e\x36" \
"\x5f\xf5\x38\x48\x18\x75\x57\x9a\x05\x7e\x3d\xb1\x55\x79\x0f\xd0" \
"\x8c\x79\x72\x90\xb7\x16\x12\x18\xa1\x97\x53\xf1\x49\x0a\x35\x40" \
"\xc2\x8b\x72\x7a\x38\x22\x04\x96\x01\xd3\x7e\x47\x5d\xaa\x03\xb0" \
"\xb5\xc3\xa9\xa6\x21\x14\xc7\xd9\x71\x07"'

# Test all the things...
echo "flow4 { src 72.229.104.206/32; dst 103.99.170.10/32; proto = 17; sport = 56733; dport = 4242; length = 140; dscp 0/0xff; fragment !dont_fragment && !is_fragment && !first_fragment && !last_fragment };" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_DROP" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow4 { port = 4242; icmp code = 0; };" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_PASS" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

# Some port tests...
echo "flow4 { port = 4242 && = 56733; };" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_DROP" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow4 { port = 4242 || 1; sport = 56733 };" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_DROP" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow4 { port = 4242 && 1 };" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_PASS" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow4 { icmp code != 0; };" | ./genrules.py parse_8021q
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_PASS" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

TEST_PKT='#define TEST \
"\x00\x0d\xb9\x50\x11\x4c\x00\x17\x10\x95\xe8\x96\x86\xdd\x60\x00" \
"\x00\x00\x00\x20\x06\x37\x2a\x01\x04\xf8\x01\x30\x71\xd2\x00\x00" \
"\x00\x00\x00\x00\x00\x02\x26\x20\x00\x6e\xa0\x00\x20\x01\x00\x00" \
"\x00\x00\x00\x00\x00\x06\x20\x8d\xc2\x72\xff\x5f\x50\xa7\x1a\xfb" \
"\x41\xed\x80\x10\x06\xef\x87\x8c\x00\x00\x01\x01\x08\x0a\x98\x3d" \
"\x75\xde\xeb\x22\xd6\x80"'

# Some v6 TCP tests...
echo "flow6 { src 2a01:4f8:130:71d2::2/128; dst 2620:6e:a000:2001::6/128; next header 6; port 8333 && 49778; tcp flags 0x010/0xfff;};" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_DROP" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow6 { src 0:4f8:130:71d2::2/128 offset 16; dst 0:0:a000:2001::/64 offset 32; next header 6; port 8333 && 49778; tcp flags 0x010/0xfff;};" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_DROP" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow6 { icmp code != 0; };" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_PASS" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

TEST_PKT='#define TEST \
"\xcc\x2d\xe0\xf5\x02\xe1\x00\x0d\xb9\x50\x42\xfe\x81\x00\x00\x03" \
"\x08\x00\x45\x00\x00\x54\xda\x85\x40\x00\x40\x01\x67\xc6\x0a\x45" \
"\x1e\x51\xd1\xfa\xfd\xcc\x08\x00\x18\x82\x7e\xda\x00\x02\xc8\xc4" \
"\x67\x60\x00\x00\x00\x00\x69\xa9\x08\x00\x00\x00\x00\x00\x10\x11" \
"\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21" \
"\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31" \
"\x32\x33\x34\x35\x36\x37"'

# ICMP and VLAN tests
echo "flow4 { src 10.0.0.0/8; dst 209.250.0.0/16; proto = 1; icmp type 8; icmp code >= 0; length < 100; fragment dont_fragment; };" | ./genrules.py parse_8021q
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_DROP" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow4 { icmp type 8; icmp code > 0; };" | ./genrules.py parse_8021q
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_PASS" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow4 { icmp type 9; };" | ./genrules.py parse_8021q
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_PASS" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow4 { src 10.0.0.0/8; dst 209.250.0.0/16; proto = 1; icmp type 8; icmp code >= 0; length < 100; fragment dont_fragment; };" | ./genrules.py req_8021q=3
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_DROP" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow4 { src 0.0.0.0/32; };" | ./genrules.py req_8021q=4
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_DROP" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow4 { src 0.0.0.0/32; };" | ./genrules.py req_8021q=3
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_PASS" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow4 { port 42; };" | ./genrules.py parse_8021q
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_PASS" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

TEST_PKT='#define TEST \
"\x00\x0d\xb9\x50\x11\x4c\x00\x17\x10\x95\xe8\x96\x86\xdd\x60\x0a" \
"\xb8\x00\x00\x40\x3a\x3e\x20\x01\x04\x70\x00\x00\x02\xc8\x00\x00" \
"\x00\x00\x00\x00\x00\x02\x26\x20\x00\x6e\xa0\x00\x00\x01\x00\x00" \
"\x00\x00\x00\x00\xca\xfe\x81\x00\x40\x94\x85\x14\x00\x13\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00"'

# ICMPv6 tests
echo "flow6 { icmp type 129; icmp code 0; };" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_DROP" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow6 { icmp code != 0; };" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_PASS" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow6 { tcp flags 0x0/0x0; };" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_PASS" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp

echo "flow6 { port 42; };" | ./genrules.py
echo "$TEST_PKT" >> rules.h
echo "#define TEST_EXP XDP_PASS" >> rules.h
clang -std=c99 -fsanitize=address -pedantic -Wall -Wextra -Wno-pointer-arith -Wno-unused-variable -O0 -g xdp.c -o xdp && ./xdp


