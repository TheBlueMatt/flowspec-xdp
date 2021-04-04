FlowSpec -> XDP Conversion Utility
==================================

This utility allows you to convert flowspec rules (exctracted from a local BIRD instance with birdc)
to an XDP program. It currently supports the entire flowspec grammar, however does not implement
community parsing to detect actions due to BIRD limitations.

`install.sh` provides a simple example script which will compile and install a generated XDP program
from the rules in bird's `flowspec4` and `flowspec6` routing tables. It will drop any packets which
match any flowspec filter.

`genrules.py` will accept birdc output on stdin and generate a rules.h file which is included in
xdp.c to check individual rules. The specific behavior of some less-common parsing options can be
controlled by parameters to `genrules.py` -
 * --8021q can be either "drop-vlan", "accept-vlan" or "parse-vlan" to either drop all traffic with
   a VLAN tag, accept all traffic with a VLAN tag (without comparing it against any flowspec rules),
   or parse VLAN traffic and compare it against flowspec rules just like any other traffic.
 * If --8021q is set to "parse-vlan", --require-8021q can be set to a specific VLAN tag, and all
   traffic with different VLAN tags is dropped.
 * --ihl can be set to "drop-options", "accept-options", or "parse-options" to drop all traffic with
   extra IPv4 option fields, accept all traffic with extra IPv4 options fields (without comparing it
   to any flowspec rules), or parse IPv4 traffic with option fields like normal.
 * --v6frag can be set to "drop-frags","ignore","parse-frags","ignore-parse-if-rule" to:
   * drop all IPv6 fragments,
   * ignore IPv6 fragments, matching only the IPv6 header but no ICMP/TCP/UDP options,
   * parse IPv6 fragments, matching ICMP/TCP/UDP options if relevant (eg often only in the first
     fragment), or
   * ignore IPv6 fragments as above, unless a flow6 rule specifies the "fragment" keyword, in which
     case parse all IPv6 fragments as above for all rules.

Note that if all of the above options are set to their "drop" variant, the parsing can avoid all
offset calculation, using static offsets for all fields.

Drop counts are tracked in XDP per-CPU arrays, and can be viewed with `dropcount.sh`.
