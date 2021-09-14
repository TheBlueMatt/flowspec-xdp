FlowSpec -> XDP Conversion Utility
==================================

This utility allows you to convert flowspec rules (extracted from a local BIRD instance with birdc)
to an XDP program. It currently supports the entire flowspec match grammar, rate limits, traffic
action packet match counting (sample bit) and terminal bit, and traffic marking. The redirect
community is not supported.

Note that correctly sorting rules is *not* implemented as it requires implementing the flowspec
wire serialization format and it may better be done inside bird/birdc. Thus, be vary careful using
the terminal bit in the traffict action community.

In addition to the communities specified in RFC 8955, two additional communities are supported which
provide rate-limiting on a per-source basis. When the upper two bytes in an extended community are
0x8306 (rate in bytes) or 0x830c (rate in packets), we rate limit the same as 0x8006 or 0x800c
except that the rate limit is applied per source address. The encoding mirrors the non-per-source
encoding in that the last 4 octets are the floating-point rate limit. Instead of a 2 octet
AS/ignored value, the third octet is the maximum number of source IPs tracked (plus one, times 4096)
and the fourth octet is a prefix length mask, which is applied to the source IP before rate-limiting.

See `collision_prob.py` for collision probabilities in the hash table to estimate the size you
should use.

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

Note that if all of the above options are set to their "drop" or "ignore" variants, the parsing can
avoid all offset calculation, using static offsets for all fields.

Drop counts are tracked in XDP per-CPU arrays, and can be viewed with `dropcount.sh`.

Note that rate limiting is currently tracked under a single per-rule spinlock, which may be a
bottleneck for high speed NICs with many RX queues. Adapting this to per-RX-queue/CPU limits would
be trivial but is left as a future project.
