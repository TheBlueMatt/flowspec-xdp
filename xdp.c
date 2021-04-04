#include <stdint.h>
#include <endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <arpa/inet.h>

#define NULL (void*)0

/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define IP_PROTO_ICMP 1
#define IP6_PROTO_ICMPV6 58
#define IP6_PROTO_FRAG 44

typedef __uint128_t uint128_t;

// Our own ipv6hdr that uses uint128_t
struct ip6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	priority:4,
	    	version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
	    	priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	flow_lbl[3];

	__be16	payload_len;
	__u8		nexthdr;
	__u8		hop_limit;

	uint128_t	saddr;
	uint128_t	daddr;
} __attribute__((packed));

#define IP6_MF 1
#define IP6_FRAGOFF 0xfff8
struct ip6_fraghdr {
	uint8_t nexthdr;
	uint8_t _reserved;
	uint16_t frag_off; // BE low 3 bits flags, last is "more frags"
	uint32_t id;
} __attribute__((packed));

// Our own ethhdr with optional vlan tags
struct ethhdr_vlan {
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	__be16		vlan_magic;		/* 0x8100 */
	__be16		tci;		/* PCP (3 bits), DEI (1 bit), and VLAN (12 bits) */
	__be16		h_proto;		/* packet type ID field	*/
} __attribute__((packed));

// Our own tcphdr without the flags blown up
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
	__u16	flags;
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
} __attribute__((packed));

// Note that all operations on uint128s *stay* in Network byte order!

#if defined(__LITTLE_ENDIAN)
#define BIGEND32(v) ((v >> 3*8) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | (v << 3*8) & 0xff000000)
#elif defined(__BIG_ENDIAN)
#define BIGEND32(v) (v)
#else
#error "Need endian info"
#endif

#if defined(__LITTLE_ENDIAN)
#define BIGEND128(a, b, c, d) ( \
		(((uint128_t)BIGEND32(d)) << 3*32) | \
		(((uint128_t)BIGEND32(c)) << 2*32) | \
		(((uint128_t)BIGEND32(b)) << 1*32) | \
		(((uint128_t)BIGEND32(a)) << 0*32))
#define HTON128(a) BIGEND128(a >> 3*32, a >> 2*32, a >> 1*32, a>> 0*32)
// Yes, somehow macro'ing this changes LLVM's view of htons...
#define BE16(a) ((((uint16_t)(a & 0xff00)) >> 8) | (((uint16_t)(a & 0xff)) << 8))
#elif defined(__BIG_ENDIAN)
#define BIGEND128(a, b, c, d) ((((uint128_t)a) << 3*32) | (((uint128_t)b) << 2*32) | (((uint128_t)c) << 1*32) | (((uint128_t)d) << 0*32))
#define HTON128(a) (a)
#else
#error "Need endian info"
#endif

#define MASK4(pfxlen) BIGEND32(~((((uint32_t)1) << (32 - pfxlen)) - 1))
#define MASK6(pfxlen) HTON128(~((((uint128_t)1) << (128 - pfxlen)) - 1))
#define MASK6_OFFS(offs, pfxlen) HTON128((~((((uint128_t)1) << (128 - pfxlen)) - 1)) & ((((uint128_t)1) << (128 - offs)) - 1))

// PARSE is used as a preprocessor flag to indicate parsing fields
#define PARSE 42
#include "rules.h"

#define unlikely(a) __builtin_expect(a, 0)
#define likely(a) __builtin_expect(a, 1)

static const uint32_t PKT_LEN_DROP = 0;
static const uint32_t VLAN_DROP = 1;
static const uint32_t IHL_DROP = 2;
static const uint32_t V6FRAG_DROP = 3;
#define STATIC_RULE_CNT 4

#ifdef TEST
// 64 bit version of xdp_md for testing
struct xdp_md {
	__u64 data;
	__u64 data_end;
	__u64 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u64 ingress_ifindex; /* rxq->dev->ifindex */
	__u64 rx_queue_index;  /* rxq->queue_index  */

	__u64 egress_ifindex;  /* txq->dev->ifindex */
};
static const int XDP_PASS = 0;
static const int XDP_DROP = 1;

static long drop_cnt_map[RULECNT + STATIC_RULE_CNT];
#define DO_RETURN(reason, ret) { \
		if (ret == XDP_DROP) drop_cnt_map[reason] += 1; \
		return ret; \
	}

#else
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") drop_cnt_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(long),
	.max_entries = RULECNT + STATIC_RULE_CNT,
};
#define DO_RETURN(reason, ret) {\
		if (ret == XDP_DROP) { \
			long *value = bpf_map_lookup_elem(&drop_cnt_map, &reason); \
			if (value) \
				*value += 1; \
		} \
		return XDP_DROP; \
	}

SEC("xdp_drop")
#endif

// It seems (based on drop counts) that data_end points to the last byte, not one-past-the-end.
// This feels strange, but some documentation suggests > here as well, so we stick with that.
#define CHECK_LEN(start, struc) \
	if (unlikely((void*)(start) + sizeof(struct struc) > data_end)) DO_RETURN(PKT_LEN_DROP, XDP_DROP);

int xdp_drop_prog(struct xdp_md *ctx)
{
	const void *const data_end = (void *)(size_t)ctx->data_end;

	const void * pktdata;
	unsigned short eth_proto;

	{
		CHECK_LEN((size_t)ctx->data, ethhdr);
		const struct ethhdr *const eth = (void*)(size_t)ctx->data;

#if PARSE_8021Q == PARSE
		if (likely(eth->h_proto == BE16(ETH_P_8021Q))) {
			CHECK_LEN((size_t)ctx->data, ethhdr_vlan);
			const struct ethhdr_vlan *const eth_vlan = (void*)(size_t)ctx->data;

#ifdef REQ_8021Q
			if (unlikely((eth_vlan->tci & BE16(0xfff)) != BE16(REQ_8021Q)))
				DO_RETURN(VLAN_DROP, XDP_DROP);
#endif

			eth_proto = eth_vlan->h_proto;
			pktdata = (const void *)(long)ctx->data + sizeof(struct ethhdr_vlan);
#else
		if (unlikely(eth->h_proto == BE16(ETH_P_8021Q))) {
			DO_RETURN(VLAN_DROP, PARSE_8021Q);
#endif
		} else {
#ifdef REQ_8021Q
			DO_RETURN(VLAN_DROP, XDP_DROP);
#else
			pktdata = (const void *)(long)ctx->data + sizeof(struct ethhdr);
			eth_proto = eth->h_proto;
#endif
		}
	}

	const void *l4hdr = NULL;
	const struct tcphdr *tcp = NULL;
	uint8_t ports_valid = 0;
	uint16_t sport, dport; // Host Endian! Only valid with tcp || udp

#ifdef NEED_V4_PARSE
	if (eth_proto == BE16(ETH_P_IP)) {
		CHECK_LEN(pktdata, iphdr);
		const struct iphdr *ip = (struct iphdr*) pktdata;

#if PARSE_IHL == PARSE
		if (unlikely(ip->ihl < 5)) DO_RETURN(IHL_DROP, XDP_DROP);
		l4hdr = pktdata + ip->ihl * 4;
#else
		if (ip->ihl != 5) DO_RETURN(IHL_DROP, PARSE_IHL);
		l4hdr = pktdata + 5*4;
#endif

		const struct icmphdr *icmp = NULL;
		if ((ip->frag_off & BE16(IP_OFFSET)) == 0) {
			if (ip->protocol == IP_PROTO_TCP) {
				CHECK_LEN(l4hdr, tcphdr);
				tcp = (struct tcphdr*) l4hdr;
				sport = BE16(tcp->source);
				dport = BE16(tcp->dest);
				ports_valid = 1;
			} else if (ip->protocol == IP_PROTO_UDP) {
				CHECK_LEN(l4hdr, udphdr);
				const struct udphdr *udp = (struct udphdr*) l4hdr;
				sport = BE16(udp->source);
				dport = BE16(udp->dest);
				ports_valid = 1;
			} else if (ip->protocol == IP_PROTO_ICMP) {
				CHECK_LEN(l4hdr, icmphdr);
				icmp = (struct icmphdr*) l4hdr;
			}
		}

		RULES4
	}
#endif
#ifdef NEED_V6_PARSE
	if (eth_proto == BE16(ETH_P_IPV6)) {
		CHECK_LEN(pktdata, ip6hdr);
		const struct ip6hdr *ip6 = (struct ip6hdr*) pktdata;

		l4hdr = pktdata + 40;

		uint8_t v6nexthdr = ip6->nexthdr;
		const struct ip6_fraghdr *frag6 = NULL;
#ifdef PARSE_V6_FRAG
#if PARSE_V6_FRAG == PARSE
		if (ip6->nexthdr == IP6_PROTO_FRAG) {
			CHECK_LEN(l4hdr, ip6_fraghdr);
			frag6 = (struct ip6_fraghdr*) l4hdr;
			l4hdr = l4hdr + sizeof(struct ip6_fraghdr);
			v6nexthdr = frag6->nexthdr;
#else
		if (unlikely(ip6->nexthdr == IP6_PROTO_FRAG)) {
			DO_RETURN(V6FRAG_DROP, PARSE_V6_FRAG);
#endif
		}
#endif
		// TODO: Handle more options?

		const struct icmp6hdr *icmpv6 = NULL;
		if (frag6 == NULL || (frag6->frag_off & BE16(IP6_FRAGOFF)) == 0) {
			if (v6nexthdr == IP_PROTO_TCP) {
				CHECK_LEN(l4hdr, tcphdr);
				tcp = (struct tcphdr*) l4hdr;
				sport = BE16(tcp->source);
				dport = BE16(tcp->dest);
				ports_valid = 1;
			} else if (v6nexthdr == IP_PROTO_UDP) {
				CHECK_LEN(l4hdr, udphdr);
				const struct udphdr *udp = (struct udphdr*) l4hdr;
				sport = BE16(udp->source);
				dport = BE16(udp->dest);
				ports_valid = 1;
			} else if (v6nexthdr == IP6_PROTO_ICMPV6) {
				CHECK_LEN(l4hdr, icmp6hdr);
				icmpv6 = (struct icmp6hdr*) l4hdr;
			}
		}

		RULES6
	}
#endif

	return XDP_PASS;
}

#ifdef TEST
#include <assert.h>
#include <string.h>

const char d[] = TEST;
int main() {
	struct xdp_md test = {
		.data = (uint64_t)d,
		// -1 because sizeof includes a trailing null in the "string"
		.data_end = (uint64_t)(d + sizeof(d) - 1),
	};
	assert(xdp_drop_prog(&test) == TEST_EXP);
}
#endif
