#!/usr/bin/env python3

import sys
import ipaddress
from enum import Enum
import argparse
import math


IP_PROTO_ICMP = 1
IP_PROTO_ICMPV6 = 58
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

class ASTAction(Enum):
    OR = 1
    AND = 2
    NOT = 3
    FALSE = 4
    TRUE = 5
    EXPR = 6
class ASTNode:
    def __init__(self, action, left, right=None):
        self.action = action
        if action == ASTAction.FALSE or action == ASTAction.TRUE:
            assert left is None and right is None
            return
        self.left = left
        if right is None:
            assert action == ASTAction.EXPR or action == ASTAction.NOT
        else:
            self.right = right

    def write(self, expr_param, expr_param2=None):
        if self.action == ASTAction.OR:
            return "(" + self.left.write(expr_param, expr_param2) + ") || (" + self.right.write(expr_param, expr_param2) + ")"
        if self.action == ASTAction.AND:
            return "(" + self.left.write(expr_param, expr_param2) + ") && (" + self.right.write(expr_param, expr_param2) + ")"
        if self.action == ASTAction.NOT:
            return "!(" + self.left.write(expr_param, expr_param2) + ")"
        if self.action == ASTAction.FALSE:
            return "0"
        if self.action == ASTAction.TRUE:
            return "1"
        if self.action == ASTAction.EXPR:
            return self.left.write(expr_param, expr_param2)

def parse_ast(expr, parse_expr, comma_is_or):
    expr = expr.strip()

    comma_split = expr.split(",", 1)
    or_split = expr.split("||", 1)
    if len(comma_split) > 1 and not "||" in comma_split[0]:
        # Confusingly, BIRD uses `,` as either || or &&, depending on the type
        # of expression being parsed. Specifically, a `numbers-match` uses `,`
        # as OR, whereas a `bitmask-match` uses `,` as AND.
        if comma_is_or:
            return ASTNode(ASTAction.OR, parse_ast(comma_split[0], parse_expr, comma_is_or), parse_ast(comma_split[1], parse_expr, comma_is_or))
        else:
            return ASTNode(ASTAction.AND, parse_ast(comma_split[0], parse_expr, comma_is_or), parse_ast(comma_split[1], parse_expr, comma_is_or))
    if len(or_split) > 1:
        assert not "," in or_split[0]
        return ASTNode(ASTAction.OR, parse_ast(or_split[0], parse_expr, comma_is_or), parse_ast(or_split[1], parse_expr, comma_is_or))

    and_split = expr.split("&&", 1)
    if len(and_split) > 1:
        return ASTNode(ASTAction.AND, parse_ast(and_split[0], parse_expr, comma_is_or), parse_ast(and_split[1], parse_expr, comma_is_or))

    if expr.strip() == "true":
        return ASTNode(ASTAction.TRUE, None)
    if expr.strip() == "false":
        return ASTNode(ASTAction.FALSE, None)

    if expr.startswith("!"):
        return ASTNode(ASTAction.NOT, parse_ast(expr[1:], parse_expr, comma_is_or))

    return parse_expr(expr)


class NumbersAction(Enum):
    EQ = "=="
    GT = ">"
    GTOE = ">="
    LT = "<"
    LTOE = "<="
class NumbersExpr:
    def __init__(self, action, val):
        self.action = action
        self.val = val

    def write(self, param, param2):
        if param2 is not None:
            return "(" + param + self.action.value + self.val + ") || (" + param2 + self.action.value + self.val + ")"
        return param + self.action.value + self.val

def parse_numbers_expr(expr):
    space_split = expr.split(" ")
    if expr.startswith(">="):
        assert len(space_split) == 2
        return ASTNode(ASTAction.EXPR, NumbersExpr(NumbersAction.GTOE, space_split[1]))
    if expr.startswith(">"):
        assert len(space_split) == 2
        return ASTNode(ASTAction.EXPR, NumbersExpr(NumbersAction.GT, space_split[1]))
    if expr.startswith("<="):
        assert len(space_split) == 2
        return ASTNode(ASTAction.EXPR, NumbersExpr(NumbersAction.LTOE, space_split[1]))
    if expr.startswith("<"):
        assert len(space_split) == 2
        return ASTNode(ASTAction.EXPR, NumbersExpr(NumbersAction.LT, space_split[1]))
    if ".." in expr:
        rangesplit = expr.split("..")
        assert len(rangesplit) == 2
        #XXX: Are ranges really inclusive,inclusive?
        left = ASTNode(ASTAction.EXPR, NumbersExpr(NumbersAction.GTOE, rangesplit[0]))
        right = ASTNode(ASTAction.EXPR, NumbersExpr(NumbersAction.LTOE, rangesplit[1]))
        return ASTNode(ASTAction.AND, left, right)
    
    if expr.startswith("= "):
        expr = expr[2:]
    return ASTNode(ASTAction.EXPR, NumbersExpr(NumbersAction.EQ, expr))

class FragExpr(Enum):
    IF = 1
    FF = 2
    DF = 3
    LF = 4

    def write(self, ipproto, _param2):
        if ipproto == 4:
            if self == FragExpr.IF:
                return "(ip->frag_off & BE16(IP_MF|IP_OFFSET)) != 0"
            elif self == FragExpr.FF:
                return "((ip->frag_off & BE16(IP_MF)) != 0 && (ip->frag_off & BE16(IP_OFFSET)) == 0)"
            elif self == FragExpr.DF:
                return "(ip->frag_off & BE16(IP_DF)) != 0"
            elif self == FragExpr.LF:
                return "((ip->frag_off & BE16(IP_MF)) == 0 && (ip->frag_off & BE16(IP_OFFSET)) != 0)"
            else:
                assert False
        else:
            if self == FragExpr.IF:
                return "frag6 != NULL"
            elif self == FragExpr.FF:
                return "(frag6 != NULL && (frag6->frag_off & BE16(IP6_MF)) != 0 && (frag6->frag_off & BE16(IP6_FRAGOFF)) == 0)"
            elif self == FragExpr.DF:
                assert False # No such thing in v6
            elif self == FragExpr.LF:
                return "(frag6 != NULL && (frag6->frag_off & BE16(IP6_MF)) == 0 && (frag6->frag_off & BE16(IP6_FRAGOFF)) != 0)"
            else:
                assert False

def parse_frag_expr(expr):
    if expr == "is_fragment":
        return ASTNode(ASTAction.EXPR, FragExpr.IF)
    elif expr == "first_fragment":
        return ASTNode(ASTAction.EXPR, FragExpr.FF)
    elif expr == "dont_fragment":
        return ASTNode(ASTAction.EXPR, FragExpr.DF)
    elif expr == "last_fragment":
        return ASTNode(ASTAction.EXPR, FragExpr.LF)
    else:
        assert False

class BitExpr:
    def __init__(self, val):
        s = val.split("/")
        assert len(s) == 2
        self.match = s[0]
        self.mask = s[1]

    def write(self, param, _param2):
        return f"({param} & {self.mask}) == {self.match}"

def parse_bit_expr(expr):
    return ASTNode(ASTAction.EXPR, BitExpr(expr))


def ip_to_rule(proto, inip, ty, offset):
    if proto == 4:
        assert offset is None
        net = ipaddress.IPv4Network(inip.strip())
        if net.prefixlen == 0:
            return ""
        return f"""if ((ip->{ty} & MASK4({net.prefixlen})) != BIGEND32({int(net.network_address)}ULL))
	break;"""
    else:
        net = ipaddress.IPv6Network(inip.strip())
        if net.prefixlen == 0:
            return ""
        u32s = [(int(net.network_address) >> (3*32)) & 0xffffffff,
                (int(net.network_address) >> (2*32)) & 0xffffffff,
                (int(net.network_address) >> (1*32)) & 0xffffffff,
                (int(net.network_address) >> (0*32)) & 0xffffffff]
        if offset is None:
            mask = f"MASK6({net.prefixlen})"
        else:
            mask = f"MASK6_OFFS({offset}, {net.prefixlen})"
        return f"""if ((ip6->{ty} & {mask}) != (BIGEND128({u32s[0]}ULL, {u32s[1]}ULL, {u32s[2]}ULL, {u32s[3]}ULL) & {mask}))
	break;"""

def fragment_to_rule(ipproto, rules):
    ast = parse_ast(rules, parse_frag_expr, False)
    return "if (!( " + ast.write(ipproto) + " )) break;"

def len_to_rule(rules):
    ast = parse_ast(rules, parse_numbers_expr, True)
    return "if (!( " + ast.write("(data_end - pktdata)") + " )) break;"
 
def proto_to_rule(ipproto, proto):
    ast = parse_ast(proto, parse_numbers_expr, True)

    if ipproto == 4:
        return "if (!( " + ast.write("ip->protocol") + " )) break;"
    else:
        return "if (!( " + ast.write("ip6->nexthdr") + " )) break;"

def icmp_type_to_rule(proto, ty):
    ast = parse_ast(ty, parse_numbers_expr, True)
    if proto == 4:
        return "if (icmp == NULL) break;\nif (!( " + ast.write("icmp->type") + " )) break;"
    else:
        return "if (icmpv6 == NULL) break;\nif (!( " + ast.write("icmpv6->icmp6_type") + " )) break;"

def icmp_code_to_rule(proto, code):
    ast = parse_ast(code, parse_numbers_expr, True)
    if proto == 4:
        return "if (icmp == NULL) break;\nif (!( " + ast.write("icmp->code") + " )) break;"
    else:
        return "if (icmpv6 == NULL) break;\nif (!( " + ast.write("icmpv6->icmp6_code") + " )) break;"

def dscp_to_rule(proto, rules):
    ast = parse_ast(rules, parse_numbers_expr, True)

    if proto == 4:
        return "if (!( " + ast.write("((ip->tos & 0xfc) >> 2)") + " )) break;"
    else:
        return "if (!( " + ast.write("((ip6->priority << 2) | ((ip6->flow_lbl[0] & 0xc0) >> 6))") + " )) break;"

def port_to_rule(ty, rules):
    if ty == "port" :
        ast = parse_ast(rules, parse_numbers_expr, True)
        return "if (sport == -1 || dport == -1) break;\nif (!( " + ast.write("sport", "dport") + " )) break;"

    ast = parse_ast(rules, parse_numbers_expr, True)
    return "if (" + ty + " == -1) break;\nif (!( " + ast.write(ty) + " )) break;"

def tcp_flags_to_rule(rules):
    ast = parse_ast(rules, parse_bit_expr, False)

    return f"""if (tcp == NULL) break;
if (!( {ast.write("(ntohs(tcp->flags) & 0xfff)")} )) break;"""

def flow_label_to_rule(rules):
    ast = parse_ast(rules, parse_bit_expr, False)

    return f"""if (ip6 == NULL) break;
if (!( {ast.write("((((uint32_t)(ip6->flow_lbl[0] & 0xf)) << 2*8) | (((uint32_t)ip6->flow_lbl[1]) << 1*8) | (uint32_t)ip6->flow_lbl[0])")} )) break;"""


with open("rules.h", "w") as out:
    parse = argparse.ArgumentParser()
    parse.add_argument("--ihl", dest="ihl", required=True, choices=["drop-options","accept-options","parse-options"])
    parse.add_argument("--v6frag", dest="v6frag", required=True, choices=["drop-frags","ignore","parse-frags","ignore-parse-if-rule"])
    parse.add_argument("--8021q", dest="vlan", required=True, choices=["drop-vlan","accept-vlan","parse-vlan"])
    parse.add_argument("--require-8021q", dest="vlan_tag")
    args = parse.parse_args(sys.argv[1:])

    if args.ihl == "drop-options":
        out.write("#define PARSE_IHL XDP_DROP\n")
    elif args.ihl == "accept-options":
        out.write("#define PARSE_IHL XDP_PASS\n")
    elif args.ihl == "parse-options":
        out.write("#define PARSE_IHL PARSE\n")

    if args.v6frag == "drop-frags":
        out.write("#define PARSE_V6_FRAG XDP_DROP\n")
    elif args.v6frag == "ignore":
        pass
    elif args.v6frag == "parse-frags":
        out.write("#define PARSE_V6_FRAG PARSE\n")

    if args.vlan == "drop-vlan":
        out.write("#define PARSE_8021Q XDP_DROP\n")
    elif args.vlan == "accept-vlan":
        out.write("#define PARSE_8021Q XDP_PASS\n")
    elif args.vlan == "parse-vlan":
        out.write("#define PARSE_8021Q PARSE\n")

    if args.vlan_tag is not None:
        if args.vlan != "parse-vlan":
            assert False
        out.write("#define REQ_8021Q " + args.vlan_tag + "\n")

    rules6 = ""
    rules4 = ""
    use_v6_frags = False
    stats_rulecnt = 0
    ratelimitcnt = 0
    v4persrcratelimits = []
    v5persrcratelimits = []
    v6persrcratelimits = []

    lastrule = None
    for line in sys.stdin.readlines():
        if "{" in line:
            if lastrule is not None:
                print("Skipped rule due to lack of understood community tag: " + lastrule)
            lastrule = line
            continue
        if "BGP.ext_community: " in line:
            assert lastrule is not None

            t = lastrule.split("{")
            if t[0].strip() == "flow4":
                proto = 4
                rules4 += "\tdo {\\\n"
            elif t[0].strip() == "flow6":
                proto = 6
                rules6 += "\tdo {\\\n"
            else:
                continue

            def write_rule(r):
                global rules4, rules6
                if proto == 6:
                    rules6 += "\t\t" + r.replace("\n", " \\\n\t\t") + " \\\n"
                else:
                    rules4 += "\t\t" + r.replace("\n", " \\\n\t\t") + " \\\n"

            rule = t[1].split("}")[0].strip()
            for step in rule.split(";"):
                if step.strip().startswith("src") or step.strip().startswith("dst"):
                    nets = step.strip()[3:].strip().split(" ")
                    if len(nets) > 1:
                        assert nets[1] == "offset"
                        offset = nets[2]
                    else:
                        offset = None
                    if step.strip().startswith("src"):
                        write_rule(ip_to_rule(proto, nets[0], "saddr", offset))
                    else:
                        write_rule(ip_to_rule(proto, nets[0], "daddr", offset))
                elif step.strip().startswith("proto") and proto == 4:
                    write_rule(proto_to_rule(4, step.strip()[6:]))
                elif step.strip().startswith("next header") and proto == 6:
                    write_rule(proto_to_rule(6, step.strip()[12:]))
                elif step.strip().startswith("icmp type"):
                    write_rule(icmp_type_to_rule(proto, step.strip()[10:]))
                elif step.strip().startswith("icmp code"):
                    write_rule(icmp_code_to_rule(proto, step.strip()[10:]))
                elif step.strip().startswith("sport") or step.strip().startswith("dport") or step.strip().startswith("port"):
                    write_rule(port_to_rule(step.strip().split(" ")[0], step.strip().split(" ", 1)[1]))
                elif step.strip().startswith("length"):
                    write_rule(len_to_rule(step.strip()[7:]))
                elif step.strip().startswith("dscp"):
                    write_rule(dscp_to_rule(proto, step.strip()[5:]))
                elif step.strip().startswith("tcp flags"):
                    write_rule(tcp_flags_to_rule(step.strip()[10:]))
                elif step.strip().startswith("label"):
                    write_rule(flow_label_to_rule(step.strip()[6:]))
                elif step.strip().startswith("fragment"):
                    if proto == 6:
                        use_v6_frags = True
                    write_rule(fragment_to_rule(proto, step.strip()[9:]))
                elif step.strip() == "":
                    pass
                else:
                    assert False

            # Now write the match handling!
            first_action = None
            stats_action = ""
            last_action = None
            for community in line.split("("):
                if not community.startswith("generic, "):
                    continue
                blocks = community.split(",")
                assert len(blocks) == 3
                if len(blocks[1].strip()) != 10: # Should be 0x12345678
                    continue
                ty = blocks[1].strip()[:6]
                high_byte = int(blocks[1].strip()[6:8], 16)
                mid_byte = int(blocks[1].strip()[8:], 16)
                low_bytes = int(blocks[2].strip(") \n"), 16)
                if ty == "0x8006" or ty == "0x800c" or ty == "0x8306" or ty == "0x830c":
                    if first_action is not None:
                        # Two ratelimit actions, just drop the old one. RFC 8955 says we can.
                        first_action = None
                    exp = (low_bytes & (0xff << 23)) >> 23
                    if low_bytes == 0:
                        first_action = "{stats_replace}\nreturn XDP_DROP;"
                    elif low_bytes & (1 <<  31) != 0:
                        # Negative limit, just drop
                        first_action = "{stats_replace}\nreturn XDP_DROP;"
                    elif exp == 0xff:
                        # NaN/INF. Just treat as INF and accept
                        first_action = None
                    elif exp < 127: # < 1
                        first_action = "{stats_replace}\nreturn XDP_DROP;"
                    elif exp >= 127 + 29: # We can't handle the precision required with ns this high
                        first_action = None
                    else:
                        mantissa = low_bytes & ((1 << 23) - 1)
                        value = 1.0 + mantissa / (2**23)
                        value *= 2**(exp-127)

                        first_action =   "int64_t time_masked = bpf_ktime_get_ns() & RATE_TIME_MASK;\n"
                        first_action += f"int64_t per_pkt_ns = (1000000000LL << RATE_BUCKET_INTEGER_BITS) / {math.floor(value)};\n"
                        if ty == "0x8006" or ty == "0x800c":
                            spin_lock = "bpf_spin_lock(&rate->lock);"
                            spin_unlock = "bpf_spin_unlock(&rate->lock);"
                            first_action += f"const uint32_t ratelimitidx = {ratelimitcnt};\n"
                            first_action += "struct ratelimit *rate = bpf_map_lookup_elem(&rate_map, &ratelimitidx);\n"
                            ratelimitcnt += 1
                        else:
                            spin_lock = "/* No locking as we're locked in get_v*_persrc_ratelimit */"
                            spin_unlock = "bpf_spin_unlock(rate_ptr.lock);"
                            if proto == 4:
                                if mid_byte > 32:
                                    continue
                                first_action += f"const uint32_t srcip = ip->saddr & MASK4({mid_byte});\n"
                                first_action += f"void *rate_map = &v4_src_rate_{len(v4persrcratelimits)};\n"
                                first_action += f"struct persrc_rate4_ptr rate_ptr = get_v4_persrc_ratelimit(srcip, rate_map, {(high_byte + 1) * 4096}, time_masked);\n"
                                first_action += f"struct persrc_rate4_entry *rate = rate_ptr.rate;\n"
                                v4persrcratelimits.append((high_byte + 1) * 4096)
                            elif mid_byte <= 64:
                                first_action += f"const uint64_t srcip = BE128BEHIGH64(ip6->saddr & MASK6({mid_byte}));\n"
                                first_action += f"void *rate_map = &v5_src_rate_{len(v5persrcratelimits)};\n"
                                first_action += f"struct persrc_rate5_ptr rate_ptr = get_v5_persrc_ratelimit(srcip, rate_map, {(high_byte + 1) * 4096}, time_masked);\n"
                                first_action += f"struct persrc_rate5_entry *rate = rate_ptr.rate;\n"
                                v5persrcratelimits.append((high_byte + 1) * 4096)
                            else:
                                if mid_byte > 128:
                                    continue
                                first_action += f"const uint128_t srcip = ip6->saddr & MASK6({mid_byte});\n"
                                first_action += f"void *rate_map = &v6_src_rate_{len(v6persrcratelimits)};\n"
                                first_action += f"struct persrc_rate6_ptr rate_ptr = get_v6_persrc_ratelimit(srcip, rate_map, {(high_byte + 1) * 4096}, time_masked);\n"
                                first_action += f"struct persrc_rate6_entry *rate = rate_ptr.rate;\n"
                                v6persrcratelimits.append((high_byte + 1) * 4096)
                        if ty == "0x8006" or ty == "0x8306":
                            first_action += "uint64_t amt = data_end - pktdata;\n"
                        else:
                            first_action += "uint64_t amt = 1;\n"
                        first_action +=  "if (rate) {\n"
                        first_action += f"\t{spin_lock}\n"
                        first_action +=  "\tint64_t bucket_pkts = (rate->sent_time & (~RATE_TIME_MASK)) >> (64 - RATE_BUCKET_BITS);\n"
                        # We mask the top 12 bits, so date overflows every 52 days, handled below
                        first_action +=  "\tint64_t time_diff = time_masked - ((int64_t)(rate->sent_time & RATE_TIME_MASK));\n"
                        first_action +=  "\tif (unlikely(time_diff < -1000000000 || time_diff > 16000000000)) {\n"
                        first_action +=  "\t\tbucket_pkts = 0;\n"
                        first_action +=  "\t} else {\n"
                        first_action +=  "\t\tif (unlikely(time_diff < 0)) { time_diff = 0; }\n"
                        first_action += f"\t\tint64_t pkts_since_last = (time_diff << RATE_BUCKET_BITS) * amt / per_pkt_ns;\n"
                        first_action +=  "\t\tbucket_pkts -= pkts_since_last;\n"
                        first_action +=  "\t}\n"
                        first_action +=  "\tif (bucket_pkts >= (((1 << RATE_BUCKET_INTEGER_BITS) - 1) << RATE_BUCKET_DECIMAL_BITS)) {\n"
                        first_action += f"\t\t{spin_unlock}\n"
                        first_action +=  "\t\t{stats_replace}\n"
                        first_action +=  "\t\treturn XDP_DROP;\n"
                        first_action +=  "\t} else {\n"
                        first_action +=  "\t\tif (unlikely(bucket_pkts < 0)) bucket_pkts = 0;\n"
                        first_action += f"\t\trate->sent_time = time_masked | ((bucket_pkts + (1 << RATE_BUCKET_DECIMAL_BITS)) << (64 - RATE_BUCKET_BITS));\n"
                        first_action += f"\t\t{spin_unlock}\n"
                        first_action +=  "\t}\n"
                        first_action +=  "}\n"
                elif ty == "0x8007":
                    if low_bytes & 1 == 0:
                        last_action = "return XDP_PASS;"
                    if low_bytes & 2 == 2:
                        stats_action = f"const uint32_t ruleidx = STATIC_RULE_CNT + {stats_rulecnt};\n"
                        stats_action += "INCREMENT_MATCH(ruleidx);"
                elif ty == "0x8008":
                    assert False # We do not implement the redirect action
                elif ty == "0x8009":
                    if low_bytes & ~0b111111 != 0:
                        assert False # Invalid DSCP value
                    if proto == 4:
                        write_rule("int32_t chk = ~BE16(ip->check) & 0xffff;")
                        write_rule("uint8_t orig_tos = ip->tos;")
                        write_rule("ip->tos = (ip->tos & 3) | " + str(low_bytes << 2) + ";")
                        write_rule("chk = (chk - orig_tos + ip->tos);")
                        write_rule("if (unlikely(chk > 0xffff)) { chk -= 65535; }")
                        write_rule("else if (unlikely(chk < 0)) { chk += 65535; }")
                        write_rule("ip->check = ~BE16(chk);")
                    else:
                        write_rule("ip6->priority = " + str(low_bytes >> 2) + ";")
                        write_rule("ip6->flow_lbl[0] = (ip6->flow_lbl[0] & 0x3f) | " + str((low_bytes & 3) << 6) + ";")
            if first_action is not None:
                write_rule(first_action.replace("{stats_replace}", stats_action))
            if stats_action != "" and (first_action is None or "{stats_replace}" not in first_action):
                write_rule(stats_action)
            if last_action is not None:
                write_rule(last_action)
            if proto == 6:
                rules6 += "\t} while(0);\\\n"
            else:
                rules4 += "\t} while(0);\\\n"
            if stats_action != "":
                print(rule)
                stats_rulecnt += 1
            lastrule = None

    out.write("\n")
    out.write(f"#define STATS_RULECNT {stats_rulecnt}\n")
    if ratelimitcnt != 0:
        out.write(f"#define RATE_CNT {ratelimitcnt}\n")
    if rules4 != "":
        out.write("#define NEED_V4_PARSE\n")
        out.write("#define RULES4 {\\\n" + rules4 + "}\n")
    if rules6:
        out.write("#define NEED_V6_PARSE\n")
        out.write("#define RULES6 {\\\n" + rules6 + "}\n")
    if args.v6frag == "ignore-parse-if-rule":
        if use_v6_frags:
            out.write("#define PARSE_V6_FRAG PARSE\n")
    with open("maps.h", "w") as out:
        for idx, limit in enumerate(v4persrcratelimits):
            out.write(f"SRC_RATE_DEFINE(4, {idx}, {limit})\n")
        for idx, limit in enumerate(v5persrcratelimits):
            out.write(f"SRC_RATE_DEFINE(5, {idx}, {limit})\n")
        for idx, limit in enumerate(v6persrcratelimits):
            out.write(f"SRC_RATE_DEFINE(6, {idx}, {limit})\n")
