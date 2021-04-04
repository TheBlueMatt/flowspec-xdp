#!/usr/bin/env python3

import sys
import ipaddress
from enum import Enum
import argparse


IP_PROTO_ICMP = 1
IP_PROTO_ICMPV6 = 58
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

class ASTAction(Enum):
    OR = 1,
    AND = 2,
    NOT = 3,
    EXPR = 4
class ASTNode:
    def __init__(self, action, left, right=None):
        self.action = action
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
        if self.action == ASTAction.EXPR:
            return self.left.write(expr_param, expr_param2)

def parse_ast(expr, parse_expr):
    expr = expr.strip()

    and_split = expr.split("&&", 1)
    or_split = expr.split("||", 1)
    if len(and_split) > 1 and not "||" in and_split[0]:
        return ASTNode(ASTAction.AND, parse_ast(and_split[0], parse_expr), parse_ast(and_split[1], parse_expr))
    if len(or_split) > 1:
        assert not "&&" in or_split[0]
        return ASTNode(ASTAction.OR, parse_ast(or_split[0], parse_expr), parse_ast(or_split[1], parse_expr))

    comma_split = expr.split(",", 1)
    if len(comma_split) > 1:
        return ASTNode(ASTAction.OR, parse_ast(comma_split[0], parse_expr), parse_ast(comma_split[1], parse_expr))

    if expr.startswith("!"):
        return ASTNode(ASTAction.NOT, parse_ast(expr[1:], parse_expr))

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
    ast = parse_ast(rules, parse_frag_expr)
    return "if (!( " + ast.write(ipproto) + " )) break;"

def len_to_rule(rules):
    ast = parse_ast(rules, parse_numbers_expr)
    return "if (!( " + ast.write("(data_end - pktdata)") + " )) break;"
 
def proto_to_rule(ipproto, proto):
    ast = parse_ast(proto, parse_numbers_expr)

    if ipproto == 4:
        return "if (!( " + ast.write("ip->protocol") + " )) break;"
    else:
        return "if (!( " + ast.write("ip6->nexthdr") + " )) break;"

def icmp_type_to_rule(proto, ty):
    ast = parse_ast(ty, parse_numbers_expr)
    if proto == 4:
        return "if (icmp == NULL) break;\nif (!( " + ast.write("icmp->type") + " )) break;"
    else:
        return "if (icmpv6 == NULL) break;\nif (!( " + ast.write("icmpv6->icmp6_type") + " )) break;"

def icmp_code_to_rule(proto, code):
    ast = parse_ast(code, parse_numbers_expr)
    if proto == 4:
        return "if (icmp == NULL) break;\nif (!( " + ast.write("icmp->code") + " )) break;"
    else:
        return "if (icmpv6 == NULL) break;\nif (!( " + ast.write("icmpv6->icmp6_code") + " )) break;"

def dscp_to_rule(proto, rules):
    ast = parse_ast(rules, parse_numbers_expr)

    if proto == 4:
        return "if (!( " + ast.write("((ip->tos & 0xfc) >> 2)") + " )) break;"
    else:
        return "if (!( " + ast.write("((ip6->priority << 4) | ((ip6->flow_lbl[0] & 0xc0) >> 4) >> 2)") + " )) break;"

def port_to_rule(ty, rules):
    if ty == "port" :
        ast = parse_ast(rules, parse_numbers_expr)
        return "if (tcp == NULL && udp == NULL) break;\nif (!( " + ast.write("sport", "dport") + " )) break;"

    ast = parse_ast(rules, parse_numbers_expr)
    return "if (tcp == NULL && udp == NULL) break;\nif (!( " + ast.write(ty) + " )) break;"

def tcp_flags_to_rule(rules):
    ast = parse_ast(rules, parse_bit_expr)

    return f"""if (tcp == NULL) break;
if (!( {ast.write("(ntohs(tcp->flags) & 0xfff)")} )) break;"""

def flow_label_to_rule(rules):
    ast = parse_ast(rules, parse_bit_expr)

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

    use_v4 = False
    use_v6 = False
    use_v6_frags = False
    rulecnt = 0

    out.write("#define RULES \\\n")

    def write_rule(r):
        out.write("\t\t" + r.replace("\n", " \\\n\t\t") + " \\\n")

    for line in sys.stdin.readlines():
        t = line.split("{")
        if len(t) != 2:
            continue
        if t[0].strip() == "flow4":
            proto = 4
            use_v4 = True
            out.write("if (eth_proto == htons(ETH_P_IP)) { \\\n")
            out.write("\tdo {\\\n")
        elif t[0].strip() == "flow6":
            proto = 6
            use_v6 = True
            out.write("if (eth_proto == htons(ETH_P_IPV6)) { \\\n")
            out.write("\tdo {\\\n")
        else:
            continue

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
        out.write(f"\t\tconst uint32_t ruleidx = STATIC_RULE_CNT + {rulecnt};\\\n")
        out.write("\t\tDO_RETURN(ruleidx, XDP_DROP);\\\n")
        out.write("\t} while(0);\\\n}\\\n")
        rulecnt += 1

    out.write("\n")
    out.write(f"#define RULECNT {rulecnt}\n")
    if use_v4:
        out.write("#define NEED_V4_PARSE\n")
    if use_v6:
        out.write("#define NEED_V6_PARSE\n")
    if args.v6frag == "ignore-parse-if-rule":
        if use_v6_frags:
            out.write("#define PARSE_V6_FRAG PARSE\n")
