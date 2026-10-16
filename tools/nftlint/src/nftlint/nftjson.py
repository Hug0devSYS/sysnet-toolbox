"""Parser for ``nft -j list ruleset`` (libnftables JSON schema version 1)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from .intervals import IntervalSet
from .model import (
    BOUNDS,
    CTSTATE,
    DADDR4,
    DADDR6,
    DPORT,
    IPV4,
    IPV6,
    L4PROTO,
    NFPROTO,
    NO_VERDICT,
    SADDR4,
    SADDR6,
    SPORT,
    Chain,
    IfaceMatch,
    Match,
    Rule,
    Ruleset,
    Verdict,
    VMap,
    values,
)
from .values import Unsupported, address_span, protocol_number, scalar_to_int, to_set


class ParseError(Exception):
    pass


TCP_SYN = "tcp flags & (fin|syn|rst|ack) == syn"
TCP_SYN_BIT = "tcp flags syn"
SYN_TOKENS = frozenset({TCP_SYN, TCP_SYN_BIT})

PORT_PROTOCOLS = {"tcp": 6, "udp": 17, "udplite": 136, "sctp": 132, "dccp": 33}
ICMP_PROTOCOLS = {"icmp": (1, IPV4), "icmpv6": (58, IPV6), "igmp": (2, IPV4)}

SIDE_EFFECTS = frozenset(
    {
        "counter",
        "log",
        "mangle",
        "notrack",
        "dup",
        "fwd",
        "set",
        "map",
        "ct helper",
        "ct timeout",
        "ct expectation",
        "secmark",
        "last",
        "flow",
    }
)
CONDITIONS = frozenset({"limit", "quota", "ct count", "meter", "synproxy"})
NAT = frozenset({"snat", "dnat", "masquerade", "redirect", "tproxy"})
VERDICT_KEYS = ("accept", "drop", "reject", "continue", "return", "queue", "jump", "goto")

Left = Tuple[str, Optional[str], List[Tuple[str, IntervalSet]]]


# ---------------------------------------------------------------------------
# Rendering (nft-like text for reports)
# ---------------------------------------------------------------------------
def render_expr(e: Any) -> str:
    if isinstance(e, (int, str)):
        return str(e)
    if isinstance(e, list):
        return ",".join(render_expr(x) for x in e)
    if isinstance(e, dict) and len(e) == 1:
        ((k, v),) = e.items()
        if k == "payload" and isinstance(v, dict):
            if "protocol" in v:
                return f"{v['protocol']} {v['field']}"
            return "@" + ",".join(str(v.get(x, "")) for x in ("base", "offset", "len"))
        if k == "meta" and isinstance(v, dict):
            key = v.get("key")
            return key if key in ("iifname", "oifname", "iif", "oif", "mark") else f"meta {key}"
        if k == "ct" and isinstance(v, dict):
            return f"ct {v.get('key')}"
        if k == "set":
            return "{ " + ", ".join(render_expr(x) for x in v) + " }"
        if k == "range":
            return f"{render_expr(v[0])}-{render_expr(v[1])}"
        if k == "prefix":
            return f"{v['addr']}/{v['len']}"
        if k == "concat":
            return " . ".join(render_expr(x) for x in v)
        if k in ("&", "|", "^", "<<", ">>"):
            return f"{render_expr(v[0])} {k} {render_expr(v[1])}"
        if k == "elem" and isinstance(v, dict):
            return render_expr(v.get("val"))
        if k == "fib" and isinstance(v, dict):
            return f"fib {' . '.join(v.get('flags', []))} {v.get('result', '')}".strip()
    return json.dumps(e, separators=(",", ":"), sort_keys=True)


def render_stmt(stmt: Dict[str, Any]) -> str:
    ((k, v),) = stmt.items()
    if k == "match":
        op = v.get("op", "==")
        ops = "" if op in ("==", "in") else f"{op} "
        return f"{render_expr(v['left'])} {ops}{render_expr(v['right'])}"
    if k in ("jump", "goto"):
        return f"{k} {v.get('target')}"
    if k == "vmap":
        pairs = v.get("data")
        if isinstance(pairs, dict) and "set" in pairs:
            body = ", ".join(
                f"{render_expr(p[0])} : {render_stmt(p[1])}" for p in pairs["set"] if len(p) == 2
            )
            pairs = "{ " + body + " }"
        else:
            pairs = render_expr(pairs)
        return f"{render_expr(v['key'])} vmap {pairs}"
    if k == "log" and isinstance(v, dict) and "prefix" in v:
        return f'log prefix "{v["prefix"]}"'
    if k == "limit" and isinstance(v, dict):
        return f"limit rate {v.get('rate')}/{v.get('per')}"
    if k == "reject" and isinstance(v, dict) and v.get("expr"):
        return f"reject with {v.get('type', '')} {v['expr']}".replace("  ", " ")
    if v is None or k in ("counter", "log", "reject", "notrack", "masquerade"):
        return k
    return f"{k} {render_expr(v)}"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
class NftJsonParser:
    def __init__(self, source: str) -> None:
        self.source = source
        self.sets: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self.ruleset = Ruleset()
        self.opaque_examples: Dict[str, int] = {}

    def parse(self, text: str) -> Ruleset:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"{self.source}: invalid JSON: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
            raise ParseError(f"{self.source}: not an 'nft -j list ruleset' document")
        objs = data["nftables"]
        for o in objs:
            if not isinstance(o, dict):
                continue
            for kind in ("set", "map"):
                s = o.get(kind)
                if isinstance(s, dict):
                    self.sets[(s.get("family"), s.get("table"), s.get("name"))] = s
        tables = set()
        for o in objs:
            if not isinstance(o, dict):
                continue
            if "table" in o and isinstance(o["table"], dict):
                tables.add((o["table"].get("family"), o["table"].get("name")))
            elif "chain" in o and isinstance(o["chain"], dict):
                self._chain(o["chain"])
            elif "rule" in o and isinstance(o["rule"], dict):
                self._rule(o["rule"])
        rs = self.ruleset
        rs.sources.append(
            {
                "path": self.source,
                "format": "nft-json",
                "tables": len(tables),
                "chains": len(rs.chains),
                "rules": rs.rule_count(),
            }
        )
        if self.opaque_examples:
            top = sorted(self.opaque_examples.items(), key=lambda kv: -kv[1])[:5]
            rs.notes.append(
                f"{self.source}: {sum(self.opaque_examples.values())} expression(s) are not "
                "modelled and are handled conservatively (e.g. " + ", ".join(f"`{k}`" for k, _ in top) + ")"
            )
        return rs

    # -- chains -------------------------------------------------------------
    def _chain(self, c: Dict[str, Any]) -> Chain:
        chain = Chain(
            source=self.source,
            family=str(c.get("family")),
            table=str(c.get("table")),
            name=str(c.get("name")),
            type=c.get("type"),
            hook=c.get("hook"),
            prio=_int(c.get("prio"), 0),
            policy=c.get("policy") or ("accept" if c.get("hook") else None),
        )
        existing = self.ruleset.chains.get(chain.key())
        if existing is not None:
            existing.type, existing.hook = chain.type, chain.hook
            existing.prio, existing.policy = chain.prio, chain.policy
            return existing
        return self.ruleset.add_chain(chain)

    def _rule(self, r: Dict[str, Any]) -> None:
        chain = self.ruleset.chains.get(
            (self.source, str(r.get("family")), str(r.get("table")), str(r.get("chain")))
        )
        if chain is None:
            chain = self._chain({"family": r.get("family"), "table": r.get("table"), "name": r.get("chain")})
        b = _RuleBuilder(self, chain.family, chain.table)
        for stmt in r.get("expr") or []:
            if isinstance(stmt, dict) and len(stmt) == 1:
                b.statement(stmt)
            else:
                b.opaque(json.dumps(stmt, separators=(",", ":")))
        text = " ".join(b.parts) or "(empty rule)"
        if r.get("comment"):
            text += f' comment "{r["comment"]}"'
        rule = Rule(
            index=len(chain.rules) + 1,
            match=b.match,
            verdict=b.verdict,
            text=text,
            handle=_int(r.get("handle"), None),
            vmap=b.vmap,
            chain=chain,
        )
        if b.xt:
            self.ruleset.xt_rules += 1
        chain.rules.append(rule)

    # -- sets -----------------------------------------------------------------
    def set_elements(self, family: str, table: str, name: str) -> List[Any]:
        s = self.sets.get((family, table, name))
        if s is None:
            raise Unsupported(f"unknown set @{name}")
        flags = s.get("flags") or []
        if isinstance(flags, str):
            flags = [flags]
        if "dynamic" in flags or "timeout" in flags or "timeout" in s:
            raise Unsupported(f"set @{name} is dynamic")
        elems = s.get("elem") or []
        return elems if isinstance(elems, list) else [elems]


class _RuleBuilder:
    def __init__(self, parser: NftJsonParser, family: str, table: str) -> None:
        self.p = parser
        self.family = family
        self.table = table
        self.match = Match()
        self.verdict = NO_VERDICT
        self.vmap: Optional[VMap] = None
        self.parts: List[str] = []
        self.xt = False

    def opaque(self, text: str) -> None:
        self.match.add_opaque(text)
        self.p.opaque_examples[text] = self.p.opaque_examples.get(text, 0) + 1

    def statement(self, stmt: Dict[str, Any]) -> None:
        ((k, v),) = stmt.items()
        try:
            rendered = render_stmt(stmt)
        except (KeyError, TypeError, IndexError):
            rendered = json.dumps(stmt, separators=(",", ":"))
        self.parts.append(rendered)
        if k == "match" and isinstance(v, dict):
            self._match(v, rendered)
        elif k in VERDICT_KEYS:
            target = v.get("target") if isinstance(v, dict) else None
            self.verdict = Verdict(k, target)
        elif k == "vmap" and isinstance(v, dict):
            self._vmap(v, rendered)
        elif k in NAT:
            self.verdict = Verdict("nat")
        elif k == "xt":
            self.xt = True
            if not (isinstance(v, dict) and v.get("type") == "target"):
                self.opaque(rendered)
        elif k in SIDE_EFFECTS:
            pass
        elif k in CONDITIONS:
            self.opaque(rendered)
        else:
            self.opaque(rendered)

    # -- left-hand side ---------------------------------------------------------
    def _left(self, left: Any) -> Optional[Left]:
        """Classify a match's left side as ('dim', dim, implied), ('iface', key, [])
        or ('implied', None, implied). None means not modelled."""
        if not isinstance(left, dict) or len(left) != 1:
            return None
        ((k, v),) = left.items()
        if not isinstance(v, dict):
            return None
        if k == "payload":
            proto, fld = v.get("protocol"), v.get("field")
            if proto == "ip":
                imp = [(NFPROTO, values(NFPROTO, IPV4))]
                dim = {"saddr": SADDR4, "daddr": DADDR4, "protocol": L4PROTO}.get(fld)
                return ("dim", dim, imp) if dim else ("implied", None, imp)
            if proto == "ip6":
                imp = [(NFPROTO, values(NFPROTO, IPV6))]
                dim = {"saddr": SADDR6, "daddr": DADDR6, "nexthdr": L4PROTO}.get(fld)
                return ("dim", dim, imp) if dim else ("implied", None, imp)
            if proto in PORT_PROTOCOLS:
                imp = [(L4PROTO, values(L4PROTO, PORT_PROTOCOLS[proto]))]
                dim = {"sport": SPORT, "dport": DPORT}.get(fld)
                return ("dim", dim, imp) if dim else ("implied", None, imp)
            if proto == "th":
                dim = {"sport": SPORT, "dport": DPORT}.get(fld)
                return ("dim", dim, []) if dim else None
            if proto in ICMP_PROTOCOLS:
                num, fam = ICMP_PROTOCOLS[proto]
                return ("implied", None, [(L4PROTO, values(L4PROTO, num)), (NFPROTO, values(NFPROTO, fam))])
            return None
        if k == "meta":
            key = v.get("key")
            if key == "l4proto":
                return ("dim", L4PROTO, [])
            if key == "nfproto":
                return ("dim", NFPROTO, [])
            if key in ("iifname", "iif"):
                return ("iface", "iif", [])
            if key in ("oifname", "oif"):
                return ("iface", "oif", [])
            return None
        if k == "ct" and v.get("key") == "state" and "dir" not in v:
            return ("dim", CTSTATE, [])
        return None

    def _match(self, m: Dict[str, Any], rendered: str) -> None:
        left, right, op = m.get("left"), m.get("right"), m.get("op", "==")
        if _is_tcp_syn(left, right, op):
            self.match.constrain(L4PROTO, values(L4PROTO, 6))
            self.match.add_opaque(TCP_SYN_BIT if _is_flags(left) else TCP_SYN)
            return
        cls = self._left(left)
        if cls is None:
            self.opaque(rendered)
            return
        kind, dim, implied = cls
        for idim, iset in implied:
            self.match.constrain(idim, iset)
        if kind == "implied":
            self.opaque(rendered)
            return
        try:
            if kind == "iface":
                names = self._names(right)
                if op not in ("==", "!=", "in"):
                    raise Unsupported(op)
                self.match.constrain_iface(dim, IfaceMatch(frozenset(names), negated=op == "!="))
                return
            assert dim is not None
            self.match.constrain(dim, self._set(dim, right, op))
        except (Unsupported, ValueError, KeyError, TypeError, IndexError):
            self.opaque(rendered)

    def _set(self, dim: str, right: Any, op: str) -> IntervalSet:
        if op in ("==", "in"):
            return to_set(dim, self._spans(dim, right))
        if op == "!=":
            return to_set(dim, self._spans(dim, right)).complement()
        if op in ("<", "<=", ">", ">=") and dim not in (SADDR4, SADDR6, DADDR4, DADDR6):
            n = scalar_to_int(dim, right)
            hi = BOUNDS[dim][1]
            spans = {
                "<": (0, n - 1),
                "<=": (0, n),
                ">": (n + 1, hi),
                ">=": (n, hi),
            }[op]
            return to_set(dim, [spans])
        raise Unsupported(f"operator {op}")

    def _spans(self, dim: str, right: Any) -> List[Tuple[int, int]]:
        addr = dim in (SADDR4, SADDR6, DADDR4, DADDR6)
        if isinstance(right, bool):
            raise Unsupported("boolean value")
        if isinstance(right, str) and right.startswith("@"):
            out: List[Tuple[int, int]] = []
            for e in self.p.set_elements(self.family, self.table, right[1:]):
                out.extend(self._spans(dim, e))
            return out
        if isinstance(right, (int, str)):
            if addr:
                return [address_span(dim, str(right))]
            n = scalar_to_int(dim, right)
            return [(n, n)]
        if isinstance(right, list):
            out = []
            for e in right:
                out.extend(self._spans(dim, e))
            return out
        if isinstance(right, dict) and len(right) == 1:
            ((k, v),) = right.items()
            if k == "set":
                return self._spans(dim, v)
            if k == "elem" and isinstance(v, dict):
                return self._spans(dim, v.get("val"))
            if k == "range" and isinstance(v, list) and len(v) == 2:
                if addr:
                    return [(address_span(dim, str(v[0]))[0], address_span(dim, str(v[1]))[1])]
                return [(scalar_to_int(dim, v[0]), scalar_to_int(dim, v[1]))]
            if k == "prefix" and addr and isinstance(v, dict):
                return [address_span(dim, f"{v['addr']}/{v['len']}")]
        raise Unsupported(f"value {right!r}")

    def _names(self, right: Any) -> List[str]:
        if isinstance(right, str):
            if right.startswith("@"):
                out = []
                for e in self.p.set_elements(self.family, self.table, right[1:]):
                    out.extend(self._names(e))
                return out
            return [right.replace("\\*", "*")]
        if isinstance(right, list):
            return [n for e in right for n in self._names(e)]
        if isinstance(right, dict) and "set" in right:
            return self._names(right["set"])
        if isinstance(right, dict) and "elem" in right:
            return self._names(right["elem"].get("val"))
        raise Unsupported(f"interface value {right!r}")

    # -- verdict maps -------------------------------------------------------
    def _vmap(self, v: Dict[str, Any], rendered: str) -> None:
        data = v.get("data")
        pairs: List[Any] = []
        try:
            if isinstance(data, dict) and isinstance(data.get("set"), list):
                pairs = data["set"]
            elif isinstance(data, str) and data.startswith("@"):
                pairs = self.p.set_elements(self.family, self.table, data[1:])
            else:
                raise Unsupported("vmap data")
        except Unsupported:
            self.verdict = Verdict("vmap")
            self.vmap = VMap(None, [], [])
            self.opaque(rendered)
            return
        verdicts: List[Verdict] = []
        raw: List[Tuple[Any, Verdict]] = []
        for p in pairs:
            if not (isinstance(p, list) and len(p) == 2 and isinstance(p[1], dict) and len(p[1]) == 1):
                continue
            ((vk, vv),) = p[1].items()
            if vk not in VERDICT_KEYS:
                continue
            verd = Verdict(vk, vv.get("target") if isinstance(vv, dict) else None)
            verdicts.append(verd)
            raw.append((p[0], verd))
        cls = self._left(v.get("key"))
        dim = cls[1] if cls and cls[0] == "dim" else None
        entries: List[Tuple[IntervalSet, Verdict]] = []
        if dim is not None:
            assert cls is not None
            for idim, iset in cls[2]:
                self.match.constrain(idim, iset)
            try:
                for key, verd in raw:
                    entries.append((to_set(dim, self._spans(dim, key)), verd))
            except (Unsupported, ValueError, KeyError, TypeError, IndexError):
                dim, entries = None, []
        self.verdict = Verdict("vmap")
        self.vmap = VMap(dim, entries, verdicts)


def _is_flags(left: Any) -> bool:
    return isinstance(left, dict) and left.get("payload") == {"protocol": "tcp", "field": "flags"}


def _is_tcp_syn(left: Any, right: Any, op: str) -> bool:
    if op not in ("==", "in") or right != "syn":
        return False
    if _is_flags(left):
        return op == "in"
    if isinstance(left, dict) and isinstance(left.get("&"), list) and len(left["&"]) == 2:
        lhs, mask = left["&"]
        if not _is_flags(lhs):
            return False
        names = mask if isinstance(mask, list) else [mask]
        if isinstance(mask, dict) and "|" in mask:
            names = _flatten_or(mask)
        return set(names) == {"fin", "syn", "rst", "ack"}
    return False


def _flatten_or(e: Any) -> List[Any]:
    if isinstance(e, dict) and "|" in e:
        return [x for part in e["|"] for x in _flatten_or(part)]
    return [e]


def _int(v: Any, default: Any) -> Any:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def parse_nft_json(text: str, source: str) -> Ruleset:
    return NftJsonParser(source).parse(text)


__all__ = ["ParseError", "parse_nft_json", "SYN_TOKENS", "TCP_SYN", "protocol_number"]
