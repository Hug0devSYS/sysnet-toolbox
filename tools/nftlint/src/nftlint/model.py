"""Format-independent ruleset model shared by the nftables and iptables parsers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

from .intervals import IntervalSet

# ---------------------------------------------------------------------------
# Match dimensions
# ---------------------------------------------------------------------------
NFPROTO = "nfproto"  # 0 = IPv4, 1 = IPv6
L4PROTO = "l4proto"  # IP protocol number
SPORT = "sport"
DPORT = "dport"
SADDR4 = "saddr4"
DADDR4 = "daddr4"
SADDR6 = "saddr6"
DADDR6 = "daddr6"
CTSTATE = "ctstate"

CT_STATES = ("new", "established", "related", "invalid", "untracked")

BOUNDS: Dict[str, Tuple[int, int]] = {
    NFPROTO: (0, 1),
    L4PROTO: (0, 255),
    SPORT: (0, 65535),
    DPORT: (0, 65535),
    SADDR4: (0, 2**32 - 1),
    DADDR4: (0, 2**32 - 1),
    SADDR6: (0, 2**128 - 1),
    DADDR6: (0, 2**128 - 1),
    CTSTATE: (0, len(CT_STATES) - 1),
}

ADDRESS_DIMS = (SADDR4, DADDR4, SADDR6, DADDR6)
SOURCE_DIMS = (SADDR4, SADDR6)
FAMILY_OF_DIM = {SADDR4: 0, DADDR4: 0, SADDR6: 1, DADDR6: 1}

IPV4, IPV6 = 0, 1
FAMILY_NAMES = {IPV4: "IPv4", IPV6: "IPv6"}

# nftables table family -> nfproto values the table sees.
TABLE_FAMILIES: Dict[str, FrozenSet[int]] = {
    "ip": frozenset({IPV4}),
    "ip6": frozenset({IPV6}),
    "inet": frozenset({IPV4, IPV6}),
}

# Opaque token that an initial TCP SYN always satisfies (``--syn``,
# ``tcp flags syn``); used by the exposure simulation.
TCP_SYN = "tcp-syn"

ICMP_PROTOS = frozenset({1, 58})


def universe(dim: str) -> IntervalSet:
    lo, hi = BOUNDS[dim]
    return IntervalSet.full(lo, hi)


def nothing(dim: str) -> IntervalSet:
    lo, hi = BOUNDS[dim]
    return IntervalSet.empty(lo, hi)


def values(dim: str, *vals: int) -> IntervalSet:
    lo, hi = BOUNDS[dim]
    return IntervalSet(lo, hi, [(v, v) for v in vals])


def span(dim: str, a: int, b: int) -> IntervalSet:
    lo, hi = BOUNDS[dim]
    return IntervalSet(lo, hi, [(a, b)])


# ---------------------------------------------------------------------------
# Interface matching
# ---------------------------------------------------------------------------
def _pattern_covers(outer: str, inner: str) -> bool:
    """True if every name matched by ``inner`` is matched by ``outer``.

    Patterns ending in ``*`` are prefix wildcards (``eth*``); iptables'
    ``eth+`` is normalised to ``eth*`` by the parser.
    """
    if outer.endswith("*"):
        return inner.rstrip("*").startswith(outer[:-1])
    return not inner.endswith("*") and inner == outer


def _patterns_overlap(a: str, b: str) -> bool:
    if a.endswith("*") and b.endswith("*"):
        pa, pb = a[:-1], b[:-1]
        return pa.startswith(pb) or pb.startswith(pa)
    if a.endswith("*"):
        return b.startswith(a[:-1])
    if b.endswith("*"):
        return a.startswith(b[:-1])
    return a == b


@dataclass(frozen=True)
class IfaceMatch:
    patterns: FrozenSet[str]
    negated: bool = False

    def matches_name(self, name: str) -> bool:
        hit = any(_pattern_covers(p, name) for p in self.patterns)
        return hit != self.negated

    def only_loopback(self) -> bool:
        return not self.negated and self.patterns == frozenset({"lo"})

    def issubset(self, outer: Optional[IfaceMatch]) -> bool:
        """``self`` (inner) matches a subset of what ``outer`` matches."""
        if outer is None:
            return True
        if not self.negated and not outer.negated:
            return all(any(_pattern_covers(o, i) for o in outer.patterns) for i in self.patterns)
        if self.negated and outer.negated:
            return all(any(_pattern_covers(i, o) for i in self.patterns) for o in outer.patterns)
        if not self.negated and outer.negated:
            return not any(_patterns_overlap(i, o) for i in self.patterns for o in outer.patterns)
        return False

    def render(self) -> str:
        names = sorted(self.patterns)
        body = names[0] if len(names) == 1 else "{ " + ", ".join(names) + " }"
        return ("!= " if self.negated else "") + body


# ---------------------------------------------------------------------------
# Match, verdicts, rules
# ---------------------------------------------------------------------------
@dataclass
class Match:
    dims: Dict[str, IntervalSet] = field(default_factory=dict)
    ifaces: Dict[str, IfaceMatch] = field(default_factory=dict)  # keys: "iif", "oif"
    opaque: FrozenSet[str] = frozenset()

    def constrain(self, dim: str, iset: IntervalSet) -> None:
        cur = self.dims.get(dim)
        self.dims[dim] = iset if cur is None else cur & iset

    def constrain_iface(self, key: str, m: IfaceMatch) -> None:
        if key in self.ifaces:
            # Two constraints on the same interface: keep it exact by making
            # the combination opaque rather than guessing.
            self.add_opaque(f"{key} {self.ifaces[key].render()} && {m.render()}")
            return
        self.ifaces[key] = m

    def add_opaque(self, text: str) -> None:
        self.opaque = self.opaque | {text}

    def impossible(self) -> bool:
        return any(s.is_empty() for s in self.dims.values())

    def is_universal(self) -> bool:
        return all(s.is_full() for s in self.dims.values()) and not self.ifaces and not self.opaque

    def get(self, dim: str) -> IntervalSet:
        return self.dims.get(dim) or universe(dim)

    def constrained(self, dim: str) -> bool:
        s = self.dims.get(dim)
        return s is not None and not s.is_full()

    def covers(self, inner: Match) -> bool:
        """True if every packet matched by ``inner`` is matched by ``self``."""
        if inner.impossible():
            return True
        for dim, outer_set in self.dims.items():
            if not inner.get(dim).issubset(outer_set):
                return False
        for key, outer_if in self.ifaces.items():
            inner_if = inner.ifaces.get(key)
            if inner_if is None or not inner_if.issubset(outer_if):
                return False
        return self.opaque <= inner.opaque


TERMINAL = frozenset({"accept", "drop", "reject", "goto", "return", "queue", "nat"})
DENY = frozenset({"drop", "reject"})


@dataclass(frozen=True)
class Verdict:
    kind: str  # accept|drop|reject|jump|goto|return|continue|queue|nat|vmap|none
    target: Optional[str] = None

    @property
    def terminal(self) -> bool:
        return self.kind in TERMINAL

    @property
    def klass(self) -> str:
        if self.kind in DENY:
            return "deny"
        if self.kind == "accept":
            return "allow"
        return self.kind

    def render(self) -> str:
        if self.kind in ("jump", "goto"):
            return f"{self.kind} {self.target}"
        return self.kind


NO_VERDICT = Verdict("none")


@dataclass
class VMap:
    """Verdict map. ``dim`` is None when the key is not modelled."""

    dim: Optional[str]
    entries: List[Tuple[IntervalSet, Verdict]]
    verdicts: List[Verdict] = field(default_factory=list)  # all verdicts (incl. unmodelled)


@dataclass
class Rule:
    index: int  # 1-based position in its chain
    match: Match
    verdict: Verdict
    text: str
    handle: Optional[int] = None
    line: Optional[int] = None
    vmap: Optional[VMap] = None
    chain: Optional[Chain] = None

    def targets(self) -> List[Tuple[str, str]]:
        """(kind, chain) pairs this rule can transfer control to."""
        out = []
        if self.verdict.kind in ("jump", "goto") and self.verdict.target:
            out.append((self.verdict.kind, self.verdict.target))
        if self.vmap:
            for v in self.vmap.verdicts:
                if v.kind in ("jump", "goto") and v.target:
                    out.append((v.kind, v.target))
        return out

    def location(self) -> str:
        assert self.chain is not None
        loc = f"{self.chain.label()} #{self.index}"
        if self.handle is not None:
            loc += f" (handle {self.handle})"
        elif self.line is not None:
            loc += f" (line {self.line})"
        return loc


HOOK_PRIORITY_IPTABLES = {"raw": -300, "mangle": -150, "nat": -100, "filter": 0, "security": 50}


@dataclass
class Chain:
    source: str
    family: str  # ip | ip6 | inet | arp | bridge | netdev
    table: str
    name: str
    type: Optional[str] = None  # filter | nat | route | (iptables table name)
    hook: Optional[str] = None
    prio: int = 0
    policy: Optional[str] = None  # accept | drop
    rules: List[Rule] = field(default_factory=list)

    @property
    def base(self) -> bool:
        return self.hook is not None

    @property
    def nfprotos(self) -> FrozenSet[int]:
        return TABLE_FAMILIES.get(self.family, frozenset())

    def label(self) -> str:
        return f"{self.family} {self.table} {self.name}"

    def key(self) -> Tuple[str, str, str, str]:
        return (self.source, self.family, self.table, self.name)


@dataclass
class Ruleset:
    chains: Dict[Tuple[str, str, str, str], Chain] = field(default_factory=dict)
    sources: List[Dict[str, object]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)  # parser remarks (per source)
    xt_rules: int = 0

    def add_chain(self, chain: Chain) -> Chain:
        existing = self.chains.get(chain.key())
        if existing is not None:
            return existing
        self.chains[chain.key()] = chain
        return chain

    def resolve(self, chain: Chain, target: str) -> Optional[Chain]:
        return self.chains.get((chain.source, chain.family, chain.table, target))

    def base_chains(self) -> List[Chain]:
        return [c for c in self.chains.values() if c.base]

    def rule_count(self) -> int:
        return sum(len(c.rules) for c in self.chains.values())

    def merge(self, other: Ruleset) -> None:
        for k, c in other.chains.items():
            self.chains[k] = c
        self.sources.extend(other.sources)
        self.notes.extend(other.notes)
        self.xt_rules += other.xt_rules


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
SEVERITIES = ("info", "low", "medium", "high")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    code: str
    title: str
    severity: str
    message: str
    rule: Optional[Rule] = None
    chain: Optional[Chain] = None
    related: Optional[Rule] = None
    extra: Dict[str, object] = field(default_factory=dict)
    subject: Optional[str] = None  # location for findings not tied to a rule/chain

    def location(self) -> str:
        if self.rule is not None:
            return self.rule.location()
        if self.chain is not None:
            return self.chain.label()
        return self.subject or "ruleset"

    def to_dict(self) -> Dict[str, object]:
        d: Dict[str, object] = {
            "code": self.code,
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "location": self.location(),
        }
        chain = self.rule.chain if self.rule is not None else self.chain
        if chain is not None:
            d["source"] = chain.source
            d["family"] = chain.family
            d["table"] = chain.table
            d["chain"] = chain.name
        if self.rule is not None:
            d["rule"] = {
                "index": self.rule.index,
                "handle": self.rule.handle,
                "line": self.rule.line,
                "text": self.rule.text,
            }
        if self.related is not None:
            d["related_rule"] = {
                "location": self.related.location(),
                "text": self.related.text,
            }
        if self.extra:
            d["details"] = self.extra
        return d
