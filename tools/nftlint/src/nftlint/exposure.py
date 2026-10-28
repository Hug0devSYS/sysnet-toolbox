"""Correlate listening sockets (``ss``) with the input filtering path.

For every non-loopback listening socket nftlint builds a synthetic first
packet (conntrack state ``new``, arriving on a non-loopback interface,
destined to the socket's address and port) and runs it symbolically through
every base chain hooked on ``input``. The packet's *source address* is kept
symbolic: each rule splits the remaining source space, so the result is the
exact set of sources that are accepted (``0.0.0.0/0`` → open, a subset →
restricted). Conditions nftlint cannot model (rate limits, marks, dynamic
sets, unknown interfaces, ...) produce "maybe" outcomes that are reported as
*conditional* exposure or as caveats, never silently assumed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .intervals import IntervalSet
from .model import (
    CT_STATES,
    CTSTATE,
    DADDR4,
    DADDR6,
    DPORT,
    FAMILY_NAMES,
    FAMILY_OF_DIM,
    IPV4,
    IPV6,
    L4PROTO,
    NFPROTO,
    SADDR4,
    SADDR6,
    SPORT,
    Chain,
    Finding,
    Match,
    Rule,
    Ruleset,
    Verdict,
    universe,
)
from .nftjson import SYN_TOKENS
from .ss import Listener
from .values import PROTOCOLS, format_addresses, sensitive_for, to_set

YES, NO, MAYBE = "yes", "no", "maybe"
MAX_DEPTH = 32
STATUS_ORDER = ["local", "filtered", "unknown", "conditional", "restricted", "open", "unfiltered"]

# Destinations a packet from the network can plausibly carry when the socket
# is bound to a wildcard address: everything except loopback, "this network"
# and multicast/broadcast/reserved space.
_PLAUSIBLE = {
    IPV4: to_set(DADDR4, [(0, 0xFFFFFFFF)])
    - to_set(DADDR4, [(0x00000000, 0x00FFFFFF), (0x7F000000, 0x7FFFFFFF), (0xE0000000, 0xFFFFFFFF)]),
    IPV6: to_set(DADDR6, [(0, 2**128 - 1)]) - to_set(DADDR6, [(0, 1), (0xFF << 120, 2**128 - 1)]),
}


@dataclass
class Packet:
    family: int
    l4proto: int
    dport: int
    daddr: Optional[int] = None
    ctstate: int = CT_STATES.index("new")

    @property
    def sdim(self) -> str:
        return SADDR4 if self.family == IPV4 else SADDR6

    @property
    def ddim(self) -> str:
        return DADDR4 if self.family == IPV4 else DADDR6


@dataclass
class Flow:
    accepted: IntervalSet
    dropped: IntervalSet
    cont: IntervalSet
    maybe: IntervalSet
    accept_rules: List[Rule] = field(default_factory=list)
    maybe_rules: List[Rule] = field(default_factory=list)
    caveats: List[Rule] = field(default_factory=list)

    @classmethod
    def empty(cls, dim: str) -> Flow:
        e = universe(dim).complement()
        return cls(e, e, e, e)


@dataclass
class FamilyResult:
    family: int
    status: str
    accepted: Optional[IntervalSet] = None
    maybe: Optional[IntervalSet] = None
    via_policy_only: bool = False
    accept_rules: List[Rule] = field(default_factory=list)
    maybe_rules: List[Rule] = field(default_factory=list)
    caveats: List[Rule] = field(default_factory=list)

    def sources(self) -> str:
        if self.accepted is None or self.accepted.is_empty():
            return ""
        return format_addresses(self.accepted, 4 if self.family == IPV4 else 6)

    def to_dict(self) -> Dict[str, object]:
        d: Dict[str, object] = {"family": FAMILY_NAMES[self.family], "status": self.status}
        if self.accepted is not None and not self.accepted.is_empty():
            d["allowed_sources"] = self.sources()
        if self.via_policy_only:
            d["via_default_policy"] = True
        if self.accept_rules:
            d["accepted_by"] = _uniq_locs(self.accept_rules)
        if self.maybe_rules:
            d["conditionally_accepted_by"] = _uniq_locs(self.maybe_rules)
        if self.caveats:
            d["caveats"] = _uniq_locs(self.caveats)
        return d


def _uniq_locs(rules: List[Rule]) -> List[str]:
    out: List[str] = []
    for r in rules:
        loc = f"{r.location()}: {r.text}"
        if loc not in out:
            out.append(loc)
    return out


@dataclass
class Exposure:
    listener: Listener
    results: List[FamilyResult]

    @property
    def status(self) -> str:
        if not self.results:
            return "local"
        return max((r.status for r in self.results), key=STATUS_ORDER.index)

    def to_dict(self) -> Dict[str, object]:
        d = self.listener.to_dict()
        d["status"] = self.status
        d["families"] = [r.to_dict() for r in self.results]
        return d


class Simulator:
    def __init__(self, rs: Ruleset) -> None:
        self.rs = rs

    # -- single match ------------------------------------------------------
    def eval_match(self, m: Match, pkt: Packet) -> Tuple[str, IntervalSet]:
        src = universe(pkt.sdim)
        none = src.complement()
        if m.impossible():
            return NO, none
        state = YES
        concrete = {NFPROTO: pkt.family, L4PROTO: pkt.l4proto, DPORT: pkt.dport, CTSTATE: pkt.ctstate}
        for dim, s in m.dims.items():
            if dim in concrete:
                if not s.contains(concrete[dim]):
                    return NO, none
            elif dim == SPORT:
                if not s.is_full():
                    state = MAYBE
            elif dim in FAMILY_OF_DIM and FAMILY_OF_DIM[dim] != pkt.family:
                if not s.is_full():
                    return NO, none
            elif dim == pkt.sdim:
                src = src & s
            elif dim == pkt.ddim:
                if pkt.daddr is not None:
                    if not s.contains(pkt.daddr):
                        return NO, none
                else:
                    plausible = _PLAUSIBLE[pkt.family]
                    if (s & plausible).is_empty():
                        return NO, none
                    if not plausible.issubset(s):
                        state = MAYBE
        iif = m.ifaces.get("iif")
        if iif is not None:
            if iif.patterns == frozenset({"lo"}):
                if not iif.negated:
                    return NO, none
            else:
                state = MAYBE
        oif = m.ifaces.get("oif")
        if oif is not None and not oif.negated:
            return NO, none  # no output interface on the input path
        for tok in m.opaque:
            if tok in SYN_TOKENS and pkt.l4proto == PROTOCOLS["tcp"]:
                continue
            state = MAYBE
        if src.is_empty():
            return NO, none
        return state, src

    # -- chains ------------------------------------------------------------
    def eval_chain(self, chain: Chain, pkt: Packet, region: IntervalSet, depth: int = 0) -> Flow:
        flow = Flow.empty(pkt.sdim)
        if depth > MAX_DEPTH:
            flow.cont = region
            return flow
        remaining = region
        for rule in chain.rules:
            if remaining.is_empty():
                break
            state, src = self.eval_match(rule.match, pkt)
            if state == NO:
                continue
            hit = remaining & src
            if hit.is_empty():
                continue
            for piece, verdict, st in self._pieces(rule, pkt, hit, state):
                remaining = self._apply(flow, chain, rule, verdict, st, piece, remaining, pkt, depth)
        flow.cont = flow.cont | remaining
        return flow

    def _pieces(self, rule: Rule, pkt: Packet, hit: IntervalSet, state: str):
        vm = rule.vmap
        if vm is None:
            return [(hit, rule.verdict, state)]
        if vm.dim is None:
            return [(hit, v, MAYBE) for v in vm.verdicts]
        concrete = {NFPROTO: pkt.family, L4PROTO: pkt.l4proto, DPORT: pkt.dport, CTSTATE: pkt.ctstate}
        if vm.dim in concrete:
            for s, v in vm.entries:
                if s.contains(concrete[vm.dim]):
                    return [(hit, v, state)]
            return []
        if vm.dim == pkt.sdim:
            out = []
            rest = hit
            for s, v in vm.entries:
                part = rest & s
                if not part.is_empty():
                    out.append((part, v, state))
                    rest = rest - s
            return out
        return [(hit, v, MAYBE) for _, v in vm.entries]

    def _apply(
        self,
        flow: Flow,
        chain: Chain,
        rule: Rule,
        verdict: Verdict,
        st: str,
        hit: IntervalSet,
        remaining: IntervalSet,
        pkt: Packet,
        depth: int,
    ) -> IntervalSet:
        sure = st == YES
        kind = verdict.kind
        if kind == "accept":
            if sure:
                flow.accepted = flow.accepted | hit
                flow.accept_rules.append(rule)
                return remaining - hit
            flow.maybe = flow.maybe | hit
            flow.maybe_rules.append(rule)
        elif kind in ("drop", "reject"):
            if sure:
                flow.dropped = flow.dropped | hit
                return remaining - hit
            flow.caveats.append(rule)
        elif kind == "queue":
            flow.maybe = flow.maybe | hit
            flow.maybe_rules.append(rule)
            if sure:
                return remaining - hit
        elif kind == "return":
            if sure:
                flow.cont = flow.cont | hit
                return remaining - hit
            flow.caveats.append(rule)
        elif kind in ("jump", "goto") and verdict.target:
            callee = self.rs.resolve(chain, verdict.target)
            if callee is None:
                return remaining
            sub = self.eval_chain(callee, pkt, hit, depth + 1)
            if sure:
                flow.accepted = flow.accepted | sub.accepted
                flow.dropped = flow.dropped | sub.dropped
                flow.maybe = flow.maybe | sub.maybe
                flow.accept_rules += sub.accept_rules
                flow.maybe_rules += sub.maybe_rules
                flow.caveats += sub.caveats
                if kind == "jump":
                    return (remaining - hit) | sub.cont
                flow.cont = flow.cont | sub.cont
                return remaining - hit
            flow.maybe = flow.maybe | sub.accepted | sub.maybe
            flow.maybe_rules += sub.accept_rules + sub.maybe_rules
            flow.caveats += sub.caveats + [rule]
        return remaining

    # -- hook --------------------------------------------------------------
    def input_chains(self, family: int) -> List[Chain]:
        chains = [
            c
            for c in self.rs.base_chains()
            if c.hook == "input" and family in c.nfprotos and c.type in ("filter", None)
        ]
        return sorted(chains, key=lambda c: c.prio)

    def evaluate(self, pkt: Packet) -> FamilyResult:
        chains = self.input_chains(pkt.family)
        if not chains:
            return FamilyResult(pkt.family, "unfiltered")
        region = universe(pkt.sdim)
        none = region.complement()
        maybe = none
        explicit = none
        res = FamilyResult(pkt.family, "filtered")
        for c in chains:
            f = self.eval_chain(c, pkt, region)
            acc = f.accepted | (f.cont if c.policy != "drop" else none)
            explicit = explicit | f.accepted
            if not maybe.is_empty():
                fm = self.eval_chain(c, pkt, maybe)
                maybe = fm.accepted | fm.maybe | (fm.cont if c.policy != "drop" else none)
            maybe = maybe | (f.maybe - acc)
            res.accept_rules += f.accept_rules
            res.maybe_rules += f.maybe_rules
            res.caveats += f.caveats
            region = acc
        res.accepted = region
        res.maybe = maybe - region
        res.via_policy_only = not (region - explicit).is_empty()
        if region.is_full():
            res.status = "open"
        elif not region.is_empty():
            res.status = "restricted"
        elif not res.maybe.is_empty():
            res.status = "conditional"
        # Keep only the rules that matter for the reported outcome.
        if region.is_empty():
            res.accept_rules = []
        return res


def covered_families(rs: Ruleset) -> set:
    if any(s.get("format") == "nft-json" for s in rs.sources):
        return {IPV4, IPV6}
    fams = set()
    for c in rs.chains.values():
        fams |= set(c.nfprotos)
    return fams


def analyse_exposure(rs: Ruleset, listeners: List[Listener]) -> List[Exposure]:
    sim = Simulator(rs)
    covered = covered_families(rs)
    out: List[Exposure] = []
    for lst in listeners:
        if lst.loopback:
            out.append(Exposure(lst, []))
            continue
        results = []
        for fam in lst.families:
            if fam not in covered:
                results.append(FamilyResult(fam, "unknown"))
                continue
            pkt = Packet(fam, PROTOCOLS[lst.proto], lst.port, lst.daddr(fam))
            results.append(sim.evaluate(pkt))
        out.append(Exposure(lst, results))
    return out


def exposure_findings(
    rs: Ruleset, exposures: List[Exposure], listeners: List[Listener], sensitive: Dict[int, str]
) -> List[Finding]:
    findings: List[Finding] = []
    unknown: Dict[int, List[str]] = {}
    for exp in exposures:
        lst = exp.listener
        what = f"{lst.proto}/{lst.port} ({lst.process or 'unknown process'} on {lst.raw_address})"
        for r in exp.results:
            fam = FAMILY_NAMES[r.family]
            wide = (
                r.status == "restricted"
                and r.accepted is not None
                and (r.accepted.size() * 2 > r.accepted.universe_size())
            )
            if r.status in ("open", "unfiltered") or wide:
                if r.status == "unfiltered":
                    why = "no base chain filters this family on the input hook"
                elif r.via_policy_only:
                    why = "only the default accept policy lets it through"
                else:
                    why = "an explicit rule accepts it from any source"
                if wide:
                    why += f" (allowed sources: {r.sources()})"
                if lst.port in sensitive_for(sensitive, lst.proto == "udp"):
                    findings.append(
                        Finding(
                            "NFT008",
                            "exposed-sensitive-service",
                            "high",
                            f"{what} is reachable from {'almost ' if wide else ''}any {fam} source: {why}",
                            extra={"listener": lst.to_dict(), "family": fam},
                            subject=f"socket {lst.proto}/{lst.port} {lst.raw_address}",
                        )
                    )
                elif r.status == "unfiltered" or r.via_policy_only:
                    findings.append(
                        Finding(
                            "NFT011",
                            "exposed-by-default",
                            "medium",
                            f"{what} is reachable from {'almost ' if wide else ''}any {fam} source "
                            f"although no rule allows it: {why}",
                            extra={"listener": lst.to_dict(), "family": fam},
                            subject=f"socket {lst.proto}/{lst.port} {lst.raw_address}",
                        )
                    )
            elif r.status == "unknown":
                unknown.setdefault(r.family, []).append(what)
    for fam, whats in sorted(unknown.items()):
        name = FAMILY_NAMES[fam]
        shown = "; ".join(whats[:6]) + (f"; +{len(whats) - 6} more" if len(whats) > 6 else "")
        findings.append(
            Finding(
                "NFT014",
                "family-not-analysed",
                "medium",
                f"{len(whats)} socket(s) accept {name} traffic but no {name} ruleset was analysed "
                f"(pass the {'ip6tables-save' if fam == IPV6 else 'iptables-save'} output too): " + shown,
                extra={"family": name, "count": len(whats)},
            )
        )
    findings.extend(_stale_openings(rs, listeners))
    return findings


def _stale_openings(rs: Ruleset, listeners: List[Listener]) -> List[Finding]:
    """Input accept rules for ports nothing listens on."""
    listening = {(lst.proto, lst.port) for lst in listeners if not lst.loopback}
    tcp, udp = PROTOCOLS["tcp"], PROTOCOLS["udp"]
    findings: List[Finding] = []
    for chain in rs.base_chains():
        if chain.hook != "input" or chain.type not in ("filter", None):
            continue
        for rule in chain.rules:
            if rule.verdict.kind != "accept" or not rule.match.constrained(DPORT):
                continue
            dports = rule.match.get(DPORT)
            if dports.size() > 64:
                continue
            protos = rule.match.get(L4PROTO)
            names = [n for n, p in (("tcp", tcp), ("udp", udp)) if protos.contains(p)]
            if not names:
                continue
            ports = [p for a, b in dports for p in range(a, b + 1)]
            if any((n, p) in listening for n in names for p in ports):
                continue
            shown = ",".join(str(p) for p in ports[:10]) + ("..." if len(ports) > 10 else "")
            findings.append(
                Finding(
                    "NFT009",
                    "stale-opening",
                    "low",
                    f"rule opens {'/'.join(names)} port(s) {shown} but no socket listens on them "
                    "(remove it unless the service is started on demand or traffic is meant "
                    "for another host)",
                    rule=rule,
                    extra={"ports": ports, "protocols": names},
                )
            )
    return findings


__all__ = ["analyse_exposure", "exposure_findings", "Simulator", "Packet", "Exposure"]
