"""Static ruleset checks: shadowing, reachability, permissive rules and policies."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from .model import (
    CT_STATES,
    CTSTATE,
    DADDR4,
    DADDR6,
    DPORT,
    FAMILY_NAMES,
    ICMP_PROTOS,
    IPV4,
    IPV6,
    L4PROTO,
    SADDR4,
    SADDR6,
    SOURCE_DIMS,
    SPORT,
    Chain,
    Finding,
    Rule,
    Ruleset,
    values,
)
from .values import format_ports, sensitive_for

IPPROTO_UDP = 17

FILTER_HOOKS = ("input", "forward")
MAX_DEPTH = 32


def _is_nat_context(chain: Chain) -> bool:
    return chain.type == "nat"


def reachable_chains(rs: Ruleset) -> Dict[Tuple[str, str, str, str], Set[str]]:
    """Map every reachable chain key to the set of base-chain types reaching it."""
    seen: Dict[Tuple[str, str, str, str], Set[str]] = {}
    stack: List[Tuple[Chain, str]] = [(c, c.type or "filter") for c in rs.base_chains()]
    while stack:
        chain, ctx = stack.pop()
        ctxs = seen.setdefault(chain.key(), set())
        if ctx in ctxs:
            continue
        ctxs.add(ctx)
        for rule in chain.rules:
            for _, target in rule.targets():
                callee = rs.resolve(chain, target)
                if callee is not None:
                    stack.append((callee, ctx))
    return seen


def check_references(rs: Ruleset, reach) -> List[Finding]:
    findings: List[Finding] = []
    referenced: Set[Tuple[str, str, str, str]] = set()
    for chain in rs.chains.values():
        for rule in chain.rules:
            for _, target in rule.targets():
                callee = rs.resolve(chain, target)
                if callee is None:
                    findings.append(
                        Finding(
                            "NFT013",
                            "undefined-chain",
                            "medium",
                            f"rule jumps to chain '{target}' which does not exist in "
                            f"table {chain.family} {chain.table}",
                            rule=rule,
                        )
                    )
                else:
                    referenced.add(callee.key())
    for chain in rs.chains.values():
        if chain.base or chain.key() in reach:
            continue
        why = (
            "is never referenced by a jump/goto"
            if chain.key() not in referenced
            else "is only referenced from chains that are themselves unreachable"
        )
        findings.append(
            Finding(
                "NFT004",
                "unreachable-chain",
                "low",
                f"regular chain {why}; its {len(chain.rules)} rule(s) never see traffic",
                chain=chain,
            )
        )
    return findings


def check_shadowing(chain: Chain) -> List[Finding]:
    findings: List[Finding] = []
    earlier: List[Rule] = []
    for idx, rule in enumerate(chain.rules):
        if rule.match.impossible():
            findings.append(
                Finding(
                    "NFT003",
                    "unreachable-rule",
                    "medium",
                    "rule can never match: its conditions are contradictory "
                    "(e.g. an IPv4 address match together with an IPv6 one)",
                    rule=rule,
                )
            )
            continue
        cover: Optional[Rule] = None
        for prev in earlier:
            if prev.match.covers(rule.match):
                cover = prev
                break
        if cover is not None and cover.match.is_universal():
            rest = chain.rules[idx:]
            findings.append(
                Finding(
                    "NFT003",
                    "unreachable-rule",
                    "medium",
                    (
                        f"rule #{rule.index} is never evaluated"
                        if len(rest) == 1
                        else f"{len(rest)} rules from #{rule.index} to #{rest[-1].index} are never evaluated"
                    )
                    + f": #{cover.index} `{cover.text}` matches every packet first",
                    rule=rule,
                    related=cover,
                    extra={"count": len(rest)},
                )
            )
            break
        if cover is not None:
            terminal = rule.verdict.terminal
            conflict = terminal and rule.verdict.klass != cover.verdict.klass
            if conflict:
                findings.append(
                    Finding(
                        "NFT001",
                        "shadowed-rule",
                        "high",
                        f"rule never matches: every packet it targets is already handled by "
                        f"#{cover.index} `{cover.text}` with a different verdict "
                        f"({cover.verdict.render()} instead of {rule.verdict.render()})",
                        rule=rule,
                        related=cover,
                    )
                )
            elif rule.verdict.kind in ("jump", "goto", "vmap"):
                findings.append(
                    Finding(
                        "NFT001",
                        "shadowed-rule",
                        "medium",
                        f"rule never matches: every packet it targets is already handled by "
                        f"#{cover.index} `{cover.text}` ({cover.verdict.render()}), so "
                        f"`{rule.verdict.render()}` is never taken",
                        rule=rule,
                        related=cover,
                    )
                )
            else:
                findings.append(
                    Finding(
                        "NFT002",
                        "redundant-rule",
                        "low",
                        f"rule is redundant: fully covered by #{cover.index} `{cover.text}` "
                        f"({cover.verdict.render()}), it can be removed",
                        rule=rule,
                        related=cover,
                    )
                )
            continue
        if rule.verdict.terminal:
            earlier.append(rule)
    return findings


def _source_is_wide(rule: Rule) -> bool:
    for dim in SOURCE_DIMS:
        s = rule.match.dims.get(dim)
        if s is not None and s.size() * 2 < s.universe_size():
            return False
    return True


def _iface_scope(rule: Rule) -> Tuple[bool, Optional[str]]:
    """(loopback_only, description of an interface restriction)."""
    descs = []
    for key in ("iif", "oif"):
        m = rule.match.ifaces.get(key)
        if m is None:
            continue
        if key == "iif" and m.only_loopback():
            return True, None
        if not m.negated:
            descs.append(f"{key} {m.render()}")
    return False, (", ".join(descs) or None)


def _accepts_new(rule: Rule) -> bool:
    ct = rule.match.dims.get(CTSTATE)
    if ct is None:
        return True
    return ct.contains(CT_STATES.index("new")) or ct.contains(CT_STATES.index("untracked"))


def check_permissive_rules(chain: Chain, sensitive: Dict[int, str]) -> List[Finding]:
    """any-any accepts and sensitive services open to any source (base chains only)."""
    findings: List[Finding] = []
    if chain.hook not in FILTER_HOOKS or chain.type not in ("filter", None):
        return findings
    for rule in chain.rules:
        if rule.verdict.kind != "accept" or rule.match.impossible() or rule.match.opaque:
            continue
        if not _accepts_new(rule):
            continue
        lo_only, iface = _iface_scope(rule)
        if lo_only:
            continue
        m = rule.match
        proto = m.dims.get(L4PROTO)
        if proto is not None and proto.issubset(_icmp_set(proto)):
            continue
        no_tuple = not any(m.constrained(d) for d in (SADDR4, SADDR6, DADDR4, DADDR6, DPORT, SPORT))
        if no_tuple:
            what = "all traffic"
            if proto is not None and not proto.is_full():
                what = "all traffic of the matched protocol(s)"
            if iface:
                findings.append(
                    Finding(
                        "NFT005",
                        "any-any-accept",
                        "low",
                        f"accepts {what} restricted only by interface ({iface}); make sure that "
                        "interface is fully trusted",
                        rule=rule,
                    )
                )
            else:
                findings.append(
                    Finding(
                        "NFT005",
                        "any-any-accept",
                        "high",
                        f"accepts {what} from any source to any destination/port on hook {chain.hook}",
                        rule=rule,
                    )
                )
            continue
        if chain.hook != "input" or not m.constrained(DPORT) or not _source_is_wide(rule):
            continue
        dports = m.get(DPORT)
        udp_only = proto is not None and proto.issubset(values(L4PROTO, IPPROTO_UDP))
        relevant = sensitive_for(sensitive, udp_only)
        hits = sorted(p for p in relevant if dports.contains(p))
        if not hits or dports.size() > 4096:
            continue
        names = ", ".join(f"{p}/{relevant[p]}" for p in hits[:8])
        findings.append(
            Finding(
                "NFT007",
                "sensitive-port-open",
                "low" if iface else "medium",
                f"management/data service port(s) {names} accepted from any source"
                + (f" (only via {iface})" if iface else "")
                + "; restrict to an admin network or allow-list set",
                rule=rule,
                extra={"ports": hits},
            )
        )
    return findings


def _icmp_set(proto):
    return values(L4PROTO, *sorted(ICMP_PROTOS))


def _ends_restrictive(rs: Ruleset, chain: Chain, depth: int = 0) -> bool:
    """True if every packet that reaches the end of ``chain`` is denied."""
    if depth > MAX_DEPTH:
        return False
    for rule in chain.rules:
        if not rule.match.is_universal():
            continue
        if rule.verdict.kind in ("drop", "reject"):
            return True
        if rule.verdict.kind in ("jump", "goto") and rule.verdict.target:
            callee = rs.resolve(chain, rule.verdict.target)
            if callee is not None and _ends_restrictive(rs, callee, depth + 1):
                return True
        if rule.verdict.terminal:
            return False
    return chain.base and chain.policy == "drop"


def check_policies(rs: Ruleset) -> List[Finding]:
    findings: List[Finding] = []
    nft_present = any(s.get("format") == "nft-json" for s in rs.sources)
    flagged: Dict[Tuple[str, str, str, str], List[str]] = {}
    for hook in FILTER_HOOKS:
        for fam in (IPV4, IPV6):
            chains = [
                c
                for c in rs.base_chains()
                if c.hook == hook and fam in c.nfprotos and c.type in ("filter", None)
            ]
            if not chains:
                if hook == "input" and fam == IPV6 and nft_present and _has_hook(rs, "input", IPV4):
                    findings.append(
                        Finding(
                            "NFT010",
                            "no-ipv6-filtering",
                            "medium",
                            "IPv4 input traffic is filtered but no base chain filters IPv6 input "
                            "(use an 'inet' table or add an 'ip6' table): if IPv6 is enabled, "
                            "every IPv6 service is reachable",
                        )
                    )
                continue
            if any(_ends_restrictive(rs, c) for c in chains):
                continue
            for c in chains:
                flagged.setdefault(c.key(), []).append(FAMILY_NAMES[fam])
    for key, fams in flagged.items():
        c = rs.chains[key]
        findings.append(
            Finding(
                "NFT006",
                "permissive-policy",
                "high" if c.hook == "input" else "medium",
                f"base chain on hook {c.hook} ({'+'.join(fams)}) has policy "
                f"{c.policy or 'accept'} and no catch-all drop/reject, and no other base chain "
                "on that hook denies by default: anything not explicitly dropped is accepted"
                + (" (harmless only if IP forwarding is disabled)" if c.hook == "forward" else ""),
                chain=c,
                extra={"families": fams},
            )
        )
    return findings


def _has_hook(rs: Ruleset, hook: str, fam: int) -> bool:
    return any(c.hook == hook and fam in c.nfprotos for c in rs.base_chains())


def run_static_checks(rs: Ruleset, sensitive: Dict[int, str]) -> List[Finding]:
    findings: List[Finding] = []
    reach = reachable_chains(rs)
    findings.extend(check_references(rs, reach))
    for chain in rs.chains.values():
        ctxs = reach.get(chain.key(), {chain.type or "filter"})
        if ctxs and all(c == "nat" for c in ctxs):
            continue
        findings.extend(check_shadowing(chain))
        if chain.base:
            findings.extend(check_permissive_rules(chain, sensitive))
    findings.extend(check_policies(rs))
    for note in rs.notes:
        findings.append(Finding("NFT000", "partial-analysis", "info", note))
    if rs.xt_rules:
        findings.append(
            Finding(
                "NFT012",
                "iptables-nft-compat",
                "info",
                f"{rs.xt_rules} rule(s) use iptables-nft (xt) compatibility expressions that "
                "nftables JSON does not describe; analyse `iptables-save` output for full precision",
            )
        )
    return findings


__all__ = ["run_static_checks", "reachable_chains", "check_shadowing", "format_ports"]
