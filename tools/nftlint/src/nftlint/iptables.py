"""Parser for ``iptables-save`` / ``ip6tables-save`` output."""

from __future__ import annotations

import re
import shlex
from typing import List, Optional, Tuple

from .model import (
    CTSTATE,
    DADDR4,
    DADDR6,
    DPORT,
    HOOK_PRIORITY_IPTABLES,
    L4PROTO,
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
    universe,
    values,
)
from .nftjson import TCP_SYN, ParseError
from .values import Unsupported, address_span, ct_state_index, port_number, protocol_number, to_set

BUILTIN_HOOKS = {
    "PREROUTING": "prerouting",
    "INPUT": "input",
    "FORWARD": "forward",
    "OUTPUT": "output",
    "POSTROUTING": "postrouting",
}
STANDARD_TARGETS = {"ACCEPT": "accept", "DROP": "drop", "REJECT": "reject", "RETURN": "return"}
NAT_TARGETS = {"DNAT", "SNAT", "MASQUERADE", "REDIRECT", "NETMAP", "TPROXY"}
QUEUE_TARGETS = {"NFQUEUE", "QUEUE"}

# Options whose values are fully understood.
PORT_OPTS = {"--dport": DPORT, "--destination-port": DPORT, "--sport": SPORT, "--source-port": SPORT}
MULTIPORT_OPTS = {
    "--dports": DPORT,
    "--destination-ports": DPORT,
    "--sports": SPORT,
    "--source-ports": SPORT,
}
# Options that are pure annotations and never affect matching.
IGNORED_OPTS = {"--comment"}
# Options without an argument.
FLAG_OPTS = {"--syn", "-f", "--fragment", "--rcheck", "--update", "--set", "--remove", "--rttl"}

COUNTER_PREFIX = re.compile(r"^\[\d+:\d+\]\s+")


def looks_like_ipv6(text: str) -> bool:
    return bool(
        re.search(r"^-A .*\s-[sd]\s+[0-9a-fA-F:]*:[0-9a-fA-F:./]*", text, re.M)
        or re.search(r"\b(ipv6-icmp|icmpv6|icmp6)\b", text)
        or re.search(r"--icmpv6-type", text)
    )


class IptablesParser:
    def __init__(self, source: str, family: str) -> None:
        if family not in ("ip", "ip6"):
            raise ValueError(family)
        self.source = source
        self.family = family
        self.saddr = SADDR4 if family == "ip" else SADDR6
        self.daddr = DADDR4 if family == "ip" else DADDR6
        self.ruleset = Ruleset()
        self.opaque_count = 0
        self.opaque_examples: dict = {}

    def parse(self, text: str) -> Ruleset:
        table: Optional[str] = None
        tables = 0
        seen_rule_or_chain = False
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = COUNTER_PREFIX.sub("", raw.strip())
            if not line or line.startswith("#"):
                continue
            if line.startswith("*"):
                table = line[1:].strip()
                tables += 1
                continue
            if line == "COMMIT":
                table = None
                continue
            if table is None:
                raise ParseError(f"{self.source}:{lineno}: content outside a '*table' block")
            if line.startswith(":"):
                seen_rule_or_chain = True
                parts = line[1:].split()
                if not parts:
                    raise ParseError(f"{self.source}:{lineno}: malformed chain declaration")
                self._chain(table, parts[0], parts[1] if len(parts) > 1 else "-")
                continue
            if line.startswith("-A ") or line.startswith("--append "):
                seen_rule_or_chain = True
                self._rule(table, line, lineno)
                continue
            if line.startswith(("-N ", "-P ", "-I ")):
                raise ParseError(
                    f"{self.source}:{lineno}: looks like an iptables command script, not iptables-save output"
                )
            raise ParseError(f"{self.source}:{lineno}: unrecognised line: {line[:60]}")
        if not seen_rule_or_chain:
            raise ParseError(f"{self.source}: no chains found in iptables-save input")
        rs = self.ruleset
        rs.sources.append(
            {
                "path": self.source,
                "format": "iptables-save" if self.family == "ip" else "ip6tables-save",
                "tables": tables,
                "chains": len(rs.chains),
                "rules": rs.rule_count(),
            }
        )
        if self.opaque_examples:
            top = sorted(self.opaque_examples.items(), key=lambda kv: -kv[1])[:5]
            rs.notes.append(
                f"{self.source}: {self.opaque_count} match option(s) are not modelled and are "
                "handled conservatively (e.g. " + ", ".join(f"`{k}`" for k, _ in top) + ")"
            )
        return rs

    def _chain(self, table: str, name: str, policy: str = "-") -> Chain:
        builtin = name in BUILTIN_HOOKS
        chain = Chain(
            source=self.source,
            family=self.family,
            table=table,
            name=name,
            type=table,
            hook=BUILTIN_HOOKS.get(name) if builtin else None,
            prio=HOOK_PRIORITY_IPTABLES.get(table, 0),
            policy=policy.lower() if builtin and policy != "-" else ("accept" if builtin else None),
        )
        existing = self.ruleset.chains.get(chain.key())
        if existing is not None:
            if builtin and policy != "-":
                existing.policy = policy.lower()
            return existing
        return self.ruleset.add_chain(chain)

    def _opaque(self, m: Match, text: str) -> None:
        m.add_opaque(text)
        self.opaque_count += 1
        self.opaque_examples[text] = self.opaque_examples.get(text, 0) + 1

    def _rule(self, table: str, line: str, lineno: int) -> None:
        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            raise ParseError(f"{self.source}:{lineno}: {exc}") from exc
        if len(tokens) < 2:
            raise ParseError(f"{self.source}:{lineno}: rule without chain")
        chain = self._chain(table, tokens[1])
        m = Match()
        verdict = NO_VERDICT
        module = ""
        i = 2
        negate = False
        target_seen = False
        while i < len(tokens):
            tok = tokens[i]
            if tok == "!":
                negate = True
                i += 1
                continue
            if target_seen:
                # Target options (--reject-with, --log-prefix, ...): skip.
                i += 1
                continue
            arg, nxt = _arg(tokens, i)
            # Old-style negation: "-s ! 1.2.3.4".
            if arg == "!":
                negate = True
                arg, nxt = _arg(tokens, i + 1)
            try:
                if tok in ("-p", "--protocol"):
                    self._proto(m, arg, negate)
                elif tok in ("-s", "--source", "--src"):
                    self._addr(m, self.saddr, arg, negate)
                elif tok in ("-d", "--destination", "--dst"):
                    self._addr(m, self.daddr, arg, negate)
                elif tok in ("-i", "--in-interface"):
                    m.constrain_iface("iif", _iface(arg, negate))
                elif tok in ("-o", "--out-interface"):
                    m.constrain_iface("oif", _iface(arg, negate))
                elif tok in ("-m", "--match"):
                    module = arg or ""
                elif tok in PORT_OPTS:
                    m.constrain(PORT_OPTS[tok], _maybe_not(_port_spans(PORT_OPTS[tok], [arg]), negate))
                elif tok in MULTIPORT_OPTS:
                    dim = MULTIPORT_OPTS[tok]
                    m.constrain(dim, _maybe_not(_port_spans(dim, (arg or "").split(",")), negate))
                elif tok in ("--ctstate", "--state"):
                    idx = [ct_state_index(s) for s in (arg or "").split(",")]
                    m.constrain(CTSTATE, _maybe_not(values(CTSTATE, *idx), negate))
                elif tok in ("--src-range", "--dst-range"):
                    dim = self.saddr if tok == "--src-range" else self.daddr
                    m.constrain(dim, _maybe_not(to_set(dim, [address_span(dim, arg or "")]), negate))
                elif tok in IGNORED_OPTS:
                    pass
                elif tok == "--syn" and not negate:
                    m.constrain(L4PROTO, values(L4PROTO, 6))
                    m.add_opaque(TCP_SYN)
                    nxt = i + 1
                elif tok == "--tcp-flags":
                    mask = (arg or "").upper()
                    comp = tokens[nxt].upper() if nxt < len(tokens) else ""
                    nxt += 1
                    if not negate and set(mask.split(",")) == {"FIN", "SYN", "RST", "ACK"} and comp == "SYN":
                        m.constrain(L4PROTO, values(L4PROTO, 6))
                        m.add_opaque(TCP_SYN)
                    else:
                        self._opaque(m, ("! " if negate else "") + f"--tcp-flags {mask} {comp}")
                elif tok in ("-j", "--jump"):
                    verdict = _target(arg or "")
                    target_seen = True
                elif tok in ("-g", "--goto"):
                    verdict = Verdict("goto", arg)
                    target_seen = True
                elif tok in ("-4", "-6"):
                    nxt = i + 1
                elif tok in ("-c", "--set-counters"):
                    nxt = i + 3
                elif tok.startswith("-"):
                    # Unknown match option: consume its arguments and treat
                    # it as an opaque condition.
                    if tok in FLAG_OPTS:
                        nxt = i + 1
                        args: List[str] = []
                    else:
                        nxt = i + 1
                        args = []
                        while nxt < len(tokens) and not tokens[nxt].startswith("-") and tokens[nxt] != "!":
                            args.append(tokens[nxt])
                            nxt += 1
                    text = ("! " if negate else "") + " ".join([f"-m {module}" if module else "", tok, *args])
                    self._opaque(m, text.strip())
                else:
                    raise ParseError(f"{self.source}:{lineno}: unexpected token {tok!r}")
            except Unsupported:
                self._opaque(m, ("! " if negate else "") + f"{tok} {arg}")
            negate = False
            i = nxt
        rule = Rule(index=len(chain.rules) + 1, match=m, verdict=verdict, text=line, line=lineno, chain=chain)
        chain.rules.append(rule)

    def _proto(self, m: Match, arg: Optional[str], negate: bool) -> None:
        if arg is None:
            raise Unsupported("missing protocol")
        a = arg.lower()
        s = universe(L4PROTO) if a in ("all", "0") else values(L4PROTO, protocol_number(a))
        m.constrain(L4PROTO, s.complement() if negate else s)

    def _addr(self, m: Match, dim: str, arg: Optional[str], negate: bool) -> None:
        if arg is None:
            raise Unsupported("missing address")
        spans = []
        for part in arg.split(","):
            spans.append(address_span(dim, part))
        s = to_set(dim, spans)
        m.constrain(dim, s.complement() if negate else s)


def _arg(tokens: List[str], i: int) -> Tuple[Optional[str], int]:
    if i + 1 < len(tokens):
        return tokens[i + 1], i + 2
    return None, i + 1


def _maybe_not(s, negate: bool):
    return s.complement() if negate else s


def _port_spans(dim: str, items: List[Optional[str]]):
    spans = []
    for it in items:
        if it is None or it == "":
            raise Unsupported("missing port")
        if ":" in it:
            a, b = it.split(":", 1)
            spans.append((port_number(a) if a else 0, port_number(b) if b else 65535))
        else:
            p = port_number(it)
            spans.append((p, p))
    return to_set(dim, spans)


def _iface(arg: Optional[str], negate: bool) -> IfaceMatch:
    if not arg:
        raise Unsupported("missing interface")
    name = arg[:-1] + "*" if arg.endswith("+") else arg
    return IfaceMatch(frozenset({name}), negated=negate)


def _target(name: str) -> Verdict:
    if name in STANDARD_TARGETS:
        return Verdict(STANDARD_TARGETS[name])
    if name in NAT_TARGETS:
        return Verdict("nat")
    if name in QUEUE_TARGETS:
        return Verdict("queue")
    # Either a user-defined chain or a non-terminating extension target (LOG,
    # NFLOG, MARK, CONNMARK, TCPMSS, CT, ...); resolved once all chains are known.
    return Verdict("ext", name)


def parse_iptables_save(text: str, source: str, family: str = "ip") -> Ruleset:
    rs = IptablesParser(source, family).parse(text)
    # Resolve all-uppercase "extension" targets that are actually user chains.
    for chain in rs.chains.values():
        for rule in chain.rules:
            if rule.verdict.kind == "ext" and rs.resolve(chain, rule.verdict.target or "") is not None:
                rule.verdict = Verdict("jump", rule.verdict.target)
            elif rule.verdict.kind == "ext":
                rule.verdict = NO_VERDICT
    return rs
