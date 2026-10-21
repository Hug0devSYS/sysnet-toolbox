"""Parser for indentation-based configurations.

Covers Cisco IOS / IOS-XE, NX-OS, IOS-XR, Arista EOS and look-alikes (ASA's
running-config also parses well): ``show running-config`` output where a
sub-statement is indented under its parent and ``!`` starts a comment.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .masking import Masker
from .model import Config, Node, compress_ints

WS_RE = re.compile(r"\s+")
EXIT_RE = re.compile(r"^(?:exit(?:-[\w-]+)?|end-(?:policy|set|group|macro)|quit-?\w*)$")
BANNER_RE = re.compile(r"^banner\s+(\S+)\s*(.*)$")

# Built-in volatile statements (counters, timestamps, prompts): ignored unless
# --keep-volatile is given.
VOLATILE = tuple(
    re.compile(p)
    for p in (
        r"^ntp clock-period\b",
        r"^Building configuration",
        r"^Current configuration\s*:",
        r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d+ ",
        r"^[\w.:/-]+[#>]\s*(?:sh|show)\s",
        r"^Time source is\b",
        r"^Command:\s*show\b",
    )
)

# Contexts whose children are evaluated in order.
ORDERED_RE = re.compile(
    r"^(?:(?:ip|ipv4|ipv6|mac|arp) access-list\b"
    r"|access-list\s+\S+$"  # synthetic group of top-level numbered/ASA ACL entries
    r"|(?:ip|ipv6) prefix-list\s+\S+$"
    r"|ip as-path access-list\s+\S+$"
    r"|ip (?:community-list|extcommunity-list)\s+(?:standard\s+|expanded\s+)?\S+$"
    r"|policy-map\b"
    r"|route-policy\b"
    r"|banner\b"
    r"|macro name\b"
    r"|certificate\b"
    r")"
)

# Top-level statements that are really entries of one ordered list.
# (regex, group-name builder, child-key builder)
SEQ_RE = re.compile(r"\bseq \d+\s+")
GROUPS: Tuple[Tuple[re.Pattern, Callable[[re.Match], str], Callable[[str], str]], ...] = (
    (re.compile(r"^access-list\s+(\S+)\s"), lambda m: f"access-list {m.group(1)}", lambda t: t),
    (
        re.compile(r"^(ip|ipv6) prefix-list\s+(\S+)\s"),
        lambda m: f"{m.group(1)} prefix-list {m.group(2)}",
        lambda t: SEQ_RE.sub("", t),
    ),
    (re.compile(r"^ip as-path access-list\s+(\S+)\s"), lambda m: f"ip as-path access-list {m.group(1)}", str),
    (
        re.compile(r"^ip (community-list|extcommunity-list)\s+(?:(standard|expanded)\s+)?(\S+)\s"),
        lambda m: f"ip {m.group(1)} {m.group(2) + ' ' if m.group(2) else ''}{m.group(3)}",
        lambda t: t,
    ),
)

ACL_CONTEXT_RE = re.compile(r"^(?:(?:ip|ipv4|ipv6|mac|arp) access-list\b|object-group\b)")
ACL_SEQ_RE = re.compile(r"^(\d+)\s+(.*)$")

# Single-valued commands: a statement whose key matches one of these replaces
# the previous one, so "description A" -> "description B" is a modification
# rather than a removal plus an addition. (regex, key template or None)
_KEY_RULES: Sequence[Tuple[str, Optional[str]]] = (
    (r"^hostname\b", None),
    (r"^description\b", None),
    (r"^ip address\b(?!.*\bsecondary\b)", None),
    (r"^ipv6 address (?:dhcp|autoconfig)\b", "ipv6 address auto"),
    (r"^(?:ip |ipv6 )?mtu\b", None),
    (r"^(?:bandwidth|delay|speed|duplex|load-interval|encapsulation|carrier-delay|keepalive)\b", None),
    (r"^negotiation\b", None),
    (r"^switchport (?:mode|access vlan|voice vlan|trunk native vlan|trunk encapsulation)\b", None),
    (r"^switchport port-security maximum\b", None),
    (r"^switchport$", None),
    (r"^(?:ip )?vrf (?:forwarding|member)\b", None),
    (r"^vrf\s+\S+$", "vrf"),
    (r"^ip ospf (?:cost|network|priority|hello-interval|dead-interval)\b", None),
    (r"^ip ospf \d+ area\b", "ip ospf area"),
    (r"^ip router ospf \S+ area\b", "ip router ospf area"),
    (r"^ip router isis\b", None),
    (r"^isis metric\b", None),
    (r"^channel-group\b", None),
    (r"^spanning-tree (?:portfast|mode|port type|guard|bpduguard|bpdufilter|link-type|cost)\b", None),
    (r"^spanning-tree vlan (\S+) priority\b", r"spanning-tree vlan \1 priority"),
    (r"^(?:bgp )?router-id\b", None),
    (
        r"^(?:logging source-interface|ntp source|ip ssh source-interface|snmp-server source-interface)\b",
        None,
    ),
    (r"^snmp-server (?:location|contact|chassis-id)\b", None),
    (r"^ip domain[ -]name\b", "ip domain name"),
    (r"^ip domain-lookup\b", None),
    (r"^clock timezone\b", None),
    (r"^ip default-gateway\b", None),
    (r"^(ip|ipv6) tcp adjust-mss\b", r"\1 tcp adjust-mss"),
    (r"^ip nat (?:inside|outside)$", "ip nat"),
    (r"^(standby|vrrp) (\d+) (priority|preempt|timers|authentication)\b", r"\1 \2 \3"),
    (r"^(standby|vrrp) (\d+) ip(?!\s+\S+\s+secondary)\b", r"\1 \2 ip"),
    (r"^service-policy (?:type \S+ )?(input|output)\b", r"service-policy \1"),
    (r"^ip access-group \S+ (in|out)\b", r"ip access-group \1"),
    (r"^ipv6 traffic-filter \S+ (in|out)\b", r"ipv6 traffic-filter \1"),
    (r"^(ipv4|ipv6) access-group \S+ (ingress|egress)\b", r"\1 access-group \2"),
    (r"^access-class \S+ (in|out)\b", r"access-class \1"),
    (r"^ipv6 access-class \S+ (in|out)\b", r"ipv6 access-class \1"),
    (r"^(?:shutdown|cdp enable|lldp transmit|lldp receive|ip proxy-arp|ip redirects|ip unreachables)$", None),
    (r"^(?:ip directed-broadcast|ip route-cache|mop enabled|ip ospf passive|power inline)\b", None),
    (r"^storm-control (?:broadcast|multicast|unicast) level\b", None),
    (r"^storm-control action\b", None),
    (r"^username (\S+)\b", r"username \1"),
    (r"^enable (?:secret|password)\b", "enable secret"),
    (r"^ip ssh (?:version|time-out|authentication-retries)\b", None),
    (r"^(?:exec-timeout|session-timeout|absolute-timeout|transport input|transport output)\b", None),
    (r"^(?:privilege level|login authentication|authorization exec|accounting exec)\b", None),
    (r"^logging (?:buffered|console|monitor|trap)\b", None),
    (r"^service timestamps (debug|log)\b", r"service timestamps \1"),
    (r"^(?:remote-as|update-source|local-as|ebgp-multihop|password)\b", None),
    (r"^(route-map|prefix-list|filter-list) \S+ (in|out)$", r"\1 \2"),
    (
        r"^neighbor (\S+) (remote-as|description|update-source|password|ebgp-multihop|timers|local-as|"
        r"maximum-prefix|ttl-security|version|weight|fall-over|peer-group)\b",
        r"neighbor \1 \2",
    ),
    (
        r"^neighbor (\S+) (route-map|prefix-list|filter-list|distribute-list) \S+ (in|out)\b",
        r"neighbor \1 \2 \3",
    ),
    (r"^(?:name|state|mode|priority|timers|metric|distance|maximum-paths|auto-cost)\b", None),
    (r"^switchport trunk allowed vlan\b", None),
)
KEY_RULES = tuple((re.compile(p), t) for p, t in _KEY_RULES)

VLAN_RE = re.compile(r"^switchport trunk allowed vlan(?:\s+(add|remove|except))?\s+(\S+)$")


def statement_key(text: str) -> str:
    """Identity of a statement among its siblings (see KEY_RULES)."""
    body = text[3:] if text.startswith("no ") else text
    for rx, template in KEY_RULES:
        m = rx.match(body)
        if m:
            return m.expand(template) if template else m.group(0)
    return body


def _vlan_set(spec: str) -> Optional[set]:
    if spec == "all":
        return set(range(1, 4095))
    if spec == "none":
        return set()
    out = set()
    for part in spec.split(","):
        if not part:
            continue
        a, _, b = part.partition("-")
        if not a.isdigit() or (b and not b.isdigit()):
            return None
        lo, hi = int(a), int(b or a)
        if lo > hi or hi > 4095:
            return None
        out.update(range(lo, hi + 1))
    return out


def _merge_trunk_vlans(node: Node) -> None:
    """Fold 'switchport trunk allowed vlan [add|remove|except] X' lines into one VLAN set."""
    vlan_lines = [(i, c) for i, c in enumerate(node.children) if VLAN_RE.match(c.text)]
    if not vlan_lines:
        return
    allowed: Optional[set] = None
    for _, c in vlan_lines:
        m = VLAN_RE.match(c.text)
        assert m
        op, vals = m.group(1), _vlan_set(m.group(2))
        if vals is None:
            return  # unknown syntax: leave untouched
        if op is None:
            allowed = vals
        elif op == "add":
            allowed = (allowed or set()) | vals
        elif op == "remove":
            allowed = (allowed if allowed is not None else set(range(1, 4095))) - vals
        else:  # except
            allowed = set(range(1, 4095)) - vals
    assert allowed is not None
    text = "switchport trunk allowed vlan " + (compress_ints(sorted(allowed)) or "none")
    merged = Node(text, key="switchport trunk allowed vlan", members=tuple(sorted(allowed)), synthetic=True)
    first = vlan_lines[0][0]
    drop = {id(c) for _, c in vlan_lines}
    kids = [c for c in node.children if id(c) not in drop]
    kids.insert(first, merged)
    node.children = kids
    node.reindex()


def _group_top_level(root: Node) -> None:
    out: List[Node] = []
    groups: Dict[str, Node] = {}
    for c in root.children:
        for rx, name_of, key_of in GROUPS:
            m = rx.match(c.text)
            if m and not c.children:
                name = name_of(m)
                g = groups.get(name)
                if g is None:
                    g = groups[name] = Node(name, ordered=True, synthetic=True)
                    out.append(g)
                k = key_of(c.text)
                g.add(Node(c.text, key=k, cmp=k))
                break
        else:
            out.append(c)
    root.children = out
    root.reindex()


class _Lines:
    def __init__(self, text: str):
        self.lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self.i = 0

    def next(self) -> Optional[str]:
        if self.i >= len(self.lines):
            return None
        line = self.lines[self.i]
        self.i += 1
        return line


def _read_banner(rest: str, lines: _Lines) -> Optional[List[str]]:
    """Return the banner body lines, or None if ``rest`` has no delimiter."""
    if not rest:
        return None
    if rest.startswith("^C"):
        delim, rest = "^C", rest[2:]
    else:
        delim, rest = rest[0], rest[1:]
    if delim in rest:
        return [rest[: rest.index(delim)]]
    body = [rest] if rest else []
    while True:
        line = lines.next()
        if line is None:
            return body
        if delim in line:
            head = line[: line.index(delim)]
            if head:
                body.append(head.rstrip())
            return body
        body.append(line.rstrip())


def parse(text: str, vendor: str = "ios", masker: Optional[Masker] = None) -> Config:
    masker = masker or Masker()
    text = text.lstrip("﻿").replace("\x03", "^C")
    root = Node("<root>")
    meta: Dict[str, str] = {}
    stack: List[Tuple[int, Optional[Node]]] = [(-1, root)]
    lines = _Lines(text)
    while True:
        raw = lines.next()
        if raw is None:
            break
        raw = raw.expandtabs(4).rstrip()
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("!"):
            continue
        if stripped == "end" or EXIT_RE.match(stripped):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        while stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]

        m = BANNER_RE.match(stripped)
        body = _read_banner(m.group(2), lines) if m and indent == 0 else None
        if parent is None:
            stack.append((indent, None))  # inside an ignored subtree
            continue
        if body is not None:
            assert m is not None
            node = Node(f"banner {m.group(1)}", ordered=True)
            for b in body:
                node.add(Node(b))
            existing = parent.find(node.key)  # type: ignore[arg-type]
            if existing is not None:
                parent.children.remove(existing)
                parent.reindex()
            parent.add(node)
            continue

        stmt = masker.line(WS_RE.sub(" ", stripped))
        if stmt.startswith("version ") and indent == 0:
            meta.setdefault("version", stmt[8:])
        node = _make_node(stmt, parent)
        if not parent.ordered:
            existing = parent.find(node.key)  # type: ignore[arg-type]
            if existing is not None and existing.text == node.text:
                stack.append((indent, existing))  # same context opened twice: merge
                continue
        parent.add(node)
        stack.append((indent, node))

    _group_top_level(root)
    for _, n in root.walk():
        if n.children:
            _merge_trunk_vlans(n)
    return Config(vendor, root, meta)


def _make_node(stmt: str, parent: Node) -> Node:
    ordered = bool(ORDERED_RE.match(stmt))
    if ACL_CONTEXT_RE.match(parent.text):
        m = ACL_SEQ_RE.match(stmt)
        if m:
            # Sequence numbers only encode the order, which is compared anyway:
            # a resequenced ACL is not a change.
            return Node(stmt, key=m.group(2), cmp=m.group(2), ordered=ordered)
        return Node(stmt, ordered=ordered)
    if parent.ordered:
        return Node(stmt, ordered=ordered)
    return Node(stmt, key=statement_key(stmt), ordered=ordered)
