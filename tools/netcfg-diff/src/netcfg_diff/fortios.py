"""Parser for FortiOS (FortiGate) configurations: config / edit / set / next / end."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .masking import FORTIOS_PUBLIC_ATTR, FORTIOS_SECRET_ATTR, Masker
from .model import Config, Node

# Tables whose entries are evaluated in order (the position of an "edit"
# block, not its ID, decides which policy matches first).
ORDERED_CONFIG_RE = re.compile(
    r"^config firewall (?:policy6?|policy46|policy64|security-policy|proxy-policy|local-in-policy6?|"
    r"shaping-policy|DoS-policy6?|multicast-policy6?|interface-policy6?|central-snat-map|"
    r"consolidated policy|acl6?|ttl-policy|sniffer)$"
)
ORDERED_RULE_PARENT_RE = re.compile(
    r"^config router (?:access-list6?|prefix-list6?|route-map|aspath-list|community-list|key-chain)$"
)
# Multi-valued attributes whose order is not significant.
LIST_ATTRS = frozenset(
    {
        "member",
        "srcaddr",
        "dstaddr",
        "srcaddr6",
        "dstaddr6",
        "srcintf",
        "dstintf",
        "service",
        "allowaccess",
        "groups",
        "users",
        "interface",
        "internet-service-name",
        "internet-service-id",
        "internet-service-src-name",
        "internet-service-src-id",
        "application",
        "poolname",
        "poolname6",
        "fsso-groups",
        "trusthost",
        "vdom",
    }
)


def _split(line: str) -> List[Tuple[str, str]]:
    """Split a logical line into (raw, value) words, honouring quotes and escapes."""
    out: List[Tuple[str, str]] = []
    i, n = 0, len(line)
    while i < n:
        if line[i].isspace():
            i += 1
            continue
        if line[i] in "\"'":
            q, j, buf = line[i], i + 1, []
            while j < n and line[j] != q:
                if line[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(line[j])
                j += 1
            out.append((line[i : j + 1], "".join(buf)))
            i = j + 1
        else:
            j = i
            while j < n and not line[j].isspace():
                j += 1
            out.append((line[i:j], line[i:j]))
            i = j
    return out


def _unbalanced(line: str) -> bool:
    inq: Optional[str] = None
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and inq:
            i += 2
            continue
        if inq:
            if c == inq:
                inq = None
        elif c in "\"'" and (i == 0 or line[i - 1].isspace()):
            inq = c
        i += 1
    return inq is not None


def _logical_lines(text: str):
    buf: Optional[str] = None
    for no, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        if buf is None:
            buf, start = raw, no
        else:
            buf += "\n" + raw
        if not _unbalanced(buf):
            yield start, buf
            buf = None
    if buf is not None:
        yield start, buf


def _quote(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _is_secret(attr: str, vals: List[str], parents: List[Node]) -> bool:
    if vals and vals[0] == "ENC":
        return True
    if FORTIOS_SECRET_ATTR.search(attr) and not FORTIOS_PUBLIC_ATTR.search(attr):
        return True
    # SNMP v1/v2c community: "config system snmp community / edit N / set name <community>"
    return attr == "name" and len(parents) >= 2 and parents[-2].text == "config system snmp community"


def parse(text: str, vendor: str = "fortios", masker: Optional[Masker] = None) -> Config:
    masker = masker or Masker()
    root = Node("<root>")
    meta = {}
    stack: List[Tuple[Node, str]] = [(root, "root")]
    for _, logical in _logical_lines(text.lstrip("﻿")):
        s = logical.strip()
        if not s:
            continue
        if s.startswith("#"):
            m = re.match(r"^#config-version=([^:]+)", s)
            if m:
                meta["version"] = m.group(1)
            continue
        words = _split(s)
        cmd = words[0][1]
        top = stack[-1][0]
        parents = [n for n, _ in stack]
        if cmd == "config" and len(words) > 1:
            text_ = "config " + " ".join(v for _, v in words[1:])
            ordered = bool(ORDERED_CONFIG_RE.match(text_)) or (
                text_ == "config rule"
                and len(parents) >= 2
                and bool(ORDERED_RULE_PARENT_RE.match(parents[-2].text))
            )
            node = top.find(text_) if not top.ordered else None
            if node is None:
                node = top.add(Node(text_, ordered=ordered))
            stack.append((node, "config"))
        elif cmd == "edit" and len(words) > 1:
            raw, val = words[1]
            key = f"edit {val}"
            node = top.find(key) if not top.ordered else None
            if node is None:
                node = top.add(Node(f"edit {raw}", key=key, cmp=key))
            stack.append((node, "edit"))
        elif cmd == "next":
            if stack[-1][1] == "edit":
                stack.pop()
        elif cmd == "end":
            if stack[-1][1] == "edit":
                stack.pop()
            if stack[-1][1] == "config":
                stack.pop()
        elif cmd in ("set", "unset", "append", "select", "unselect") and len(words) > 1:
            attr = words[1][1]
            raws = [r for r, _ in words[2:]]
            vals = [v for _, v in words[2:]]
            if cmd != "unset" and _is_secret(attr, vals, parents):
                raws = vals = [masker.token(" ".join(vals))]
            key = f"set {attr}"
            existing = top.find(key)
            if cmd in ("append", "unselect") and existing is not None and existing.cmp != ("<unset>",):
                old_vals = list(existing.cmp)
                vals = old_vals + vals if cmd == "append" else [v for v in old_vals if v not in vals]
                raws = [_quote(v) for v in vals]
            if cmd == "unset":
                node = Node(
                    f"unset {attr}", key=key, cmp=("<unset>",), members=() if attr in LIST_ATTRS else None
                )
            else:
                node = Node(
                    f"set {attr} {' '.join(raws)}".rstrip(),
                    key=key,
                    cmp=tuple(vals),
                    members=tuple(vals) if attr in LIST_ATTRS else None,
                )
            if existing is not None:
                top.children[top.children.index(existing)] = node
                top.reindex()
            else:
                top.add(node)
        else:
            top.add(Node(" ".join(r for r, _ in words)))
    return Config(vendor, root, meta)
