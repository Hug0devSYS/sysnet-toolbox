"""Parser for Junos configurations.

Both the curly-brace format (``show configuration``) and the set format
(``show configuration | display set``) are turned into the same token tree,
so a brace export can be compared with a set export. Each token is a node:

    interfaces { ge-0/0/0 { unit 0 { family inet { address 192.0.2.1/24; } } } }
    set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24

both give ``interfaces > ge-0/0/0 > unit > 0 > family > inet > address >
192.0.2.1/24``. ``[ a b ]`` lists become sibling leaves. ``inactive:`` and
``deactivate`` mark the statement inactive.
"""

from __future__ import annotations

import re
from typing import Iterator, List, Optional, Sequence, Tuple, Union

from .masking import JUNOS_SECRET_KEYWORDS, Masker
from .model import Config, Node, ParseError

SPECIAL = set("{};[]")
PLAIN_RE = re.compile(r'^[^\s{};\[\]"#\'\\]+$')
NOISE_RE = re.compile(
    r"^\s*(?:\{(?:master|backup|primary|secondary|hold|linecard|disabled)[^}]*\}|\S+@\S+[>#%].*)\s*$"
)
FLAGS = {"inactive:", "protect:", "replace:", "delete:", "active:"}
ORDERED_LEAF_LISTS = {
    "import",
    "export",
    "vrf-import",
    "vrf-export",
    "apply-groups",
    "apply-groups-except",
    "name-server",
    "import-policy",
    "export-policy",
}

Token = Tuple[str, str, int]  # kind ("w" or punctuation), value, line
Elem = Union[str, List[str]]


def tokenize(text: str) -> Iterator[Token]:
    i, n, line = 0, len(text), 1
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
        elif ch.isspace():
            i += 1
        elif ch == "#" or (ch == "/" and text.startswith("/*", i)):
            if ch == "#":
                j = text.find("\n", i)
                i = n if j < 0 else j
            else:
                j = text.find("*/", i + 2)
                if j < 0:
                    raise ParseError("unterminated /* comment", line)
                line += text.count("\n", i, j)
                i = j + 2
        elif ch in SPECIAL:
            yield ch, ch, line
            i += 1
        elif ch == '"':
            j, start_line = i + 1, line
            while j < n and text[j] != '"':
                if text[j] == "\\":
                    j += 1
                elif text[j] == "\n":
                    line += 1
                j += 1
            if j >= n:
                raise ParseError("unterminated quoted string", start_line)
            yield "w", text[i : j + 1], start_line
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in SPECIAL:
                j += 1
            yield "w", text[i:j], line
            i = j


def _norm(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == tok[-1] == '"' and PLAIN_RE.match(tok[1:-1]):
        return tok[1:-1]
    return tok


def _is_ordered(path: Sequence[str]) -> bool:
    name, anc = path[-1], path[:-1]
    if name == "term" and ("filter" in anc or "policy-statement" in anc):
        return True
    if name == "policy" and "policies" in anc and "security" in anc:
        return True
    if name == "rule" and "nat" in anc:
        return True
    return name in ORDERED_LEAF_LISTS


class _Builder:
    def __init__(self, masker: Masker):
        self.masker = masker
        self.root = Node("<root>")

    def insert(self, parent: Node, ppath: List[str], elems: Sequence[Elem]) -> Tuple[Node, List[str]]:
        """Insert a statement below ``parent``; returns the last node and its path."""
        for idx, e in enumerate(elems):
            if isinstance(e, list):
                last: Tuple[Node, List[str]] = (parent, ppath)
                for item in e:
                    last = self.insert(parent, ppath, [item, *elems[idx + 1 :]])
                return last
            tok = self._mask(_norm(e), ppath)
            child = parent.find(tok)
            if child is None:
                child = parent.add(Node(tok, ordered=_is_ordered([*ppath, tok])))
            parent, ppath = child, [*ppath, tok]
        return parent, ppath

    def _mask(self, tok: str, ppath: Sequence[str]) -> str:
        if self.masker.mode == "show" or not ppath:
            return tok
        prev = ppath[-1]
        if (
            prev in JUNOS_SECRET_KEYWORDS
            or (prev == "community" and ppath[0] == "snmp")
            or (prev == "key" and tok.strip('"').startswith("$9$"))
            or self.masker.is_crypt(tok)
        ):
            return self.masker.token(tok)
        return tok

    def find(self, elems: Sequence[str]) -> Optional[Node]:
        node: Optional[Node] = self.root
        path: List[str] = []
        for e in elems:
            assert node is not None
            tok = self._mask(_norm(e), path)
            node = node.find(tok)
            if node is None:
                return None
            path.append(tok)
        return node


def _parse_brace(text: str, b: _Builder) -> None:
    stack: List[Tuple[Node, List[str]]] = [(b.root, [])]
    stmt: List[Elem] = []
    inactive = False
    lst: Optional[List[str]] = None
    line = 1
    for kind, val, line in tokenize(text):
        if kind == "w":
            if lst is not None:
                lst.append(val)
            elif not stmt and val in FLAGS:
                inactive = inactive or val == "inactive:"
            else:
                stmt.append(val)
        elif kind == "[":
            if lst is not None:
                raise ParseError("nested '['", line)
            lst = []
        elif kind == "]":
            if lst is None:
                raise ParseError("unexpected ']'", line)
            stmt.append(lst)
            lst = None
        elif kind in ";{":
            if lst is not None:
                raise ParseError(f"unexpected {kind!r} inside [ ]", line)
            if not stmt:
                if kind == ";":
                    continue
                raise ParseError("'{' without a statement", line)
            parent, ppath = stack[-1]
            node, npath = b.insert(parent, ppath, stmt)
            if inactive:
                node.inactive = True
            if kind == "{":
                stack.append((node, npath))
            stmt, inactive = [], False
        elif kind == "}":
            if stmt or lst is not None:
                raise ParseError("missing ';' before '}'", line)
            if len(stack) == 1:
                raise ParseError("unbalanced '}'", line)
            stack.pop()
    if stmt or lst is not None:
        raise ParseError("statement not terminated by ';'", line)
    if len(stack) != 1:
        raise ParseError(f"{len(stack) - 1} unclosed '{{' at end of input", line)


def _parse_set(lines: Sequence[str], b: _Builder) -> None:
    for no, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        words = [v for k, v, _ in tokenize(s) if k == "w"]
        if not words:
            continue
        cmd, rest = words[0], words[1:]
        if cmd == "set" and rest:
            b.insert(b.root, [], rest)
        elif cmd == "deactivate" and rest:
            node, _ = b.insert(b.root, [], rest)
            node.inactive = True
        elif cmd == "activate" and rest:
            found = b.find(rest)
            if found is not None:
                found.inactive = False
        elif cmd in ("delete", "insert", "annotate", "protect", "unprotect"):
            continue
        else:
            raise ParseError(f"unexpected statement in set-format configuration: {s[:60]!r}", no)


def is_set_format(lines: Sequence[str]) -> bool:
    cmds = [ln.split(None, 1)[0] for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    return bool(cmds) and sum(c in ("set", "deactivate", "activate") for c in cmds) >= 0.9 * len(cmds)


def parse(text: str, vendor: str = "junos", masker: Optional[Masker] = None) -> Config:
    b = _Builder(masker or Masker())
    text = text.lstrip("﻿").replace("\r\n", "\n").replace("\r", "\n")
    lines = ["" if NOISE_RE.match(ln) else ln for ln in text.split("\n")]  # keep line numbers
    meta = {}
    if is_set_format(lines):
        _parse_set(lines, b)
        meta["format"] = "set"
    else:
        _parse_brace("\n".join(lines), b)
        meta["format"] = "brace"
    ver = b.root.find("version")
    if ver is not None and ver.children:
        meta["version"] = ver.children[0].text
    return Config(vendor, b.root, meta)
