"""Configuration tree model shared by every vendor parser."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

FAMILIES = {
    "ios": "cisco",
    "nxos": "cisco",
    "iosxr": "cisco",
    "eos": "cisco",
    "junos": "junos",
    "fortios": "fortios",
}
VENDORS = tuple(FAMILIES)


class ParseError(Exception):
    """Raised when a configuration cannot be parsed."""

    def __init__(self, message: str, line: Optional[int] = None):
        self.line = line
        super().__init__(f"line {line}: {message}" if line else message)


@dataclass(eq=False)
class Node:
    """One configuration statement and its sub-statements.

    ``text``     canonical display text (secrets already masked)
    ``key``      identity among siblings; two statements with the same key are
                 the "same" statement, possibly with a different value
    ``cmp``      value compared once two statements are matched by key
    ``members``  when set, the value is a multiset (unordered list) and the
                 change detail lists added / removed members
    ``ordered``  the order of the children is significant (ACL entries,
                 firewall policies, policy chains, ...)
    """

    text: str
    key: Optional[str] = None
    cmp: Any = None
    children: List[Node] = field(default_factory=list)
    ordered: bool = False
    inactive: bool = False
    synthetic: bool = False
    members: Optional[Tuple[Any, ...]] = None
    _index: Dict[str, Node] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.key is None:
            self.key = self.text
        if self.cmp is None:
            self.cmp = self.text

    def add(self, child: Node) -> Node:
        self.children.append(child)
        self._index.setdefault(child.key, child)
        return child

    def find(self, key: str) -> Optional[Node]:
        """First child with ``key`` (O(1); call reindex() after mutating children)."""
        return self._index.get(key)

    def reindex(self) -> None:
        self._index = {}
        for c in self.children:
            self._index.setdefault(c.key, c)

    def walk(self, depth: int = 0) -> Iterator[Tuple[int, Node]]:
        yield depth, self
        for c in self.children:
            yield from c.walk(depth + 1)

    def size(self) -> int:
        return sum(1 for _ in self.walk())

    def leaf_paths(self, prefix: Tuple[str, ...] = ()) -> Iterator[Tuple[str, ...]]:
        """Paths of every leaf below (and including) this node."""
        here = prefix + (self.text,)
        if not self.children:
            yield here
        for c in self.children:
            yield from c.leaf_paths(here)


@dataclass
class Change:
    op: str  # add, remove, modify, move, activate, deactivate
    path: Tuple[str, ...]
    before: Optional[Node] = None
    after: Optional[Node] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    @property
    def node(self) -> Node:
        node = self.after if self.after is not None else self.before
        assert node is not None
        return node


@dataclass
class Config:
    vendor: str
    root: Node
    meta: Dict[str, str] = field(default_factory=dict)

    @property
    def family(self) -> str:
        return FAMILIES[self.vendor]


def prune(
    root: Node,
    patterns: Sequence[re.Pattern],
    on_path: bool = False,
    drop_emptied: bool = False,
) -> int:
    """Remove every node matching one of ``patterns`` (and its subtree).

    With ``on_path`` the pattern is matched against the space-joined path from
    the root (Junos set-style paths), otherwise against the statement text.
    With ``drop_emptied`` a container whose children were all removed is
    removed too (otherwise it would turn into a different leaf statement).
    Returns the number of removed nodes.
    """
    if not patterns:
        return 0
    removed = 0

    def visit(node: Node, path: str) -> None:
        nonlocal removed
        kept: List[Node] = []
        for c in node.children:
            full = f"{path} {c.text}".strip() if on_path else c.text
            if any(p.search(full) for p in patterns):
                removed += c.size()
                continue
            had_children = bool(c.children)
            visit(c, full if on_path else "")
            if drop_emptied and had_children and not c.children:
                removed += 1
                continue
            kept.append(c)
        if len(kept) != len(node.children):
            node.children = kept
            node.reindex()

    visit(root, "")
    return removed


def compress_ints(values: Sequence[int]) -> str:
    """[1,2,3,5,7,8] -> '1-3,5,7-8'."""
    out: List[str] = []
    vals = sorted(set(values))
    i = 0
    while i < len(vals):
        j = i
        while j + 1 < len(vals) and vals[j + 1] == vals[j] + 1:
            j += 1
        out.append(str(vals[i]) if i == j else f"{vals[i]}-{vals[j]}")
        i = j + 1
    return ",".join(out)


def display(text: str, limit: int = 160) -> str:
    """Single-line, bounded display form of a statement (certificates, keys)."""
    if "\n" in text:
        text = text.replace("\r", "").replace("\n", "\\n")
    if len(text) > limit:
        return f"{text[: limit - 30]}...[{len(text)} chars]"
    return text
