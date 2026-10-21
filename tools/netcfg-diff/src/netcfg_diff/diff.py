"""Hierarchical, order-aware comparison of two configuration trees."""

from __future__ import annotations

from bisect import bisect_left
from collections import Counter
from typing import Any, Dict, List, Sequence, Tuple

from .model import Change, Node

Keyed = List[Tuple[Tuple[str, int], Node]]


def _keyed(nodes: Sequence[Node]) -> Keyed:
    """Pair each node with (key, occurrence) so duplicate keys match 1:1 in order."""
    seen: Dict[str, int] = {}
    out: Keyed = []
    for n in nodes:
        assert n.key is not None
        i = seen.get(n.key, 0)
        seen[n.key] = i + 1
        out.append(((n.key, i), n))
    return out


def lis_indices(seq: Sequence[int]) -> List[int]:
    """Indices of one longest strictly increasing subsequence (O(n log n))."""
    if not seq:
        return []
    tails: List[int] = []  # values
    tails_idx: List[int] = []  # index in seq of the tail of each length
    prev = [-1] * len(seq)
    for i, v in enumerate(seq):
        pos = bisect_left(tails, v)
        if pos == len(tails):
            tails.append(v)
            tails_idx.append(i)
        else:
            tails[pos] = v
            tails_idx[pos] = i
        prev[i] = tails_idx[pos - 1] if pos else -1
    out: List[int] = []
    k = tails_idx[-1]
    while k != -1:
        out.append(k)
        k = prev[k]
    return out[::-1]


def _members_detail(before: Sequence[Any], after: Sequence[Any]) -> Dict[str, List[Any]]:
    b, a = Counter(before), Counter(after)
    added = sorted((a - b).elements(), key=_sort_key)
    removed = sorted((b - a).elements(), key=_sort_key)
    return {"added": added, "removed": removed}


def _sort_key(v: Any) -> Tuple[int, Any]:
    return (0, v) if isinstance(v, int) else (1, str(v))


class Differ:
    """Compare two trees.

    ``pair_leaves``   when a statement has exactly one leaf child on each side
                      and they differ, report a single modification (Junos
                      token trees: ``host-name r1`` -> ``host-name r2``)
    ``ignore_order``  treat every list as unordered
    """

    def __init__(self, pair_leaves: bool = False, ignore_order: bool = False):
        self.pair_leaves = pair_leaves
        self.ignore_order = ignore_order

    def diff(self, left: Node, right: Node) -> List[Change]:
        out: List[Change] = []
        self._children(left, right, (), out)
        return out

    def _children(self, left: Node, right: Node, path: Tuple[str, ...], out: List[Change]) -> None:
        lk, rk = _keyed(left.children), _keyed(right.children)
        lmap, rmap = dict(lk), dict(rk)
        removed = [n for k, n in lk if k not in rmap]
        added_keys = {k for k, _ in rk if k not in lmap}

        if (
            self.pair_leaves
            and len(lk) == 1
            and len(rk) == 1
            and len(removed) == 1
            and len(added_keys) == 1
            and not lk[0][1].children
            and not rk[0][1].children
        ):
            out.append(Change("modify", path, lk[0][1], rk[0][1]))
            return

        ordered = (left.ordered or right.ordered) and not self.ignore_order
        lpos = {k: i for i, (k, _) in enumerate(lk)}
        moved: set = set()
        keep: set = set()
        if ordered:
            common = [k for k, _ in rk if k in lmap]
            keep = {common[i] for i in lis_indices([lpos[k] for k in common])}
            moved = {k for k in common if k not in keep}

        lidx = {id(n): i for i, (_, n) in enumerate(lk)}
        for n in removed:
            detail = {"position": lidx[id(n)] + 1} if ordered else {}
            out.append(Change("remove", path, n, None, detail))
        for idx, (k, n) in enumerate(rk):
            if k in added_keys:
                detail = _anchor(rk, idx, keep) if ordered else {}
                if ordered:
                    detail["position"] = idx + 1
                    detail["tail"] = all(kk in added_keys for kk, _ in rk[idx:])
                out.append(Change("add", path, None, n, detail))
                continue
            ln = lmap[k]
            if k in moved:
                detail = {"from": lpos[k] + 1, "to": idx + 1, **_anchor(rk, idx, keep)}
                out.append(Change("move", path, ln, n, detail))
            self._node(ln, n, path, out)

    def _node(self, ln: Node, rn: Node, path: Tuple[str, ...], out: List[Change]) -> None:
        if ln.members is not None or rn.members is not None:
            lm, rm = ln.members or (), rn.members or ()
            if Counter(lm) != Counter(rm):
                out.append(Change("modify", path, ln, rn, _members_detail(lm, rm)))
        elif ln.cmp != rn.cmp:
            out.append(Change("modify", path, ln, rn))
        if ln.inactive != rn.inactive:
            out.append(Change("deactivate" if rn.inactive else "activate", path, ln, rn))
        if ln.children or rn.children:
            self._children(ln, rn, path + (rn.text,), out)


def _anchor(rk: Keyed, idx: int, stable: set) -> Dict[str, Any]:
    """Reference element for 'insert X after/before Y'.

    Applying the inserts in target order, the predecessor of an element is
    always already in place, so "after predecessor" is correct. The first
    element has no predecessor: it is anchored before the first element that
    never moves (anchoring it to its successor would be wrong when that
    successor is relocated afterwards).
    """
    if idx > 0:
        return {"after": rk[idx - 1][1].text}
    for k, n in rk[1:]:
        if k in stable:
            return {"before": n.text}
    return {}


def summarize(changes: Sequence[Change]) -> Dict[str, int]:
    counts = {"added": 0, "removed": 0, "modified": 0, "moved": 0, "activated": 0, "deactivated": 0}
    names = {
        "add": "added",
        "remove": "removed",
        "modify": "modified",
        "move": "moved",
        "activate": "activated",
        "deactivate": "deactivated",
    }
    for c in changes:
        counts[names[c.op]] += 1
    counts["total"] = len(changes)
    return counts
