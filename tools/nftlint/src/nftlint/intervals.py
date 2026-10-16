"""Closed integer interval sets over a bounded universe.

Every packet field nftlint models (addresses, ports, protocol numbers,
conntrack states, ...) is represented as a set of integers inside a fixed
universe ``[lo, hi]``. Sets are stored as sorted, merged, inclusive spans so
that set algebra (union, intersection, complement, subset) stays exact and
cheap even for the 2**128 IPv6 address space.
"""

from __future__ import annotations

from typing import Iterable, Iterator, Tuple

Span = Tuple[int, int]


class IntervalSet:
    """Immutable set of integers in ``[lo, hi]`` stored as merged spans."""

    __slots__ = ("lo", "hi", "spans")

    def __init__(self, lo: int, hi: int, spans: Iterable[Span] = ()) -> None:
        if lo > hi:
            raise ValueError("empty universe")
        self.lo = lo
        self.hi = hi
        clipped = []
        for a, b in spans:
            a, b = max(a, lo), min(b, hi)
            if a <= b:
                clipped.append((a, b))
        clipped.sort()
        merged: list[Span] = []
        for a, b in clipped:
            if merged and a <= merged[-1][1] + 1:
                if b > merged[-1][1]:
                    merged[-1] = (merged[-1][0], b)
            else:
                merged.append((a, b))
        self.spans: tuple[Span, ...] = tuple(merged)

    # -- constructors -----------------------------------------------------
    @classmethod
    def full(cls, lo: int, hi: int) -> IntervalSet:
        return cls(lo, hi, [(lo, hi)])

    @classmethod
    def empty(cls, lo: int, hi: int) -> IntervalSet:
        return cls(lo, hi)

    def _new(self, spans: Iterable[Span]) -> IntervalSet:
        return IntervalSet(self.lo, self.hi, spans)

    def _check(self, other: IntervalSet) -> None:
        if (self.lo, self.hi) != (other.lo, other.hi):
            raise ValueError("interval sets over different universes")

    # -- predicates -------------------------------------------------------
    def is_empty(self) -> bool:
        return not self.spans

    def is_full(self) -> bool:
        return self.spans == ((self.lo, self.hi),)

    def contains(self, value: int) -> bool:
        for a, b in self.spans:
            if value < a:
                return False
            if value <= b:
                return True
        return False

    def __contains__(self, value: int) -> bool:
        return self.contains(value)

    def issubset(self, other: IntervalSet) -> bool:
        self._check(other)
        return (self - other).is_empty()

    def size(self) -> int:
        return sum(b - a + 1 for a, b in self.spans)

    def universe_size(self) -> int:
        return self.hi - self.lo + 1

    # -- algebra ----------------------------------------------------------
    def complement(self) -> IntervalSet:
        out: list[Span] = []
        cur = self.lo
        for a, b in self.spans:
            if a > cur:
                out.append((cur, a - 1))
            cur = b + 1
        if cur <= self.hi:
            out.append((cur, self.hi))
        return self._new(out)

    def __or__(self, other: IntervalSet) -> IntervalSet:
        self._check(other)
        return self._new(self.spans + other.spans)

    def __and__(self, other: IntervalSet) -> IntervalSet:
        self._check(other)
        out: list[Span] = []
        i = j = 0
        a, b = self.spans, other.spans
        while i < len(a) and j < len(b):
            lo = max(a[i][0], b[j][0])
            hi = min(a[i][1], b[j][1])
            if lo <= hi:
                out.append((lo, hi))
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return self._new(out)

    def __sub__(self, other: IntervalSet) -> IntervalSet:
        return self & other.complement()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IntervalSet):
            return NotImplemented
        return (self.lo, self.hi, self.spans) == (other.lo, other.hi, other.spans)

    def __hash__(self) -> int:
        return hash((self.lo, self.hi, self.spans))

    def __iter__(self) -> Iterator[Span]:
        return iter(self.spans)

    def __repr__(self) -> str:
        return f"IntervalSet({self.lo}, {self.hi}, {list(self.spans)!r})"
