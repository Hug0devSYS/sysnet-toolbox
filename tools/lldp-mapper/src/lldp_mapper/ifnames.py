"""Interface-name matching across vendors and abbreviations.

CDP reports the neighbour's port as ``GigabitEthernet1/0/1``, the neighbour's
own ifName may be ``Gi1/0/1``, NX-OS uses ``Ethernet1/1`` and ``Eth1/1``.
Names are compared exactly first, then case-insensitively, then by an
abbreviation-insensitive key (first two letters of the type + the numbering).
"""

from __future__ import annotations

import re
from typing import Callable, Iterable, List, Optional, TypeVar

_SPLIT = re.compile(r"^([A-Za-z][A-Za-z-]*?)[\s-]?(\d.*)$")

# Types whose 2-letter prefix would collide or that are commonly abbreviated
# to something other than their first two letters.
_ALIASES = {
    "twentyfivegige": "tf",
    "twentyfivegigabitethernet": "tf",
    "twe": "tf",
    "fortygigabitethernet": "fo",
    "fortygige": "fo",
    "hundredgige": "hu",
    "hundredgigabitethernet": "hu",
    "fourhundredgige": "fh",
    "port-channel": "po",
    "portchannel": "po",
    "bundle-ether": "be",
    "management": "mg",
    "mgmt": "mg",
}

_JUNOS = re.compile(r"^(ge|xe|et|fe|ae|em|fxp|me|mge|irb|vme)-?\d", re.I)

T = TypeVar("T")


def canonical(name: str) -> str:
    """Abbreviation-insensitive key: ``GigabitEthernet1/0/1`` -> ``gi1/0/1``."""
    n = name.strip().lower().replace(" ", "")
    if _JUNOS.match(n):
        return re.sub(r"\.0$", "", n)  # Junos ge-0/0/0.0 is the unit 0 of ge-0/0/0
    m = _SPLIT.match(n)
    if not m:
        return n
    kind, rest = m.group(1), m.group(2)
    key = _ALIASES.get(kind, kind[:2])
    return key + rest


def match_name(candidates: Iterable[T], name: str, keys: Callable[[T], List[str]]) -> Optional[T]:
    """Best match of ``name`` among candidates; ``None`` when absent or ambiguous."""
    name = name.strip()
    if not name:
        return None
    items = list(candidates)
    for transform in (lambda s: s, str.lower, canonical):
        target = transform(name)
        hits = []
        for it in items:
            if any(k and transform(k) == target for k in keys(it)):
                hits.append(it)
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            return None
    return None


def match_interface(interfaces, name: str):
    return match_name(interfaces, name, lambda i: [i.name, i.descr])


def short(name: str) -> str:
    """Compact display form: ``GigabitEthernet1/0/1`` -> ``Gi1/0/1`` (others unchanged)."""
    m = _SPLIT.match(name.strip())
    if not m or _JUNOS.match(name):
        return name
    kind, rest = m.group(1), m.group(2)
    long_forms = {
        "gigabitethernet": "Gi",
        "tengigabitethernet": "Te",
        "fastethernet": "Fa",
        "twentyfivegige": "Twe",
        "fortygigabitethernet": "Fo",
        "hundredgige": "Hu",
        "ethernet": "Eth",
        "port-channel": "Po",
        "tengige": "Te",
    }
    ab = long_forms.get(kind.lower())
    return ab + rest if ab else name
