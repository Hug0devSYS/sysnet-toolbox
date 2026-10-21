"""Vendor detection and parsing entry point."""

from __future__ import annotations

import re
from typing import List, Optional, Sequence

from . import cisco, fortios, junos
from .masking import Masker
from .model import FAMILIES, Config, prune

_FORTI_CMD = re.compile(r"^\s*(config|edit|set|unset|next|end)\b")
_JUNOS_BRACE = re.compile(r"(?:\{|;|\})\s*(?:#.*|/\*.*\*/)?$")


def detect(text: str) -> str:
    """Best-effort vendor detection from the content of a configuration."""
    lines = [ln.rstrip() for ln in text.lstrip("﻿")[:500_000].splitlines() if ln.strip()][:5000]
    if not lines:
        return "ios"
    head = "\n".join(lines[:60])
    if re.search(r"^#config-version=", head, re.M):
        return "fortios"
    forti = [m.group(1) for m in map(_FORTI_CMD.match, lines) if m]
    if forti and "config" in forti and ("end" in forti) and len(forti) >= 0.8 * len(lines):
        return "fortios"
    if junos.is_set_format(lines):
        return "junos"
    if re.search(r"^## Last (?:commit|changed):", head, re.M):
        return "junos"
    brace = sum(1 for ln in lines if _JUNOS_BRACE.search(ln))
    if brace >= 0.7 * len(lines):
        return "junos"
    body = "\n".join(lines[:3000])
    if re.search(r"^!! IOS XR|^RP/\d+/\S+#|^end-policy$|^end-set$", body, re.M):
        return "iosxr"
    if re.search(r"^!Command: show running-config|^feature \S+|^vdc \S+ id \d+", body, re.M):
        return "nxos"
    if re.search(
        r"^! device: |^! boot system flash:|^management api http-commands|^transceiver qsfp", body, re.M
    ):
        return "eos"
    return "ios"


def load(
    text: str,
    vendor: str = "auto",
    masker: Optional[Masker] = None,
    ignore: Sequence[re.Pattern] = (),
    keep_volatile: bool = False,
) -> Config:
    """Parse ``text`` and drop ignored / volatile statements."""
    if vendor == "auto":
        vendor = detect(text)
    if vendor not in FAMILIES:
        raise ValueError(f"unknown vendor {vendor!r}")
    masker = masker or Masker()
    family = FAMILIES[vendor]
    patterns: List[re.Pattern] = list(ignore)
    if family == "cisco":
        cfg = cisco.parse(text, vendor, masker)
        if not keep_volatile:
            patterns.extend(cisco.VOLATILE)
        cfg.meta["removed"] = str(prune(cfg.root, patterns))
    elif family == "junos":
        cfg = junos.parse(text, vendor, masker)
        cfg.meta["removed"] = str(prune(cfg.root, patterns, on_path=True, drop_emptied=True))
    else:
        cfg = fortios.parse(text, vendor, masker)
        cfg.meta["removed"] = str(prune(cfg.root, patterns))
    return cfg
