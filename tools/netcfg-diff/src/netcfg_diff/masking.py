"""Secret masking.

Secrets (password hashes, type-7 strings, pre-shared keys, SNMP communities,
FortiOS ``ENC`` blobs, private keys) are replaced *at parse time*, so they can
never reach the output. Three modes:

``mask``      (default) replaced by ``<secret:xxxxxxxx>``, an HMAC-SHA256
              fingerprint keyed with a random per-run key: equal secrets get
              equal fingerprints within one run (so a changed password shows
              up as a change), but fingerprints cannot be compared across runs
              or brute-forced offline.
``presence``  replaced by ``<secret>``: value changes are ignored, only the
              presence of the statement is compared (useful for FortiOS
              exports, where ``ENC`` values are re-salted on every backup).
``show``      no masking (explicit opt-in).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import List, Optional, Sequence, Tuple

MODES = ("mask", "presence", "show")

# Hashes and reversible encodings recognisable on their own, whatever the
# keyword in front of them: crypt(3) MD5/SHA, Cisco type 8/9, Junos $9$.
CRYPT_RE = re.compile(r'"?\$(?:1|5|6|7|8|9|14|y|2[aby]?)\$[^\s";]+"?')

_T = r"(?:[0-9]\s+)?"  # optional Cisco encryption type digit
CISCO_PATTERNS: Tuple[re.Pattern, ...] = tuple(
    re.compile(p)
    for p in (
        # enable secret/password, username ... secret/password, line password,
        # neighbor X password, ppp chap password, ...
        r"\b(?:secret|password)\s+(?!encryption\b)" + _T + r"(?P<s>\S+)",
        r"^passwd\s+(?P<s>\S+)",
        r"\bkey-string\s+" + _T + r"(?P<s>\S+)",
        r"^(?:tacacs-server|radius-server)\b.*?\bkey\s+" + _T + r"(?P<s>\S+)",
        r"^key\s+" + _T + r"(?P<s>(?!\d+$)\S+)$",
        r"^crypto isakmp key\s+" + _T + r"(?P<s>\S+)",
        r"\bpre-shared-key\s+(?:(?:local|remote)\s+)?(?:address\s+\S+(?:\s+[\d.]+)?\s+)?(?:key\s+)?"
        + _T
        + r"(?P<s>\S+)",
        r"^snmp-server community\s+(?P<s>\S+)",
        r"^snmp-server host\s+\S+(?:\s+(?:informs|traps))?(?:\s+version\s+(?:1|2c|3\s+\w+))?\s+(?P<s>\S+)",
        r"\bauth\s+(?:md5|sha\S*)\s+(?P<s>\S+)",
        r"\bpriv\s+(?:des\S*|3des|aes(?:\s+\d+)?)\s+(?P<s>\S+)",
        r"\bmd5\s+" + _T + r"(?P<s>\S+)",
        r"(?<!ntp )\bauthentication-key\s+" + _T + r"(?P<s>\S+)",
        r"\bwpa-psk\s+ascii\s+" + _T + r"(?P<s>\S+)",
    )
)

# Cheap pre-check: a line without any of these words cannot hold a secret
# recognised by CISCO_PATTERNS or CRYPT_RE.
PREFILTER_RE = re.compile(r"secret|passw|key|communit|snmp-server host|\bauth\b|\bpriv\b|md5|psk|\$")
MASKED_RE = re.compile(r"<secret(?::[0-9a-f]{8})?>")

# Junos: the token *following* one of these keywords is a secret.
JUNOS_SECRET_KEYWORDS = frozenset(
    {
        "encrypted-password",
        "plain-text-password-value",
        "secret",
        "authentication-key",
        "privacy-key",
        "ascii-text",
        "hexadecimal",
        "simple-password",
        "hello-authentication-key",
        "shared-secret",
        "pre-shared-key",
        "md5-key",
    }
)

# FortiOS attributes holding secrets (``set <attr> ...``).
FORTIOS_SECRET_ATTR = re.compile(
    r"(?:^|-)(?:pass(?:wd|word)?\d*|secret|psksecret\S*|private-key|key|auth-pwd|priv-pwd|"
    r"passphrase|token|community)$"
)
FORTIOS_PUBLIC_ATTR = re.compile(r"public-key")


class Masker:
    def __init__(self, mode: str = "mask", key: Optional[bytes] = None):
        if mode not in MODES:
            raise ValueError(f"unknown secrets mode {mode!r}")
        self.mode = mode
        self.key = key if key is not None else os.urandom(32)

    def token(self, secret: str) -> str:
        if self.mode == "show" or MASKED_RE.fullmatch(secret):
            return secret
        if self.mode == "presence":
            return "<secret>"
        fp = hmac.new(self.key, secret.strip('"').encode("utf-8", "replace"), hashlib.sha256)
        return f"<secret:{fp.hexdigest()[:8]}>"

    def line(self, text: str, patterns: Sequence[re.Pattern] = CISCO_PATTERNS) -> str:
        """Mask every secret found in one configuration line."""
        if self.mode == "show" or not PREFILTER_RE.search(text):
            return text
        spans: List[Tuple[int, int]] = []
        for p in patterns:
            for m in p.finditer(text):
                for name in ("s", "s2"):
                    if name in p.groupindex and m.group(name) is not None:
                        spans.append(m.span(name))
        spans.extend(m.span() for m in CRYPT_RE.finditer(text))
        if not spans:
            return text
        merged: List[Tuple[int, int]] = []
        for start, end in sorted(spans):
            if merged and start < merged[-1][1]:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        out = text
        for start, end in reversed(merged):
            out = out[:start] + self.token(out[start:end]) + out[end:]
        return out

    def is_crypt(self, token: str) -> bool:
        return CRYPT_RE.fullmatch(token) is not None
