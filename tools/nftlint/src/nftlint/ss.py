"""Parser for ``ss -tlnp`` / ``ss -tulnp`` (with or without -H) output."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional

from .model import IPV4, IPV6

NETIDS = {"tcp", "udp", "sctp", "raw", "u_str", "u_dgr", "u_seq", "p_raw", "p_dgr", "nl", "mptcp"}
LISTEN_STATES = {"LISTEN", "UNCONN"}
USERS = re.compile(r'\("([^"]+)",pid=(\d+)')


@dataclass
class Listener:
    proto: str  # tcp | udp | sctp
    address: Optional[str]  # None = wildcard
    families: List[int]  # nfprotos the socket accepts traffic for
    port: int
    process: str = ""
    pid: Optional[int] = None
    scope: Optional[str] = None  # interface the socket is bound to (addr%iface)
    raw_address: str = ""

    @property
    def loopback(self) -> bool:
        if self.scope == "lo":
            return True
        if self.address is None:
            return False
        ip = ipaddress.ip_address(self.address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return ip.is_loopback

    def daddr(self, family: int) -> Optional[int]:
        if self.address is None:
            return None
        ip = ipaddress.ip_address(self.address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped and family == IPV4:
            return int(ip.ipv4_mapped)
        return int(ip)

    def to_dict(self) -> dict:
        return {
            "proto": self.proto,
            "address": self.raw_address,
            "port": self.port,
            "process": self.process or None,
            "pid": self.pid,
        }


class SsParseError(Exception):
    pass


def _split_hostport(text: str):
    if text.startswith("["):
        host, _, port = text[1:].partition("]:")
    else:
        host, _, port = text.rpartition(":")
    scope = None
    if "%" in host:
        host, scope = host.split("%", 1)
    return host, port, scope


def parse_ss(text: str, source: str = "ss") -> List[Listener]:
    out: List[Listener] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        cols = line.split()
        if cols[0] in ("State", "Netid"):
            continue
        netid = None
        if cols[0].lower() in NETIDS:
            netid = cols[0].lower()
            cols = cols[1:]
        if len(cols) < 4:
            raise SsParseError(f"{source}:{lineno}: unrecognised ss line: {line[:70]}")
        state = cols[0]
        if state not in LISTEN_STATES:
            continue
        proto = netid or ("tcp" if state == "LISTEN" else "udp")
        if proto not in ("tcp", "udp", "sctp", "mptcp"):
            continue
        if proto == "mptcp":
            proto = "tcp"
        host, port_s, scope = _split_hostport(cols[3])
        if not port_s.isdigit():
            continue
        address: Optional[str]
        if host in ("*", "0.0.0.0", "::", ""):
            address = None
            if host == "*":
                families = [IPV4, IPV6]
            elif host == "0.0.0.0":
                families = [IPV4]
            else:
                families = [IPV6]
        else:
            try:
                ip = ipaddress.ip_address(host)
            except ValueError as exc:
                raise SsParseError(f"{source}:{lineno}: invalid address {host!r}") from exc
            address = str(ip)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                families = [IPV4]
            else:
                families = [IPV4 if ip.version == 4 else IPV6]
        rest = " ".join(cols[5:])
        m = USERS.search(rest)
        out.append(
            Listener(
                proto=proto,
                address=address,
                families=families,
                port=int(port_s),
                process=m.group(1) if m else "",
                pid=int(m.group(2)) if m else None,
                scope=scope,
                raw_address=cols[3].rsplit(":", 1)[0],
            )
        )
    return out
