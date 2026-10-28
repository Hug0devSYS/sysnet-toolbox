"""Conversions from textual ruleset values to integers and interval sets."""

from __future__ import annotations

import ipaddress
import socket
from typing import Dict, List, Union

from .intervals import IntervalSet
from .model import BOUNDS, CT_STATES, CTSTATE, DPORT, FAMILY_OF_DIM, L4PROTO, NFPROTO, SPORT

PROTOCOLS = {
    "hopopt": 0,
    "icmp": 1,
    "igmp": 2,
    "ipip": 4,
    "ipencap": 4,
    "tcp": 6,
    "egp": 8,
    "udp": 17,
    "ipv6": 41,
    "rsvp": 46,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "icmpv6": 58,
    "ipv6-icmp": 58,
    "eigrp": 88,
    "ospf": 89,
    "ospfigp": 89,
    "pim": 103,
    "vrrp": 112,
    "l2tp": 115,
    "sctp": 132,
    "udplite": 136,
    "dccp": 33,
    "mpls-in-ip": 137,
    "ethernet": 143,
}
PROTOCOL_NAMES = {v: k for k, v in reversed(list(PROTOCOLS.items()))}
PROTOCOL_NAMES[58] = "ipv6-icmp"
PROTOCOL_NAMES[4] = "ipip"

# Ports that usually deserve a restricted source list. Overridable with
# --sensitive-ports.
DEFAULT_SENSITIVE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    161: "snmp",
    389: "ldap",
    445: "smb",
    623: "ipmi",
    873: "rsync",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    2379: "etcd",
    2380: "etcd-peer",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-tls",
    6379: "redis",
    6443: "kube-apiserver",
    8500: "consul",
    9200: "elasticsearch",
    10250: "kubelet",
    11211: "memcached",
    27017: "mongodb",
}


# Services of the built-in list that are also (or only) reached over UDP. The others
# are TCP-only, so an accepted UDP port 1433 is not "mssql open to the world".
DEFAULT_UDP_SENSITIVE = frozenset({111, 161, 389, 623, 2049, 3389, 11211})


def sensitive_for(sensitive: Dict[int, str], udp_only: bool) -> Dict[int, str]:
    """The sensitive ports relevant to a UDP-only match or socket.

    Only the built-in list is narrowed; a list given with --sensitive-ports applies
    to every protocol, as written by the user.
    """
    if not udp_only or sensitive is not DEFAULT_SENSITIVE_PORTS:
        return sensitive
    return {p: n for p, n in sensitive.items() if p in DEFAULT_UDP_SENSITIVE}


class Unsupported(ValueError):
    """Raised when a ruleset value cannot be modelled."""


Scalar = Union[int, str]


def protocol_number(value: Scalar) -> int:
    if isinstance(value, int):
        if 0 <= value <= 255:
            return value
        raise Unsupported(f"protocol out of range: {value}")
    v = value.strip().lower()
    if v.isdigit():
        return protocol_number(int(v))
    if v in PROTOCOLS:
        return PROTOCOLS[v]
    try:
        return socket.getprotobyname(v)
    except OSError as exc:
        raise Unsupported(f"unknown protocol {value!r}") from exc


def port_number(value: Scalar) -> int:
    if isinstance(value, int):
        if 0 <= value <= 65535:
            return value
        raise Unsupported(f"port out of range: {value}")
    v = value.strip()
    if v.isdigit():
        return port_number(int(v))
    try:
        return socket.getservbyname(v)
    except OSError as exc:
        raise Unsupported(f"unknown service {value!r}") from exc


def ct_state_index(value: Scalar) -> int:
    v = str(value).strip().lower()
    if v in CT_STATES:
        return CT_STATES.index(v)
    raise Unsupported(f"unsupported conntrack state {value!r}")


def nfproto_index(value: Scalar) -> int:
    v = str(value).strip().lower()
    if v in ("ipv4", "ip", "2"):
        return 0
    if v in ("ipv6", "ip6", "10"):
        return 1
    raise Unsupported(f"unsupported nfproto {value!r}")


def address_span(dim: str, text: str) -> tuple:
    """Return the integer span covered by an address, CIDR or a-b range."""
    want = 4 if FAMILY_OF_DIM[dim] == 0 else 6
    text = text.strip()
    if "-" in text and "/" not in text:
        a, b = text.split("-", 1)
        try:
            lo = ipaddress.ip_address(a.strip())
            hi = ipaddress.ip_address(b.strip())
        except ValueError as exc:
            raise Unsupported(f"invalid address range {text!r}") from exc
        if int(lo) > int(hi):
            raise Unsupported(f"empty address range {text!r}")
        if lo.version != want or hi.version != want:
            raise Unsupported(f"address family mismatch in {text!r}")
        return int(lo), int(hi)
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise Unsupported(f"invalid address {text!r}") from exc
    if net.version != want:
        raise Unsupported(f"address family mismatch in {text!r}")
    return int(net.network_address), int(net.broadcast_address)


def scalar_to_int(dim: str, value: Scalar) -> int:
    if dim == L4PROTO:
        return protocol_number(value)
    if dim in (SPORT, DPORT):
        return port_number(value)
    if dim == CTSTATE:
        return ct_state_index(value)
    if dim == NFPROTO:
        return nfproto_index(value)
    raise Unsupported(f"no scalar conversion for {dim}")


def to_set(dim: str, spans: List[tuple]) -> IntervalSet:
    lo, hi = BOUNDS[dim]
    return IntervalSet(lo, hi, spans)


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
def format_addresses(iset: IntervalSet, version: int, limit: int = 6) -> str:
    if iset.is_full():
        return "any"
    if iset.is_empty():
        return "none"
    if iset.size() * 2 > iset.universe_size():
        return "any except " + format_addresses(iset.complement(), version, limit)
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    nets: List[str] = []
    total = 0
    for a, b in iset:
        for net in ipaddress.summarize_address_range(cls(a), cls(b)):
            total += 1
            if len(nets) < limit:
                nets.append(str(net))
    if total > limit:
        nets.append(f"... (+{total - limit} more)")
    return ", ".join(nets)


def format_ports(iset: IntervalSet, limit: int = 12) -> str:
    if iset.is_full():
        return "any"
    parts = [str(a) if a == b else f"{a}-{b}" for a, b in iset]
    if len(parts) > limit:
        parts = parts[:limit] + [f"... (+{len(parts) - limit} more)"]
    return ",".join(parts)


def format_protocols(iset: IntervalSet) -> str:
    if iset.is_full():
        return "any"
    out = []
    for a, b in iset:
        if b - a > 8:
            out.append(f"{a}-{b}")
        else:
            out.extend(PROTOCOL_NAMES.get(p, str(p)) for p in range(a, b + 1))
    return ",".join(out)
