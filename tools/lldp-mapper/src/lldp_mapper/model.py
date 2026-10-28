"""Data model: what was read from each device, and the resulting topology."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

SEVERITIES = ("info", "unknown", "warning", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Interface:
    ifindex: int
    name: str = ""  # ifName
    descr: str = ""  # ifDescr
    alias: str = ""  # ifAlias
    speed_mbps: Optional[int] = None  # ifHighSpeed
    oper_up: Optional[bool] = None
    duplex: Optional[str] = None  # "full" / "half" (EtherLike-MIB dot3StatsDuplexStatus)
    pvid: Optional[int] = None
    pvid_source: str = ""

    @property
    def label(self) -> str:
        return self.name or self.descr or f"ifIndex {self.ifindex}"


@dataclass
class LocalPort:
    """An LLDP local port (lldpLocPortTable) and its local dot1/dot3 extensions."""

    num: int
    id_subtype: int = 0
    port_id: bytes = b""
    desc: str = ""
    ifindex: Optional[int] = None
    ifindex_how: str = ""
    pvid: Optional[int] = None
    mau: Optional[int] = None
    autoneg_supported: Optional[bool] = None
    autoneg_enabled: Optional[bool] = None


@dataclass
class Neighbor:
    """One LLDP remote entry or CDP cache entry, as seen by a polled device."""

    protocol: str  # "lldp" / "cdp"
    local_key: int  # lldpRemLocalPortNum (LLDP) or ifIndex (CDP)
    local_port: str = ""  # resolved local interface name
    local_ifindex: Optional[int] = None
    chassis_subtype: int = 0
    chassis_id: str = ""  # formatted
    port_subtype: int = 0
    port_id_raw: bytes = b""
    port_id: str = ""  # formatted
    port_desc: str = ""
    sys_name: str = ""
    sys_descr: str = ""
    platform: str = ""
    caps: List[str] = field(default_factory=list)
    mgmt_addrs: List[str] = field(default_factory=list)
    pvid: Optional[int] = None
    mau: Optional[int] = None
    duplex: Optional[str] = None
    speed_mbps: Optional[int] = None
    autoneg_supported: Optional[bool] = None
    autoneg_enabled: Optional[bool] = None

    @property
    def name(self) -> str:
        return self.sys_name or self.chassis_id

    @property
    def port_label(self) -> str:
        if self.protocol == "lldp" and self.port_subtype == 3 and self.port_desc:
            return self.port_desc  # MAC port IDs are unreadable; prefer the description
        return self.port_id or self.port_desc


@dataclass
class Device:
    """A polled device."""

    target: str
    sys_name: str = ""
    sys_descr: str = ""
    sys_object_id: str = ""
    chassis_subtype: int = 0
    chassis_id: str = ""
    cdp_device_id: str = ""
    addresses: List[str] = field(default_factory=list)
    interfaces: Dict[int, Interface] = field(default_factory=dict)
    lldp_ports: Dict[int, LocalPort] = field(default_factory=dict)
    neighbors: List[Neighbor] = field(default_factory=list)
    lldp_supported: bool = False
    cdp_supported: bool = False
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    depth: int = 0
    requests: int = 0
    duration_s: float = 0.0

    @property
    def name(self) -> str:
        return self.sys_name or self.cdp_device_id or self.target

    @property
    def ok(self) -> bool:
        return self.error is None

    def iface_by_label(self, label: str) -> Optional[Interface]:
        from .ifnames import match_interface

        return match_interface(self.interfaces.values(), label)


@dataclass
class Node:
    id: str
    name: str
    polled: bool = False
    target: str = ""
    chassis_id: str = ""
    mgmt_addrs: List[str] = field(default_factory=list)
    platform: str = ""
    caps: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class EndpointFacts:
    """Layer-1/2 facts of one end of a link, with where each fact came from."""

    duplex: Optional[str] = None
    duplex_src: str = ""
    speed_mbps: Optional[int] = None
    speed_src: str = ""
    autoneg_supported: Optional[bool] = None
    autoneg_enabled: Optional[bool] = None
    autoneg_src: str = ""
    pvid: Optional[int] = None
    pvid_src: str = ""

    def as_dict(self) -> dict:
        out: dict = {}
        if self.duplex:
            out["duplex"] = {"value": self.duplex, "source": self.duplex_src}
        if self.speed_mbps:
            out["speed_mbps"] = {"value": self.speed_mbps, "source": self.speed_src}
        if self.autoneg_enabled is not None:
            out["autoneg"] = {
                "enabled": self.autoneg_enabled,
                "supported": self.autoneg_supported,
                "source": self.autoneg_src,
            }
        if self.pvid:
            out["native_vlan"] = {"value": self.pvid, "source": self.pvid_src}
        return out


@dataclass
class Endpoint:
    node: str
    port: str
    facts: EndpointFacts = field(default_factory=EndpointFacts)
    resolved: bool = False  # the port is a known port of a polled device


@dataclass
class Link:
    a: Endpoint
    b: Endpoint
    protocols: List[str] = field(default_factory=list)
    seen_from: List[str] = field(default_factory=list)  # node ids that reported the adjacency
    findings: List[str] = field(default_factory=list)  # finding codes attached to this link

    @property
    def key(self) -> Tuple[Tuple[str, str], Tuple[str, str]]:
        ends = sorted([(self.a.node, self.a.port), (self.b.node, self.b.port)])
        return ends[0], ends[1]

    @property
    def bidirectional(self) -> bool:
        return self.a.node in self.seen_from and self.b.node in self.seen_from


@dataclass
class Finding:
    code: str
    severity: str
    message: str
    node: Optional[str] = None
    port: Optional[str] = None
    peer: Optional[str] = None
    peer_port: Optional[str] = None
    detail: Dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict:
        out = {"code": self.code, "severity": self.severity, "message": self.message}
        for k in ("node", "port", "peer", "peer_port"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        if self.detail:
            out["detail"] = self.detail
        return out
