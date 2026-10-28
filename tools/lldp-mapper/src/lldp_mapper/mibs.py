"""MIB knowledge: which subtrees are walked and how they are decoded into a Device.

MIBs used (all read-only):

* SNMPv2-MIB system group, IF-MIB ifTable/ifXTable, IP-MIB ipAdEntAddr
* LLDP-MIB (IEEE 802.1AB-2005, 1.0.8802.1.1.2): local system and ports,
  remote table, remote management addresses
* LLDP-EXT-DOT1-MIB: port VLAN ID (PVID) local and remote
* LLDP-EXT-DOT3-MIB: auto-negotiation and operational MAU type, local and remote
* EtherLike-MIB dot3StatsDuplexStatus
* Q-BRIDGE-MIB dot1qPvid + BRIDGE-MIB dot1dBasePortIfIndex
* CISCO-CDP-MIB cache table, CISCO-VTP-MIB trunk native VLAN,
  CISCO-VLAN-MEMBERSHIP-MIB access VLAN
"""

from __future__ import annotations

import ipaddress
import time
from typing import Callable, Dict, List, Optional, Tuple

from . import ber
from .ber import OID, Value
from .ifnames import match_name
from .model import Device, Interface, LocalPort, Neighbor
from .snmp import SnmpError, SnmpTimeout, Varbinds

LLDP = (1, 0, 8802, 1, 1, 2, 1)
LLDP_DOT1 = LLDP + (5, 32962, 1)
LLDP_DOT3 = LLDP + (5, 4623, 1)
CDP = (1, 3, 6, 1, 4, 1, 9, 9, 23, 1)

# (key, root, required). The first walk doubles as the reachability check.
WALKS: List[Tuple[str, OID]] = [
    ("sysName", (1, 3, 6, 1, 2, 1, 1, 5)),
    ("sysDescr", (1, 3, 6, 1, 2, 1, 1, 1)),
    ("sysObjectID", (1, 3, 6, 1, 2, 1, 1, 2)),
    ("ifDescr", (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)),
    ("ifOperStatus", (1, 3, 6, 1, 2, 1, 2, 2, 1, 8)),
    ("ifName", (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1)),
    ("ifHighSpeed", (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15)),
    ("ifAlias", (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18)),
    ("ipAdEntAddr", (1, 3, 6, 1, 2, 1, 4, 20, 1, 1)),
    ("dot3StatsDuplexStatus", (1, 3, 6, 1, 2, 1, 10, 7, 2, 1, 19)),
    ("lldpLocalSystemData", LLDP + (3,)),
    ("lldpRemTable", LLDP + (4, 1, 1)),
    ("lldpRemManAddrTable", LLDP + (4, 2, 1)),
    ("lldpXdot1LocPortVlanId", LLDP_DOT1 + (2, 1, 1, 1)),
    ("lldpXdot1RemPortVlanId", LLDP_DOT1 + (3, 1, 1, 1)),
    ("lldpXdot3LocPortAutoNegTable", LLDP_DOT3 + (2, 1, 1)),
    ("lldpXdot3RemPortAutoNegTable", LLDP_DOT3 + (3, 1, 1)),
    ("dot1qPvid", (1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 1)),
    ("dot1dBasePortIfIndex", (1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2)),
    ("cdpCacheTable", CDP + (2, 1, 1)),
    ("cdpGlobalDeviceId", CDP + (3, 4)),
    ("vlanTrunkPortNativeVlan", (1, 3, 6, 1, 4, 1, 9, 9, 46, 1, 6, 1, 1, 5)),
    ("vlanTrunkPortDynamicStatus", (1, 3, 6, 1, 4, 1, 9, 9, 46, 1, 6, 1, 1, 14)),
    ("vmVlan", (1, 3, 6, 1, 4, 1, 9, 9, 68, 1, 2, 2, 1, 2)),
]
WALK_ROOTS = dict(WALKS)

CISCO_ONLY = {"cdpCacheTable", "cdpGlobalDeviceId", "vlanTrunkPortNativeVlan", "vlanTrunkPortDynamicStatus", "vmVlan"}

CHASSIS_SUBTYPES = {
    1: "chassisComponent",
    2: "interfaceAlias",
    3: "portComponent",
    4: "macAddress",
    5: "networkAddress",
    6: "interfaceName",
    7: "local",
}
PORT_SUBTYPES = {
    1: "interfaceAlias",
    2: "portComponent",
    3: "macAddress",
    4: "networkAddress",
    5: "interfaceName",
    6: "agentCircuitId",
    7: "local",
}
LLDP_CAPS = [
    "other",
    "repeater",
    "bridge",
    "wlanAccessPoint",
    "router",
    "telephone",
    "docsisCableDevice",
    "stationOnly",
    "cVLAN",
    "sVLAN",
    "twoPortMacRelay",
]
CDP_CAPS = [
    (0x01, "router"),
    (0x02, "bridge"),
    (0x04, "bridge"),
    (0x08, "bridge"),
    (0x10, "stationOnly"),
    (0x40, "repeater"),
    (0x80, "telephone"),
    (0x400, "twoPortMacRelay"),
]

# IANA-MAU-MIB dot3MauType list positions (as used by lldpXdot3*PortOperMauType).
MAU_TYPES = {
    10: "10BaseTHD",
    11: "10BaseTFD",
    12: "10BaseFLHD",
    13: "10BaseFLFD",
    14: "100BaseT4",
    15: "100BaseTXHD",
    16: "100BaseTXFD",
    17: "100BaseFXHD",
    18: "100BaseFXFD",
    19: "100BaseT2HD",
    20: "100BaseT2FD",
    21: "1000BaseXHD",
    22: "1000BaseXFD",
    23: "1000BaseLXHD",
    24: "1000BaseLXFD",
    25: "1000BaseSXHD",
    26: "1000BaseSXFD",
    27: "1000BaseCXHD",
    28: "1000BaseCXFD",
    29: "1000BaseTHD",
    30: "1000BaseTFD",
    31: "10GigBaseX",
    32: "10GigBaseLX4",
    33: "10GigBaseR",
    34: "10GigBaseER",
    35: "10GigBaseLR",
    36: "10GigBaseSR",
    37: "10GigBaseW",
    38: "10GigBaseEW",
    39: "10GigBaseLW",
    40: "10GigBaseSW",
    41: "10GigBaseCX4",
    44: "100BaseBX10D",
    45: "100BaseBX10U",
    46: "100BaseLX10",
    47: "1000BaseBX10D",
    48: "1000BaseBX10U",
    49: "1000BaseLX10",
    50: "1000BasePX10D",
    51: "1000BasePX10U",
    52: "1000BasePX20D",
    53: "1000BasePX20U",
    54: "10GbaseT",
    55: "10GbaseLRM",
    56: "1000baseKX",
    57: "10GbaseKX4",
    58: "10GbaseKR",
}


def mau_info(mau: Optional[int]) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """(name, speed in Mb/s, duplex) of a MAU type; unknown parts are None."""
    if not mau or mau not in MAU_TYPES:
        return None, None, None
    name = MAU_TYPES[mau]
    low = name.lower()
    if low.startswith(("10gig", "10gbase")):
        return name, 10000, "full"  # 10 Gb/s and faster are full-duplex only
    speed = 1000 if low.startswith("1000") else 100 if low.startswith("100b") else 10
    duplex = "half" if name.endswith("HD") else "full" if name.endswith("FD") else None
    if speed == 1000 and duplex is None:
        duplex = "full"  # 1000BASE-KX/LX10/BX/PX are full-duplex only
    if 44 <= mau <= 46:
        duplex = "full"
    return name, speed, duplex


# --------------------------------------------------------------------------- decoding helpers


def text(v: Optional[Value]) -> str:
    if v is None or not isinstance(v.value, (bytes, bytearray)):
        return "" if v is None else str(v.value)
    raw = bytes(v.value).rstrip(b"\x00")
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        s = raw.decode("latin-1")
    return "".join(c if c.isprintable() else "?" for c in s).strip()


def integer(v: Optional[Value]) -> Optional[int]:
    if v is None or not isinstance(v.value, int):
        return None
    return v.value


def truth(v: Optional[Value]) -> Optional[bool]:
    n = integer(v)
    return None if n is None else n == 1  # TruthValue: true(1), false(2)


def mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _printable(raw: bytes) -> Optional[str]:
    try:
        s = raw.rstrip(b"\x00").decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if s and all(c.isprintable() for c in s) else None


def address(family: int, raw: bytes) -> str:
    """IANA address family (1 IPv4, 2 IPv6) + raw bytes to text."""
    try:
        if family == 1 and len(raw) == 4:
            return str(ipaddress.IPv4Address(raw))
        if family == 2 and len(raw) == 16:
            return str(ipaddress.IPv6Address(raw))
    except ValueError:
        pass
    return raw.hex()


def format_id(subtype: int, raw: bytes, mac_subtype: int) -> str:
    """Format an LLDP chassis or port ID according to its subtype."""
    if subtype == mac_subtype and len(raw) == 6:
        return mac(raw)
    if subtype == mac_subtype + 1 and len(raw) >= 2:  # networkAddress: family octet + address
        return address(raw[0], raw[1:])
    s = _printable(raw)
    if s is not None:
        return s
    return mac(raw) if len(raw) == 6 else raw.hex()


def caps_from_bits(raw: bytes) -> List[str]:
    out = []
    for i, name in enumerate(LLDP_CAPS):
        byte, bit = divmod(i, 8)
        if byte < len(raw) and raw[byte] & (0x80 >> bit):
            out.append(name)
    return out


def caps_from_cdp(raw: bytes) -> List[str]:
    n = int.from_bytes(raw[-4:], "big") if raw else 0
    out: List[str] = []
    for bit, name in CDP_CAPS:
        if n & bit and name not in out:
            out.append(name)
    return out


def table(varbinds: Varbinds, root: OID) -> Dict[int, Dict[OID, Value]]:
    """Column number -> {index: value} for a walked table entry ``root``."""
    out: Dict[int, Dict[OID, Value]] = {}
    n = len(root)
    for oid, v in varbinds:
        if len(oid) <= n + 1 or oid[:n] != root:
            continue
        out.setdefault(oid[n], {})[oid[n + 1 :]] = v
    return out


def column(varbinds: Varbinds, root: OID) -> Dict[OID, Value]:
    n = len(root)
    return {oid[n:]: v for oid, v in varbinds if len(oid) > n and oid[:n] == root}


def scalar(varbinds: Varbinds) -> Optional[Value]:
    return varbinds[0][1] if varbinds else None


# --------------------------------------------------------------------------- collection

Walker = Callable[[OID], Varbinds]


def walk_all(walk: Walker, skip: Tuple[str, ...] = ()) -> Tuple[Dict[str, Varbinds], List[str]]:
    """Walk every subtree; return the data and non-fatal warnings.

    The first walk is the reachability probe: its failure is fatal. After that,
    a failing subtree is recorded as a warning and the others are still walked,
    unless the agent stops answering altogether (two consecutive timeouts).
    """
    data: Dict[str, Varbinds] = {}
    warnings: List[str] = []
    timeouts = 0
    for i, (key, root) in enumerate(WALKS):
        if key in skip:
            continue
        try:
            data[key] = walk(root)
            timeouts = 0
        except SnmpTimeout as exc:
            if i == 0:
                raise
            timeouts += 1
            warnings.append(f"{key}: {exc}")
            if timeouts >= 2:
                warnings.append("agent stopped answering: remaining tables skipped")
                break
        except SnmpError as exc:
            if i == 0:
                raise
            warnings.append(f"{key}: {exc}")
    return data, warnings


def build_device(target: str, data: Dict[str, Varbinds]) -> Device:
    dev = Device(target=target)
    g = data.get
    dev.sys_name = text(scalar(g("sysName", [])))
    dev.sys_descr = text(scalar(g("sysDescr", [])))
    oid_v = scalar(g("sysObjectID", []))
    if oid_v is not None and isinstance(oid_v.value, tuple):
        dev.sys_object_id = ber.format_oid(oid_v.value)

    # ---- interfaces
    def per_ifindex(key: str) -> Dict[int, Value]:
        return {idx[0]: v for idx, v in column(g(key, []), WALK_ROOTS[key]).items() if len(idx) == 1}

    for key, attr in (("ifDescr", "descr"), ("ifName", "name"), ("ifAlias", "alias")):
        for ifindex, v in per_ifindex(key).items():
            setattr(dev.interfaces.setdefault(ifindex, Interface(ifindex)), attr, text(v))
    for ifindex, v in per_ifindex("ifHighSpeed").items():
        n = integer(v)
        if ifindex in dev.interfaces and n:
            dev.interfaces[ifindex].speed_mbps = n
    for ifindex, v in per_ifindex("ifOperStatus").items():
        if ifindex in dev.interfaces and integer(v) is not None:
            dev.interfaces[ifindex].oper_up = integer(v) == 1
    for ifindex, v in per_ifindex("dot3StatsDuplexStatus").items():
        if ifindex in dev.interfaces:
            dev.interfaces[ifindex].duplex = {2: "half", 3: "full"}.get(integer(v) or 0)

    for v in column(g("ipAdEntAddr", []), WALK_ROOTS["ipAdEntAddr"]).values():
        if isinstance(v.value, bytes) and len(v.value) == 4:
            addr = str(ipaddress.IPv4Address(v.value))
            if not addr.startswith("127."):
                dev.addresses.append(addr)

    _native_vlans(dev, data)

    # ---- LLDP local
    loc = g("lldpLocalSystemData", [])
    loc_root = WALK_ROOTS["lldpLocalSystemData"]
    loc_scalars = {oid[len(loc_root) :]: v for oid, v in loc}
    dev.chassis_subtype = integer(loc_scalars.get((1, 0))) or 0
    chassis_raw = loc_scalars.get((2, 0))
    if chassis_raw is not None and isinstance(chassis_raw.value, bytes):
        dev.chassis_id = format_id(dev.chassis_subtype, chassis_raw.value, 4)
    if not dev.sys_name:
        dev.sys_name = text(loc_scalars.get((3, 0)))
    ports = table(loc, loc_root + (7, 1))
    for idx, v in ports.get(2, {}).items():
        lp = dev.lldp_ports.setdefault(idx[0], LocalPort(idx[0]))
        lp.id_subtype = integer(v) or 0
    for idx, v in ports.get(3, {}).items():
        lp = dev.lldp_ports.setdefault(idx[0], LocalPort(idx[0]))
        lp.port_id = bytes(v.value) if isinstance(v.value, bytes) else b""
    for idx, v in ports.get(4, {}).items():
        dev.lldp_ports.setdefault(idx[0], LocalPort(idx[0])).desc = text(v)
    for idx, v in column(g("lldpXdot1LocPortVlanId", []), WALK_ROOTS["lldpXdot1LocPortVlanId"]).items():
        if idx and idx[0] in dev.lldp_ports and integer(v):
            dev.lldp_ports[idx[0]].pvid = integer(v)
    an = table(g("lldpXdot3LocPortAutoNegTable", []), WALK_ROOTS["lldpXdot3LocPortAutoNegTable"])
    for col, attr in ((1, "autoneg_supported"), (2, "autoneg_enabled")):
        for idx, v in an.get(col, {}).items():
            if idx and idx[0] in dev.lldp_ports:
                setattr(dev.lldp_ports[idx[0]], attr, truth(v))
    for idx, v in an.get(4, {}).items():
        if idx and idx[0] in dev.lldp_ports:
            dev.lldp_ports[idx[0]].mau = integer(v)
    for lp in dev.lldp_ports.values():
        _resolve_local_port(dev, lp)
    dev.lldp_supported = bool(loc) or bool(g("lldpRemTable"))

    # ---- LLDP remote
    _lldp_neighbors(dev, data)
    # ---- CDP
    gid = scalar(g("cdpGlobalDeviceId", []))
    dev.cdp_device_id = text(gid)
    _cdp_neighbors(dev, data)
    dev.cdp_supported = bool(g("cdpCacheTable")) or bool(dev.cdp_device_id)
    return dev


def _resolve_local_port(dev: Device, lp: LocalPort) -> None:
    """Map an LLDP local port number to an ifIndex (they are not guaranteed to be equal)."""
    ifaces = list(dev.interfaces.values())
    pid = _printable(lp.port_id) if lp.id_subtype in (1, 5, 7) else None
    candidates: List[Tuple[str, Optional[str]]] = []
    if lp.id_subtype == 1 and pid:
        hit = match_name(ifaces, pid, lambda i: [i.alias])
        if hit:
            lp.ifindex, lp.ifindex_how = hit.ifindex, "port-id=ifAlias"
            return
    if pid:
        candidates.append(("port-id", pid))
    if lp.desc:
        candidates.append(("port-desc", lp.desc))
    for how, name in candidates:
        hit = match_name(ifaces, name or "", lambda i: [i.name, i.descr])
        if hit:
            lp.ifindex, lp.ifindex_how = hit.ifindex, f"{how}=ifName/ifDescr"
            return
    if lp.id_subtype == 7 and pid and pid.isdigit() and int(pid) in dev.interfaces:
        lp.ifindex, lp.ifindex_how = int(pid), "port-id=ifIndex"  # Junos: local port ID is the ifIndex
        return
    if lp.num in dev.interfaces:
        lp.ifindex, lp.ifindex_how = lp.num, "port-num=ifIndex (assumed)"


def local_port_name(dev: Device, lp: Optional[LocalPort], fallback: str = "") -> Tuple[str, Optional[int]]:
    if lp is None:
        return fallback, None
    if lp.ifindex is not None and lp.ifindex in dev.interfaces:
        return dev.interfaces[lp.ifindex].label, lp.ifindex
    pid = _printable(lp.port_id) if lp.id_subtype in (1, 5, 7) else None
    return (pid or lp.desc or f"port {lp.num}"), None


def _lldp_neighbors(dev: Device, data: Dict[str, Varbinds]) -> None:
    root = WALK_ROOTS["lldpRemTable"]
    rem = table(data.get("lldpRemTable", []), root)
    rows: Dict[OID, Neighbor] = {}
    for idx in set().union(*[set(c) for c in rem.values()]) if rem else set():
        if len(idx) != 3:
            continue
        rows[idx] = Neighbor(protocol="lldp", local_key=idx[1])

    def col(n: int) -> Dict[OID, Value]:
        return rem.get(n, {})

    for idx, nb in rows.items():
        nb.chassis_subtype = integer(col(4).get(idx)) or 0
        raw = col(5).get(idx)
        if raw is not None and isinstance(raw.value, bytes):
            nb.chassis_id = format_id(nb.chassis_subtype, raw.value, 4)
        nb.port_subtype = integer(col(6).get(idx)) or 0
        raw = col(7).get(idx)
        if raw is not None and isinstance(raw.value, bytes):
            nb.port_id_raw = raw.value
            nb.port_id = format_id(nb.port_subtype, raw.value, 3)
        nb.port_desc = text(col(8).get(idx))
        nb.sys_name = text(col(9).get(idx))
        nb.sys_descr = text(col(10).get(idx))
        caps = col(12).get(idx) or col(11).get(idx)
        if caps is not None and isinstance(caps.value, bytes):
            nb.caps = caps_from_bits(caps.value)

    # management addresses: index = TimeMark.LocalPort.RemIndex.AddrSubtype.<addr as OCTET STRING>
    man = data.get("lldpRemManAddrTable", [])
    mroot = WALK_ROOTS["lldpRemManAddrTable"]
    for oid, _v in man:
        if len(oid) < len(mroot) + 5 or oid[: len(mroot)] != mroot or oid[len(mroot)] != 3:
            continue
        idx = oid[len(mroot) + 1 :]
        key, family, rest = idx[:3], idx[3], idx[4:]
        if rest and rest[0] == len(rest) - 1:
            rest = rest[1:]
        try:
            raw = bytes(rest)
        except ValueError:
            continue
        nb = rows.get(key)
        if nb is not None:
            addr = address(family, raw)
            if addr not in nb.mgmt_addrs:
                nb.mgmt_addrs.append(addr)

    for idx, v in column(data.get("lldpXdot1RemPortVlanId", []), WALK_ROOTS["lldpXdot1RemPortVlanId"]).items():
        if idx in rows and integer(v):
            rows[idx].pvid = integer(v)
    an = table(data.get("lldpXdot3RemPortAutoNegTable", []), WALK_ROOTS["lldpXdot3RemPortAutoNegTable"])
    for colno, attr in ((1, "autoneg_supported"), (2, "autoneg_enabled")):
        for idx, v in an.get(colno, {}).items():
            if idx in rows:
                setattr(rows[idx], attr, truth(v))
    for idx, v in an.get(4, {}).items():
        if idx in rows:
            rows[idx].mau = integer(v)
            _, rows[idx].speed_mbps, rows[idx].duplex = mau_info(rows[idx].mau)

    for idx in sorted(rows):
        nb = rows[idx]
        nb.local_port, nb.local_ifindex = local_port_name(dev, dev.lldp_ports.get(nb.local_key), f"port {nb.local_key}")
        dev.neighbors.append(nb)


def _cdp_neighbors(dev: Device, data: Dict[str, Varbinds]) -> None:
    rem = table(data.get("cdpCacheTable", []), WALK_ROOTS["cdpCacheTable"])
    if not rem:
        return
    keys = sorted(set().union(*[set(c) for c in rem.values()]))
    for idx in keys:
        if len(idx) != 2:
            continue
        nb = Neighbor(protocol="cdp", local_key=idx[0], local_ifindex=idx[0])
        iface = dev.interfaces.get(idx[0])
        nb.local_port = iface.label if iface else f"ifIndex {idx[0]}"
        nb.sys_name = text(rem.get(6, {}).get(idx))
        nb.port_id = nb.port_desc = text(rem.get(7, {}).get(idx))
        nb.port_subtype = 5
        nb.platform = text(rem.get(8, {}).get(idx))
        nb.sys_descr = text(rem.get(5, {}).get(idx))
        caps = rem.get(9, {}).get(idx)
        if caps is not None and isinstance(caps.value, bytes):
            nb.caps = caps_from_cdp(caps.value)
        atype = integer(rem.get(3, {}).get(idx))
        araw = rem.get(4, {}).get(idx)
        if araw is not None and isinstance(araw.value, bytes) and araw.value:
            fam = {1: 1, 20: 2}.get(atype or 0, 0)
            nb.mgmt_addrs.append(address(fam, araw.value))
        nvlan = integer(rem.get(11, {}).get(idx))
        if nvlan:
            nb.pvid = nvlan
        nb.duplex = {2: "half", 3: "full"}.get(integer(rem.get(12, {}).get(idx)) or 0)
        dev.neighbors.append(nb)


def _native_vlans(dev: Device, data: Dict[str, Varbinds]) -> None:
    """Untagged (native/access) VLAN per ifIndex from the generic and Cisco MIBs."""

    def per_ifindex(key: str) -> Dict[int, int]:
        out = {}
        for idx, v in column(data.get(key, []), WALK_ROOTS[key]).items():
            n = integer(v)
            if len(idx) == 1 and n:
                out[idx[0]] = n
        return out

    trunking = per_ifindex("vlanTrunkPortDynamicStatus")
    native = per_ifindex("vlanTrunkPortNativeVlan")
    access = per_ifindex("vmVlan")
    bridge_port = per_ifindex("dot1dBasePortIfIndex")
    qpvid = {bridge_port[bp]: vlan for bp, vlan in per_ifindex("dot1qPvid").items() if bp in bridge_port}
    for ifindex, iface in dev.interfaces.items():
        if trunking.get(ifindex) == 1 and ifindex in native:
            iface.pvid, iface.pvid_source = native[ifindex], "CISCO-VTP-MIB trunk native VLAN"
        elif ifindex in access and trunking.get(ifindex) != 1:
            iface.pvid, iface.pvid_source = access[ifindex], "CISCO-VLAN-MEMBERSHIP-MIB access VLAN"
        elif ifindex in qpvid:
            iface.pvid, iface.pvid_source = qpvid[ifindex], "Q-BRIDGE-MIB dot1qPvid"


def poll(target: str, walk: Walker, skip: Tuple[str, ...] = ()) -> Tuple[Device, Dict[str, Varbinds]]:
    t0 = time.monotonic()
    try:
        data, warnings = walk_all(walk, skip)
    except SnmpError as exc:
        dev = Device(target=target, error=str(exc))
        dev.duration_s = time.monotonic() - t0
        return dev, {}
    dev = build_device(target, data)
    dev.warnings = warnings
    dev.duration_s = time.monotonic() - t0
    return dev, data
