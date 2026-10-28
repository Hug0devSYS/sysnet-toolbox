"""Build the topology graph from polled devices and run the link checks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .ifnames import canonical, match_interface
from .mibs import local_port_name, mau_info
from .model import Device, Endpoint, EndpointFacts, Finding, Interface, Link, LocalPort, Neighbor, Node

# Fact priority: what a device says about its own port beats what its neighbour received.
OWN, ADVERTISED = 2, 1


def norm_name(name: str) -> str:
    """Normalise a system name / CDP device ID for matching (drops NX-OS ``(serial)`` and case)."""
    n = name.strip().lower().rstrip(".")
    n = re.sub(r"\([^)]*\)$", "", n).strip()
    return n


def first_label(name: str) -> str:
    n = norm_name(name)
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", n):
        return n
    return n.split(".", 1)[0]


def slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "_", name.strip()).strip("_").lower()
    return s or "node"


@dataclass
class _FactSlot:
    prio: Dict[str, int] = field(default_factory=dict)


@dataclass
class Topology:
    nodes: Dict[str, Node] = field(default_factory=dict)
    links: List[Link] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    devices: List[Device] = field(default_factory=list)


class _Builder:
    def __init__(self, devices: List[Device]):
        self.devices = sorted(devices, key=lambda d: (d.name.lower(), d.target))
        self.topo = Topology(devices=self.devices)
        self.by_chassis: Dict[Tuple[int, str], str] = {}
        self.by_name: Dict[str, str] = {}
        self.by_label: Dict[str, Set[str]] = {}
        self.by_addr: Dict[str, str] = {}
        self.dev_of: Dict[str, Device] = {}
        self.links: Dict[Tuple[Tuple[str, str], Tuple[str, str]], Link] = {}
        self.slots: Dict[int, _FactSlot] = {}
        # (node, canonical port, protocol) -> set of remote node ids
        self.port_neighbors: Dict[Tuple[str, str, str], Set[str]] = {}
        self.port_labels: Dict[Tuple[str, str], str] = {}

    # ------------------------------------------------------------------ identity

    def _new_id(self, name: str) -> str:
        base = slug(name)
        nid, i = base, 2
        while nid in self.topo.nodes:
            nid, i = f"{base}_{i}", i + 1
        return nid

    def _register(self, nid: str, chassis: Optional[Tuple[int, str]], names: List[str], addrs: List[str]) -> None:
        if chassis and chassis[1]:
            self.by_chassis.setdefault(chassis, nid)
        for n in names:
            if n:
                self.by_name.setdefault(norm_name(n), nid)
                self.by_label.setdefault(first_label(n), set()).add(nid)
        for a in addrs:
            if a:
                self.by_addr.setdefault(a, nid)

    def _lookup(self, chassis: Optional[Tuple[int, str]], names: List[str], addrs: List[str]) -> Optional[str]:
        if chassis and chassis[1] and chassis in self.by_chassis:
            return self.by_chassis[chassis]

        def compatible(nid: str) -> bool:
            # A name or address match never merges two boxes with different chassis IDs.
            other = self.topo.nodes[nid].chassis_id
            return not (chassis and chassis[1] and other and other != chassis[1])

        for n in names:
            nid = self.by_name.get(norm_name(n)) if n else None
            if nid is not None and compatible(nid):
                return nid
        for a in addrs:
            nid = self.by_addr.get(a)
            if nid is not None and compatible(nid):
                return nid
        for n in names:
            hits = [h for h in self.by_label.get(first_label(n), set()) if compatible(h)] if n else []
            if len(hits) == 1:
                return hits[0]
        return None

    def add_devices(self) -> None:
        for dev in self.devices:
            chassis = (dev.chassis_subtype, dev.chassis_id) if dev.chassis_id else None
            names = [dev.sys_name, dev.cdp_device_id]
            addrs = [dev.target, *dev.addresses]
            existing = self._lookup(chassis, [n for n in names if n], addrs) if dev.ok else None
            if existing is not None and existing in self.dev_of:
                # Same box reached through two addresses: keep the first poll.
                self.topo.findings.append(
                    Finding(
                        "duplicate-device",
                        "info",
                        f"{dev.target} is the same device as {self.dev_of[existing].target} "
                        f"({self.topo.nodes[existing].name}); second poll ignored",
                        node=existing,
                    )
                )
                continue
            nid = self._new_id(dev.name)
            self.topo.nodes[nid] = Node(
                id=nid,
                name=dev.name,
                polled=True,
                target=dev.target,
                chassis_id=dev.chassis_id,
                mgmt_addrs=[dev.target],
                error=dev.error,
                platform=dev.sys_descr.splitlines()[0][:80] if dev.sys_descr else "",
            )
            self.dev_of[nid] = dev
            if dev.ok:
                self._register(nid, chassis, names, addrs)
            else:
                self._register(nid, None, [], [dev.target])

    def _resolve_neighbor(self, nb: Neighbor) -> str:
        chassis = (nb.chassis_subtype, nb.chassis_id) if nb.chassis_id else None
        names = [nb.sys_name] if nb.sys_name else []
        nid = self._lookup(chassis, names, nb.mgmt_addrs)
        if nid is None:
            nid = self._new_id(nb.name or "unknown")
            self.topo.nodes[nid] = Node(id=nid, name=nb.name or "unknown", chassis_id=nb.chassis_id)
            self._register(nid, chassis, names, nb.mgmt_addrs)
        node = self.topo.nodes[nid]
        if not node.polled:
            # Enrich external nodes with whatever each sighting adds.
            if not node.chassis_id and nb.chassis_id:
                node.chassis_id = nb.chassis_id
                if chassis:
                    self.by_chassis.setdefault(chassis, nid)
            if nb.sys_name and node.name == node.chassis_id and nb.sys_name != node.name:
                node.name = nb.sys_name
                self._register(nid, None, [nb.sys_name], [])
            for a in nb.mgmt_addrs:
                if a not in node.mgmt_addrs:
                    node.mgmt_addrs.append(a)
                    self.by_addr.setdefault(a, nid)
            for c in nb.caps:
                if c not in node.caps:
                    node.caps.append(c)
            if nb.platform and not node.platform:
                node.platform = nb.platform
            elif nb.sys_descr and not node.platform:
                node.platform = nb.sys_descr.splitlines()[0][:80]
        elif not self.dev_of[nid].ok:
            node.name = nb.name or node.name
        return nid

    # ------------------------------------------------------------------ ports and facts

    @staticmethod
    def _lp_for_ifindex(dev: Device, ifindex: Optional[int]) -> Optional[LocalPort]:
        if ifindex is None:
            return None
        for lp in dev.lldp_ports.values():
            if lp.ifindex == ifindex:
                return lp
        return None

    def _remote_port(self, nb: Neighbor, rdev: Optional[Device]) -> Tuple[str, Optional[int], Optional[LocalPort]]:
        """Resolve the neighbour's port on a polled remote device."""
        if rdev is None or not rdev.ok:
            return nb.port_label or "?", None, None
        if nb.protocol == "lldp" and nb.port_id_raw:
            for lp in rdev.lldp_ports.values():
                if lp.id_subtype == nb.port_subtype and lp.port_id == nb.port_id_raw:
                    label, ifindex = local_port_name(rdev, lp)
                    return label, ifindex, lp
        for cand in (nb.port_id, nb.port_desc):
            iface = match_interface(rdev.interfaces.values(), cand) if cand else None
            if iface is not None:
                return iface.label, iface.ifindex, self._lp_for_ifindex(rdev, iface.ifindex)
        return nb.port_label or "?", None, None

    def _set(self, facts: EndpointFacts, name: str, value: object, src: str, prio: int) -> None:
        if value is None or value == "" or (name == "pvid" and not value):
            return
        slot = self.slots.setdefault(id(facts), _FactSlot())
        if slot.prio.get(name, 0) >= prio:
            return
        slot.prio[name] = prio
        if name == "autoneg":
            supported, enabled = value  # type: ignore[misc]
            facts.autoneg_supported, facts.autoneg_enabled, facts.autoneg_src = supported, enabled, src
            return
        setattr(facts, name if name != "speed" else "speed_mbps", value)
        setattr(facts, {"duplex": "duplex_src", "speed": "speed_src", "pvid": "pvid_src"}[name], src)

    def _own_facts(self, facts: EndpointFacts, dev: Device, ifindex: Optional[int], lp: Optional[LocalPort]) -> None:
        iface: Optional[Interface] = dev.interfaces.get(ifindex) if ifindex is not None else None
        if lp is None and ifindex is not None:
            lp = self._lp_for_ifindex(dev, ifindex)
        who = dev.name
        if iface is not None and iface.duplex:
            self._set(facts, "duplex", iface.duplex, f"{who}: EtherLike-MIB dot3StatsDuplexStatus", OWN)
        if lp is not None and lp.mau:
            name, speed, duplex = mau_info(lp.mau)
            self._set(facts, "duplex", duplex, f"{who}: LLDP local MAU {name}", OWN)
            self._set(facts, "speed", speed, f"{who}: LLDP local MAU {name}", OWN)
        if iface is not None and iface.speed_mbps and iface.oper_up is not False:
            self._set(facts, "speed", iface.speed_mbps, f"{who}: IF-MIB ifHighSpeed", OWN)
        if lp is not None and lp.autoneg_enabled is not None:
            self._set(facts, "autoneg", (lp.autoneg_supported, lp.autoneg_enabled), f"{who}: LLDP-EXT-DOT3 local", OWN)
        if lp is not None and lp.pvid:
            self._set(facts, "pvid", lp.pvid, f"{who}: LLDP-EXT-DOT1 local PVID", OWN)
        if iface is not None and iface.pvid:
            self._set(facts, "pvid", iface.pvid, f"{who}: {iface.pvid_source}", OWN)

    def _advertised_facts(self, facts: EndpointFacts, nb: Neighbor, seen_by: str) -> None:
        proto = nb.protocol.upper()
        src = f"advertised via {proto}, received by {seen_by}"
        if nb.duplex:
            what = f" (MAU {mau_info(nb.mau)[0]})" if nb.mau else ""
            self._set(facts, "duplex", nb.duplex, src + what, ADVERTISED)
        if nb.speed_mbps:
            self._set(facts, "speed", nb.speed_mbps, src, ADVERTISED)
        if nb.autoneg_enabled is not None:
            self._set(facts, "autoneg", (nb.autoneg_supported, nb.autoneg_enabled), src, ADVERTISED)
        if nb.pvid:
            self._set(facts, "pvid", nb.pvid, src, ADVERTISED)

    # ------------------------------------------------------------------ links

    def _port_label(self, nid: str, label: str) -> str:
        key = (nid, canonical(label))
        return self.port_labels.setdefault(key, label)

    def add_links(self) -> None:
        for nid, dev in list(self.dev_of.items()):
            if not dev.ok:
                continue
            for nb in dev.neighbors:
                rid = self._resolve_neighbor(nb)
                if rid == nid:
                    continue  # loopback cable or a device hearing itself through a hub
                rdev = self.dev_of.get(rid)
                lport = self._port_label(nid, nb.local_port)
                rlabel, r_ifindex, r_lp = self._remote_port(nb, rdev)
                rport = self._port_label(rid, rlabel)
                self.port_neighbors.setdefault((nid, canonical(lport), nb.protocol), set()).add(rid)
                a, b = (nid, canonical(lport)), (rid, canonical(rport))
                key = (a, b) if a <= b else (b, a)
                link = self.links.get(key)
                if link is None:
                    link = Link(Endpoint(nid, lport), Endpoint(rid, rport))
                    self.links[key] = link
                if nb.protocol not in link.protocols:
                    link.protocols.append(nb.protocol)
                if nid not in link.seen_from:
                    link.seen_from.append(nid)
                local_ep = link.a if link.a.node == nid and canonical(link.a.port) == a[1] else link.b
                remote_ep = link.b if local_ep is link.a else link.a
                l_lp = dev.lldp_ports.get(nb.local_key) if nb.protocol == "lldp" else None
                l_ifindex = nb.local_ifindex if nb.local_ifindex is not None else (l_lp.ifindex if l_lp else None)
                self._own_facts(local_ep.facts, dev, l_ifindex, l_lp)
                self._advertised_facts(remote_ep.facts, nb, dev.name)
                local_ep.resolved = True
                if rdev is not None and rdev.ok and (r_ifindex is not None or r_lp is not None):
                    self._own_facts(remote_ep.facts, rdev, r_ifindex, r_lp)
                    remote_ep.resolved = True
        self.topo.links = sorted(self.links.values(), key=lambda lk: lk.key)

    # ------------------------------------------------------------------ checks

    def _name(self, nid: str) -> str:
        return self.topo.nodes[nid].name

    def check_links(self) -> None:
        f = self.topo.findings
        for link in self.topo.links:
            a, b = link.a, link.b
            fa, fb = a.facts, b.facts
            where = dict(node=self._name(a.node), port=a.port, peer=self._name(b.node), peer_port=b.port)
            pair = f"{self._name(a.node)} {a.port} <-> {self._name(b.node)} {b.port}"
            if fa.duplex and fb.duplex and fa.duplex != fb.duplex:
                f.append(
                    Finding(
                        "duplex-mismatch",
                        "critical",
                        f"duplex mismatch on {pair}: {fa.duplex} vs {fb.duplex} (late collisions, "
                        "CRC errors and throughput collapse under load)",
                        detail={"a": fa.duplex, "a_source": fa.duplex_src, "b": fb.duplex, "b_source": fb.duplex_src},
                        **where,
                    )
                )
                link.findings.append("duplex-mismatch")
            if fa.speed_mbps and fb.speed_mbps and fa.speed_mbps != fb.speed_mbps:
                f.append(
                    Finding(
                        "speed-mismatch",
                        "warning",
                        f"speed mismatch on {pair}: {fa.speed_mbps} vs {fb.speed_mbps} Mb/s "
                        "(media converter, wrong optic, or a stale advertisement)",
                        detail={
                            "a": fa.speed_mbps,
                            "a_source": fa.speed_src,
                            "b": fb.speed_mbps,
                            "b_source": fb.speed_src,
                        },
                        **where,
                    )
                )
                link.findings.append("speed-mismatch")
            if (
                fa.autoneg_enabled is not None
                and fb.autoneg_enabled is not None
                and fa.autoneg_supported is not False
                and fb.autoneg_supported is not False
                and fa.autoneg_enabled != fb.autoneg_enabled
            ):
                on, off = (a, b) if fa.autoneg_enabled else (b, a)
                f.append(
                    Finding(
                        "autoneg-mismatch",
                        "warning",
                        f"auto-negotiation enabled on {self._name(on.node)} {on.port} but disabled on "
                        f"{self._name(off.node)} {off.port}: the negotiating side falls back to half "
                        "duplex on copper (the classic cause of duplex mismatches)",
                        detail={
                            "a": fa.autoneg_enabled,
                            "a_source": fa.autoneg_src,
                            "b": fb.autoneg_enabled,
                            "b_source": fb.autoneg_src,
                        },
                        **where,
                    )
                )
                link.findings.append("autoneg-mismatch")
            if fa.pvid and fb.pvid and fa.pvid != fb.pvid:
                f.append(
                    Finding(
                        "native-vlan-mismatch",
                        "warning",
                        f"native/untagged VLAN mismatch on {pair}: {fa.pvid} vs {fb.pvid} "
                        "(untagged frames leak between VLANs, STP inconsistencies)",
                        detail={"a": fa.pvid, "a_source": fa.pvid_src, "b": fb.pvid, "b_source": fb.pvid_src},
                        **where,
                    )
                )
                link.findings.append("native-vlan-mismatch")

    def check_adjacency(self) -> None:
        for link in self.topo.links:
            if link.bidirectional:
                continue
            seer = link.seen_from[0]
            other = link.b if link.a.node == seer else link.a
            mine = link.a if other is link.b else link.b
            rdev = self.dev_of.get(other.node)
            if rdev is None or not rdev.ok:
                continue
            if not other.resolved:
                continue  # the remote port is not a port we know on that device
            protos = [
                p
                for p in link.protocols
                if (p == "lldp" and rdev.lldp_supported) or (p == "cdp" and rdev.cdp_supported)
            ]
            if not protos:
                continue
            seen = set()
            for p in protos:
                seen |= self.port_neighbors.get((other.node, canonical(other.port), p), set())
            where = dict(node=self._name(other.node), port=other.port, peer=self._name(mine.node), peer_port=mine.port)
            proto = "/".join(p.upper() for p in protos)
            if seen:
                names = ", ".join(sorted(self._name(n) for n in seen))
                self.topo.findings.append(
                    Finding(
                        "neighbor-mismatch",
                        "warning",
                        f"{self._name(mine.node)} {mine.port} sees {self._name(other.node)} {other.port} via "
                        f"{proto}, but {self._name(other.node)} {other.port} sees {names} (patching error, "
                        "intermediate device or stale entry)",
                        **where,
                    )
                )
            else:
                self.topo.findings.append(
                    Finding(
                        "one-way-adjacency",
                        "warning",
                        f"{self._name(mine.node)} {mine.port} sees {self._name(other.node)} {other.port} via "
                        f"{proto}, but {self._name(other.node)} has no {proto} neighbour on that port "
                        f"(transmit/receive disabled on one side, or a unidirectional link)",
                        **where,
                    )
                )
            link.findings.append("one-way-adjacency" if not seen else "neighbor-mismatch")

    def check_ports_and_devices(self) -> None:
        f = self.topo.findings
        per_port: Dict[Tuple[str, str], Set[str]] = {}
        for (nid, cport, _proto), rids in self.port_neighbors.items():
            per_port.setdefault((nid, cport), set()).update(rids)
        for (nid, cport), rids in sorted(per_port.items()):
            if len(rids) > 1:
                label = self.port_labels.get((nid, cport), cport)
                names = ", ".join(sorted(self._name(r) for r in rids))
                f.append(
                    Finding(
                        "shared-port",
                        "info",
                        f"{self._name(nid)} {label} has {len(rids)} neighbours ({names}): unmanaged "
                        "switch, hub, IP phone with a PC behind it, or a hypervisor",
                        node=self._name(nid),
                        port=label,
                        detail={"neighbors": sorted(rids)},
                    )
                )
        for nid, dev in self.dev_of.items():
            if not dev.ok:
                f.append(Finding("poll-failed", "unknown", dev.error or "poll failed", node=self._name(nid)))
                continue
            if dev.warnings:
                f.append(
                    Finding(
                        "partial-data",
                        "info",
                        f"{dev.name}: some tables could not be read: " + "; ".join(dev.warnings[:5]),
                        node=dev.name,
                        detail={"warnings": dev.warnings},
                    )
                )
            if not dev.lldp_supported and not dev.cdp_supported:
                f.append(
                    Finding(
                        "no-discovery-data",
                        "info",
                        f"{dev.name}: neither LLDP-MIB nor CISCO-CDP-MIB returned data (protocol "
                        "disabled, SNMP view excluding the MIBs, or agent without LLDP support)",
                        node=dev.name,
                    )
                )


def build(devices: List[Device]) -> Topology:
    b = _Builder(devices)
    b.add_devices()
    b.add_links()
    b.check_links()
    b.check_adjacency()
    b.check_ports_and_devices()
    return b.topo
