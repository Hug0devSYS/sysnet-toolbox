"""Synthetic devices (MIB data) and a fake UDP SNMP agent for the tests."""

from __future__ import annotations

import socket
import threading
from typing import Callable, List, Optional, Tuple

from lldp_mapper import ber
from lldp_mapper.ber import OID, Value
from lldp_mapper.mibs import CDP, LLDP, LLDP_DOT1, LLDP_DOT3

TM = 0  # lldpRemTimeMark used in indexes


def S(x) -> Value:
    return Value(ber.OCTET_STRING, x.encode() if isinstance(x, str) else bytes(x))


def I(n: int) -> Value:  # noqa: E743
    return Value(ber.INTEGER, n)


def G(n: int) -> Value:
    return Value(ber.GAUGE32, n)


def mac(text: str) -> bytes:
    return bytes(int(x, 16) for x in text.split(":"))


def lldp_caps(*names: str) -> bytes:
    order = [
        "other",
        "repeater",
        "bridge",
        "wlanAccessPoint",
        "router",
        "telephone",
        "docsisCableDevice",
        "stationOnly",
    ]
    n = 0
    for name in names:
        n |= 0x80 >> order.index(name)
    return bytes([n, 0])


class Dev:
    def __init__(self, name: str, chassis: Optional[str] = None):
        self.name = name
        self.vb: List[Tuple[OID, Value]] = []
        self.add((1, 3, 6, 1, 2, 1, 1, 1, 0), S(f"{name} test device\nsecond line"))
        self.add((1, 3, 6, 1, 2, 1, 1, 2, 0), Value(ber.OBJECT_IDENTIFIER, (1, 3, 6, 1, 4, 1, 9, 1, 1)))
        self.add((1, 3, 6, 1, 2, 1, 1, 5, 0), S(name))
        if chassis:
            self.add(LLDP + (3, 1, 0), I(4))
            self.add(LLDP + (3, 2, 0), S(mac(chassis)))
            self.add(LLDP + (3, 3, 0), S(name))

    def add(self, oid: OID, v: Value) -> Dev:
        self.vb.append((oid, v))
        return self

    def iface(
        self,
        ifindex: int,
        name: str,
        descr: Optional[str] = None,
        speed: int = 1000,
        up: bool = True,
        duplex: Optional[int] = 3,
        ip: Optional[str] = None,
    ) -> Dev:
        self.add((1, 3, 6, 1, 2, 1, 2, 2, 1, 2, ifindex), S(descr or name))
        self.add((1, 3, 6, 1, 2, 1, 2, 2, 1, 8, ifindex), I(1 if up else 2))
        self.add((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1, ifindex), S(name))
        self.add((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15, ifindex), G(speed if up else 0))
        self.add((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18, ifindex), S(""))
        if duplex is not None:
            self.add((1, 3, 6, 1, 2, 1, 10, 7, 2, 1, 19, ifindex), I(duplex))
        if ip:
            self.add(
                (1, 3, 6, 1, 2, 1, 4, 20, 1, 1) + tuple(int(x) for x in ip.split(".")),
                Value(ber.IP_ADDRESS, socket.inet_aton(ip)),
            )
        return self

    def lport(
        self,
        num: int,
        port_id: str,
        subtype: int = 5,
        desc: str = "",
        pvid: Optional[int] = None,
        mau: Optional[int] = None,
        autoneg: Optional[Tuple[bool, bool]] = None,
    ) -> Dev:
        e = LLDP + (3, 7, 1)
        self.add(e + (2, num), I(subtype)).add(e + (3, num), S(port_id)).add(e + (4, num), S(desc))
        if pvid is not None:
            self.add(LLDP_DOT1 + (2, 1, 1, 1, num), I(pvid))
        if autoneg is not None or mau is not None:
            sup, en = autoneg or (True, True)
            t = LLDP_DOT3 + (2, 1, 1)
            self.add(t + (1, num), I(1 if sup else 2)).add(t + (2, num), I(1 if en else 2))
            self.add(t + (4, num), I(mau or 0))
        return self

    def rem(
        self,
        lport: int,
        idx: int,
        sys_name: str,
        port_id: str,
        chassis: Optional[str] = None,
        chassis_subtype: int = 4,
        port_subtype: int = 5,
        port_desc: str = "",
        caps: bytes = b"",
        mgmt: Optional[str] = None,
        pvid: Optional[int] = None,
        mau: Optional[int] = None,
        autoneg: Optional[Tuple[bool, bool]] = None,
        port_raw: Optional[bytes] = None,
    ) -> Dev:
        e = LLDP + (4, 1, 1)
        key = (TM, lport, idx)
        self.add(e + (4,) + key, I(chassis_subtype))
        self.add(e + (5,) + key, S(mac(chassis) if chassis and chassis_subtype == 4 else (chassis or sys_name)))
        self.add(e + (6,) + key, I(port_subtype))
        self.add(e + (7,) + key, S(port_raw if port_raw is not None else port_id))
        self.add(e + (8,) + key, S(port_desc))
        self.add(e + (9,) + key, S(sys_name))
        self.add(e + (10,) + key, S(f"{sys_name} OS 1.0"))
        if caps:
            self.add(e + (11,) + key, S(caps)).add(e + (12,) + key, S(caps))
        if mgmt:
            octets = tuple(int(x) for x in mgmt.split("."))
            self.add(LLDP + (4, 2, 1, 3) + key + (1, 4) + octets, I(2))
        if pvid is not None:
            self.add(LLDP_DOT1 + (3, 1, 1, 1) + key, I(pvid))
        if autoneg is not None or mau is not None:
            sup, en = autoneg or (True, True)
            t = LLDP_DOT3 + (3, 1, 1)
            self.add(t + (1,) + key, I(1 if sup else 2)).add(t + (2,) + key, I(1 if en else 2))
            self.add(t + (4,) + key, I(mau or 0))
        return self

    def cdp(
        self,
        ifindex: int,
        idx: int,
        device_id: str,
        port: str,
        platform: str = "cisco WS-C9300",
        caps: int = 0x28,
        addr: Optional[str] = None,
        native: Optional[int] = None,
        duplex: Optional[int] = None,
    ) -> Dev:
        e = CDP + (2, 1, 1)
        key = (ifindex, idx)
        if addr:
            self.add(e + (3,) + key, I(1)).add(e + (4,) + key, S(socket.inet_aton(addr)))
        self.add(e + (5,) + key, S("Cisco IOS Software, Version 17.9"))
        self.add(e + (6,) + key, S(device_id)).add(e + (7,) + key, S(port)).add(e + (8,) + key, S(platform))
        self.add(e + (9,) + key, S(caps.to_bytes(4, "big")))
        if native is not None:
            self.add(e + (11,) + key, I(native))
        if duplex is not None:
            self.add(e + (12,) + key, I(duplex))
        return self

    def cdp_global(self, device_id: str) -> Dev:
        return self.add(CDP + (3, 4, 0), S(device_id))

    def trunk(self, ifindex: int, native: int, trunking: bool = True) -> Dev:
        t = (1, 3, 6, 1, 4, 1, 9, 9, 46, 1, 6, 1, 1)
        self.add(t + (5, ifindex), I(native)).add(t + (14, ifindex), I(1 if trunking else 2))
        return self

    def access_vlan(self, ifindex: int, vlan: int) -> Dev:
        return self.add((1, 3, 6, 1, 4, 1, 9, 9, 68, 1, 2, 2, 1, 2, ifindex), I(vlan))

    def sorted(self) -> List[Tuple[OID, Value]]:
        return sorted(self.vb, key=lambda vb: vb[0])


# --------------------------------------------------------------------------- fake agent


class FakeAgent:
    """UDP SNMPv1/v2c agent serving a varbind list; knobs simulate broken agents."""

    def __init__(
        self,
        varbinds,
        community: bytes = b"s3cret",
        drop_first: int = 0,
        too_big_over: int = 0,
        mutate: Optional[Callable[[list], list]] = None,
        family: int = socket.AF_INET,
    ):
        self.data = sorted(varbinds, key=lambda vb: vb[0])
        self.community = community
        self.drop_first = drop_first
        self.too_big_over = too_big_over
        self.mutate = mutate
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
        self.port = self.sock.getsockname()[1]
        self.received = 0
        self.max_reps_seen: List[int] = []
        self._stop = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _next(self, oid: OID) -> Tuple[OID, Value]:
        for o, v in self.data:
            if o > oid:
                return o, v
        return oid, Value(ber.END_OF_MIB_VIEW, None)

    def _run(self) -> None:
        self.sock.settimeout(0.1)
        while not self._stop:
            try:
                raw, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.received += 1
            if self.received <= self.drop_first:
                continue
            try:
                msg = ber.decode_message(raw)
            except ber.BerError:
                continue
            if msg.community != self.community:
                continue
            pdu = msg.pdu
            start = pdu.varbinds[0][0]
            if pdu.tag == ber.GET_BULK_REQUEST:
                reps = pdu.error_index
                self.max_reps_seen.append(reps)
                if self.too_big_over and reps > self.too_big_over:
                    self.sock.sendto(
                        ber.encode_response(msg.version, msg.community, pdu.request_id, [], error_status=1), addr
                    )
                    continue
            else:
                reps = 1
            out = []
            cur = start
            for _ in range(reps):
                o, v = self._next(cur)
                if msg.version == 0 and v.tag == ber.END_OF_MIB_VIEW:
                    self.sock.sendto(
                        ber.encode_response(
                            0,
                            msg.community,
                            pdu.request_id,
                            [(start, Value(ber.NULL, None))],
                            error_status=2,
                            error_index=1,
                        ),
                        addr,
                    )
                    out = None
                    break
                out.append((o, v))
                if v.tag == ber.END_OF_MIB_VIEW:
                    break
                cur = o
            if out is None:
                continue
            if self.mutate:
                out = self.mutate(out)
            self.sock.sendto(ber.encode_response(msg.version, msg.community, pdu.request_id, out), addr)

    def close(self) -> None:
        self._stop = True
        self.thread.join(timeout=2)
        self.sock.close()


# --------------------------------------------------------------------------- reference lab


def reference_lab() -> List[Dev]:
    """Three switches, a server and an IP phone; contains one problem of each kind.

    sw1 Gi1/0/1  <-> sw2 Ethernet1/1   healthy (LLDP both ways + CDP from sw1)
    sw1 Gi1/0/2  <-> sw2 Ethernet1/2   native VLAN 1 vs 10
    sw1 Gi1/0/3  <-> srv1 eth0         sw1 full duplex, srv1 advertises 100BASE-TX half duplex
    sw1 Gi1/0/4  <-> phone1 + pc1      shared port
    sw3 Gi0/1    --> sw2 Ethernet1/3   sw2 does not see sw3 (one-way)
    sw1 Gi1/0/5  <-> sw3 Gi0/2         auto-negotiation on/off
    """
    sw1 = (
        Dev("sw1", "00:00:5e:00:01:01")
        .cdp_global("sw1.lab.example")
        .iface(1, "Gi1/0/1", "GigabitEthernet1/0/1", ip="10.0.0.1")
        .iface(2, "Gi1/0/2", "GigabitEthernet1/0/2")
        .iface(3, "Gi1/0/3", "GigabitEthernet1/0/3", speed=100)
        .iface(4, "Gi1/0/4", "GigabitEthernet1/0/4")
        .iface(5, "Gi1/0/5", "GigabitEthernet1/0/5")
        .trunk(1, 1)
        .trunk(2, 1)
        .access_vlan(3, 30)
        .access_vlan(4, 40)
        # Local LLDP port numbers deliberately differ from ifIndex.
        .lport(101, "Gi1/0/1", desc="GigabitEthernet1/0/1")
        .lport(102, "Gi1/0/2", desc="GigabitEthernet1/0/2")
        .lport(103, "Gi1/0/3", desc="GigabitEthernet1/0/3")
        .lport(104, "Gi1/0/4", desc="GigabitEthernet1/0/4")
        .lport(105, "Gi1/0/5", desc="GigabitEthernet1/0/5", autoneg=(True, True), mau=30)
        .rem(
            101,
            1,
            "sw2.lab.example",
            "Ethernet1/1",
            chassis="00:00:5e:00:02:02",
            port_desc="to sw1",
            caps=lldp_caps("bridge", "router"),
            mgmt="10.0.0.2",
            pvid=1,
        )
        .rem(
            102,
            2,
            "sw2.lab.example",
            "Ethernet1/2",
            chassis="00:00:5e:00:02:02",
            caps=lldp_caps("bridge"),
            mgmt="10.0.0.2",
            pvid=10,
        )
        .rem(
            103,
            3,
            "srv1",
            "",
            chassis="52:54:00:aa:bb:cc",
            port_subtype=3,
            port_raw=mac("52:54:00:aa:bb:cd"),
            port_desc="eth0",
            caps=lldp_caps("stationOnly"),
            mgmt="10.0.9.10",
            mau=15,
            autoneg=(True, False),
        )
        .rem(
            104,
            4,
            "phone1",
            "",
            chassis="00:11:22:33:44:55",
            port_subtype=3,
            port_raw=mac("00:11:22:33:44:56"),
            port_desc="Port 1",
            caps=lldp_caps("telephone", "bridge"),
        )
        .rem(
            104,
            5,
            "pc1",
            "",
            chassis="00:11:22:33:44:99",
            port_subtype=3,
            port_raw=mac("00:11:22:33:44:99"),
            port_desc="eno1",
            caps=lldp_caps("stationOnly"),
        )
        .rem(105, 6, "sw3", "Gi0/2", chassis="00:00:5e:00:03:03", caps=lldp_caps("bridge"), mgmt="10.0.0.3")
        .cdp(1, 1, "sw2(FDO1234X)", "Ethernet1/1", platform="N9K-C93180YC-FX", addr="10.0.0.2", native=1, duplex=3)
    )
    sw2 = (
        Dev("sw2.lab.example", "00:00:5e:00:02:02")
        .iface(10, "Ethernet1/1", "Ethernet1/1", ip="10.0.0.2")
        .iface(11, "Ethernet1/2", "Ethernet1/2")
        .iface(12, "Ethernet1/3", "Ethernet1/3")
        .lport(1, "Ethernet1/1", pvid=1)
        .lport(2, "Ethernet1/2", pvid=10)
        .lport(3, "Ethernet1/3", pvid=1)
        .rem(
            1,
            1,
            "sw1",
            "Gi1/0/1",
            chassis="00:00:5e:00:01:01",
            caps=lldp_caps("bridge", "router"),
            mgmt="10.0.0.1",
            pvid=1,
        )
        .rem(
            2,
            2,
            "sw1",
            "Gi1/0/2",
            chassis="00:00:5e:00:01:01",
            caps=lldp_caps("bridge", "router"),
            mgmt="10.0.0.1",
            pvid=1,
        )
    )
    sw3 = (
        Dev("sw3", "00:00:5e:00:03:03")
        .iface(1, "Gi0/1", "GigabitEthernet0/1", ip="10.0.0.3")
        .iface(2, "Gi0/2", "GigabitEthernet0/2")
        .lport(1, "Gi0/1")
        .lport(2, "Gi0/2", autoneg=(True, False), mau=30)
        .rem(
            1,
            1,
            "sw2.lab.example",
            "Ethernet1/3",
            chassis="00:00:5e:00:02:02",
            caps=lldp_caps("bridge"),
            mgmt="10.0.0.2",
        )
        .rem(
            2,
            2,
            "sw1",
            "Gi1/0/5",
            chassis="00:00:5e:00:01:01",
            caps=lldp_caps("bridge"),
            mgmt="10.0.0.1",
            autoneg=(True, True),
            mau=30,
        )
    )
    return [sw1, sw2, sw3]
