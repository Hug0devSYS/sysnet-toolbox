import os

import pytest
from conftest import FIXTURES
from lab import Dev, lldp_caps, reference_lab

from lldp_mapper import mibs
from lldp_mapper.ifnames import canonical, match_interface, short
from lldp_mapper.mibs import caps_from_bits, caps_from_cdp, format_id, mau_info
from lldp_mapper.model import Interface
from lldp_mapper.snmp import FileWalker


def poll_dev(dev):
    fw = FileWalker(dev.name, dev.sorted())
    device, _ = mibs.poll(dev.name, fw.walk)
    return device


@pytest.mark.parametrize(
    "mau,expected",
    [
        (15, ("100BaseTXHD", 100, "half")),
        (16, ("100BaseTXFD", 100, "full")),
        (30, ("1000BaseTFD", 1000, "full")),
        (29, ("1000BaseTHD", 1000, "half")),
        (10, ("10BaseTHD", 10, "half")),
        (36, ("10GigBaseSR", 10000, "full")),
        (54, ("10GbaseT", 10000, "full")),
        (49, ("1000BaseLX10", 1000, "full")),
        (0, (None, None, None)),
        (999, (None, None, None)),
        (None, (None, None, None)),
    ],
)
def test_mau_info(mau, expected):
    assert mau_info(mau) == expected


def test_format_id_variants():
    assert format_id(4, bytes.fromhex("001122334455"), 4) == "00:11:22:33:44:55"
    assert format_id(5, bytes([1, 10, 0, 0, 1]), 4) == "10.0.0.1"
    assert format_id(5, b"Gi1/0/1", 3) == "Gi1/0/1"
    assert format_id(7, b"\x01\x02\xff", 3) == "0102ff"
    assert format_id(7, b"513", 3) == "513"


def test_capabilities():
    assert caps_from_bits(lldp_caps("bridge", "router")) == ["bridge", "router"]
    assert caps_from_bits(b"\x01") == ["stationOnly"]
    assert caps_from_cdp(bytes.fromhex("00000029")) == ["router", "bridge"]
    assert caps_from_cdp(bytes.fromhex("00000090")) == ["stationOnly", "telephone"]


def test_interface_names():
    assert canonical("GigabitEthernet1/0/1") == canonical("Gi1/0/1") == "gi1/0/1"
    assert canonical("TwentyFiveGigE1/0/1") == canonical("Twe1/0/1")
    assert canonical("TwoGigabitEthernet1/0/1") != canonical("TwentyFiveGigE1/0/1")
    assert canonical("Ethernet1/1") == canonical("Eth1/1")
    assert canonical("Port-channel10") == canonical("Po10")
    assert canonical("ge-0/0/0.0") == "ge-0/0/0"
    assert canonical("FastEthernet0/1") != canonical("FortyGigabitEthernet0/1")
    assert short("GigabitEthernet1/0/1") == "Gi1/0/1" and short("ge-0/0/1") == "ge-0/0/1"
    ifaces = [Interface(1, "Gi1/0/1", "GigabitEthernet1/0/1"), Interface(2, "Gi1/0/10", "GigabitEthernet1/0/10")]
    assert match_interface(ifaces, "GigabitEthernet1/0/1").ifindex == 1
    assert match_interface(ifaces, "gi1/0/10").ifindex == 2
    assert match_interface(ifaces, "Gi1/0/2") is None
    assert match_interface(ifaces, "") is None


def test_reference_switch_decoding():
    sw1 = poll_dev(reference_lab()[0])
    assert sw1.sys_name == "sw1" and sw1.chassis_id == "00:00:5e:00:01:01"
    assert sw1.cdp_device_id == "sw1.lab.example" and sw1.lldp_supported and sw1.cdp_supported
    assert sw1.addresses == ["10.0.0.1"]
    # LLDP port 101 is ifIndex 1, resolved through the port ID.
    assert sw1.lldp_ports[101].ifindex == 1 and "port-id" in sw1.lldp_ports[101].ifindex_how
    nbs = [n for n in sw1.neighbors if n.protocol == "lldp"]
    assert [n.local_port for n in nbs] == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4", "Gi1/0/4", "Gi1/0/5"]
    srv = nbs[2]
    assert srv.chassis_id == "52:54:00:aa:bb:cc" and srv.port_id == "52:54:00:aa:bb:cd"
    assert srv.port_label == "eth0" and srv.duplex == "half" and srv.speed_mbps == 100
    assert srv.autoneg_enabled is False and srv.mgmt_addrs == ["10.0.9.10"] and srv.caps == ["stationOnly"]
    cdp = [n for n in sw1.neighbors if n.protocol == "cdp"][0]
    assert cdp.sys_name == "sw2(FDO1234X)" and cdp.local_port == "Gi1/0/1" and cdp.pvid == 1
    assert cdp.mgmt_addrs == ["10.0.0.2"] and cdp.duplex == "full" and "bridge" in cdp.caps
    # native VLANs: trunk native from CISCO-VTP-MIB, access VLAN from CISCO-VLAN-MEMBERSHIP-MIB
    assert sw1.interfaces[1].pvid == 1 and "VTP" in sw1.interfaces[1].pvid_source
    assert sw1.interfaces[3].pvid == 30 and "MEMBERSHIP" in sw1.interfaces[3].pvid_source


def test_typed_fixture_decoding():
    fw = FileWalker.from_file(os.path.join(FIXTURES, "c9300-typed.walk"))
    dev, _ = mibs.poll("10.20.0.11", fw.walk)
    assert dev.name == "acc-sw01.corp.example" and dev.chassis_id == "70:0f:6a:11:22:33"
    assert dev.interfaces[9].duplex == "half" and dev.interfaces[9].pvid == 20
    lldp = [n for n in dev.neighbors if n.protocol == "lldp"]
    assert lldp[0].sys_name == "dist-sw01.corp.example" and lldp[0].caps == ["bridge", "router"]
    assert lldp[0].mgmt_addrs == ["10.20.0.1"] and lldp[0].local_port == "Gi1/0/1"
    assert lldp[1].mgmt_addrs == ["2001:db8::10"] and lldp[1].port_label == "ens192"
    assert lldp[1].duplex == "full" and lldp[1].local_port == "Gi1/0/2"


def test_mgmt_address_without_length_prefix():
    d = Dev("x", "00:00:00:00:00:01").lport(1, "p1").rem(1, 1, "peer", "p9", chassis="00:00:00:00:00:02")
    d.add(mibs.LLDP + (4, 2, 1, 3, 0, 1, 1, 1, 192, 0, 2, 7), mibs.Value(2, 2))  # non-compliant: no length
    dev = poll_dev(d)
    assert dev.neighbors[0].mgmt_addrs == ["192.0.2.7"]


def test_junos_local_port_id_is_ifindex():
    d = Dev("mx1", "00:00:00:00:00:01").iface(513, "ge-0/0/0", "ge-0/0/0")
    d.lport(1, "513", subtype=7, desc="ge-0/0/0.0")
    dev = poll_dev(d)
    assert dev.lldp_ports[1].ifindex == 513


def test_port_num_fallback_marks_assumption():
    d = Dev("x", "00:00:00:00:00:01").iface(7, "port7", "port7").lport(7, "aa:bb", subtype=3)
    dev = poll_dev(d)
    assert dev.lldp_ports[7].ifindex == 7 and "assumed" in dev.lldp_ports[7].ifindex_how


def test_unreachable_first_walk_is_fatal_later_timeouts_are_not():
    from lldp_mapper.snmp import SnmpTimeout

    def dead(root):
        raise SnmpTimeout("no response")

    dev, data = mibs.poll("10.0.0.9", dead)
    assert not dev.ok and "no response" in dev.error and data == {}

    calls = []
    good = FileWalker("sw", reference_lab()[0].sorted())

    def flaky(root):
        calls.append(root)
        if root == mibs.WALK_ROOTS["cdpCacheTable"]:
            raise SnmpTimeout("slow table")
        return good.walk(root)

    dev, _ = mibs.poll("sw", flaky)
    assert dev.ok and any("cdpCacheTable" in w for w in dev.warnings)
    assert len(calls) == len(mibs.WALKS)

    def stops(root):
        if root == mibs.WALK_ROOTS["sysName"]:
            return good.walk(root)
        raise SnmpTimeout("gone")

    dev, _ = mibs.poll("sw", stops)
    assert dev.ok and dev.warnings[-1].startswith("agent stopped answering")
