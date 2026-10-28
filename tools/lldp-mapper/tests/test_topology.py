import os

from conftest import FIXTURES
from lab import Dev, lldp_caps, reference_lab

from lldp_mapper import mibs
from lldp_mapper.model import Device
from lldp_mapper.snmp import FileWalker
from lldp_mapper.topology import build, norm_name


def poll_all(devs, targets=None):
    out = []
    for i, d in enumerate(devs):
        fw = FileWalker(d.name, d.sorted())
        dev, _ = mibs.poll(targets[i] if targets else d.name, fw.walk)
        out.append(dev)
    return out


def codes(topo):
    return sorted((f.code, f.node, f.port) for f in topo.findings)


def test_reference_lab_findings():
    topo = build(poll_all(reference_lab()))
    assert codes(topo) == [
        ("autoneg-mismatch", "sw1", "Gi1/0/5"),
        ("duplex-mismatch", "sw1", "Gi1/0/3"),
        ("native-vlan-mismatch", "sw1", "Gi1/0/2"),
        ("one-way-adjacency", "sw2.lab.example", "Ethernet1/3"),
        ("shared-port", "sw1", "Gi1/0/4"),
    ]
    sev = {f.code: f.severity for f in topo.findings}
    assert sev["duplex-mismatch"] == "critical" and sev["shared-port"] == "info"
    assert len(topo.nodes) == 6 and len(topo.links) == 7


def test_lldp_and_cdp_sightings_merge_into_one_link():
    topo = build(poll_all(reference_lab()))
    names = {n.id: n.name for n in topo.nodes.values()}
    sw1_sw2 = [lk for lk in topo.links if {names[lk.a.node], names[lk.b.node]} == {"sw1", "sw2.lab.example"}]
    assert len(sw1_sw2) == 2
    first = [lk for lk in sw1_sw2 if "Gi1/0/1" in (lk.a.port, lk.b.port)][0]
    assert sorted(first.protocols) == ["cdp", "lldp"] and first.bidirectional and not first.findings


def test_facts_prefer_own_data_over_advertised():
    topo = build(poll_all(reference_lab()))
    names = {n.id: n.name for n in topo.nodes.values()}
    lk = [lk for lk in topo.links if "Ethernet1/2" in (lk.a.port, lk.b.port)][0]
    ep = lk.a if names[lk.a.node].startswith("sw2") else lk.b
    assert ep.facts.pvid == 10 and ep.facts.pvid_src.startswith("sw2.lab.example: LLDP-EXT-DOT1 local")


def test_duplex_mismatch_detected_from_typed_fixture():
    fw = FileWalker.from_file(os.path.join(FIXTURES, "c9300-typed.walk"))
    dev, _ = mibs.poll("10.20.0.11", fw.walk)
    topo = build([dev])
    found = {f.code: f for f in topo.findings}
    assert found["duplex-mismatch"].port == "Gi1/0/2" and found["duplex-mismatch"].peer == "app01"
    assert "speed-mismatch" not in found  # both 100 Mb/s
    # LLDP and CDP sightings of dist-sw01 are one node and one link
    dist = [n for n in topo.nodes.values() if n.name.startswith("dist-sw01")]
    assert len(dist) == 1
    uplink = [lk for lk in topo.links if dist[0].id in (lk.a.node, lk.b.node)]
    assert len(uplink) == 1 and sorted(uplink[0].protocols) == ["cdp", "lldp"]


def test_neighbor_mismatch_when_peer_sees_someone_else():
    a = Dev("a", "00:00:00:00:00:0a").iface(1, "p1").lport(1, "p1").rem(1, 1, "b", "p1", chassis="00:00:00:00:00:0b")
    b = Dev("b", "00:00:00:00:00:0b").iface(1, "p1").lport(1, "p1").rem(1, 1, "c", "x9", chassis="00:00:00:00:00:0c")
    topo = build(poll_all([a, b]))
    f = [f for f in topo.findings if f.code == "neighbor-mismatch"]
    assert len(f) == 1 and f[0].node == "b" and "sees c" in f[0].message


def test_no_one_way_finding_when_peer_lacks_the_protocol():
    a = Dev("a").iface(1, "Gi1/0/1", "GigabitEthernet1/0/1").cdp(1, 1, "b", "Eth1/1")
    b = Dev("b", "00:00:00:00:00:0b").iface(5, "Eth1/1", "Ethernet1/1").lport(1, "Eth1/1")
    topo = build(poll_all([a, b]))
    assert "one-way-adjacency" not in [f.code for f in topo.findings]
    lk = topo.links[0]
    assert {lk.a.port, lk.b.port} == {"Gi1/0/1", "Eth1/1"}


def test_same_device_through_two_addresses_is_polled_once():
    devs = reference_lab()
    topo = build(poll_all([devs[0], devs[0]], targets=["10.0.0.1", "192.0.2.1"]))
    assert sum(1 for n in topo.nodes.values() if n.polled) == 1
    assert any(f.code == "duplicate-device" for f in topo.findings)


def test_server_dual_homed_is_one_node():
    srv = "52:54:00:00:00:01"
    a = (
        Dev("a", "00:00:00:00:00:0a")
        .iface(1, "p1")
        .lport(1, "p1")
        .rem(1, 1, "", "", chassis=srv, port_subtype=3, port_raw=b"\x01" * 6, port_desc="eno1")
    )
    b = (
        Dev("b", "00:00:00:00:00:0b")
        .iface(1, "p1")
        .lport(1, "p1")
        .rem(1, 1, "", "", chassis=srv, port_subtype=3, port_raw=b"\x02" * 6, port_desc="eno2")
    )
    topo = build(poll_all([a, b]))
    ext = [n for n in topo.nodes.values() if not n.polled]
    assert len(ext) == 1 and ext[0].chassis_id == srv and len(topo.links) == 2


def test_failed_device_and_partial_data_findings():
    ok = poll_all(reference_lab()[:1])[0]
    ok.warnings = ["cdpCacheTable: timeout"]
    failed = Device(target="10.0.0.99", error="10.0.0.99: no response")
    topo = build([ok, failed])
    sev = {f.code: f.severity for f in topo.findings}
    assert sev["poll-failed"] == "unknown" and sev["partial-data"] == "info"
    assert topo.nodes["10_0_0_99"].error


def test_speed_mismatch_and_down_interfaces_ignored():
    a = (
        Dev("a", "00:00:00:00:00:0a")
        .iface(1, "p1", speed=1000)
        .iface(2, "p2", speed=1000, up=False)
        .lport(1, "p1")
        .lport(2, "p2")
        .rem(1, 1, "b", "q1", chassis="00:00:00:00:00:0b", mau=16)
        .rem(2, 2, "c", "q2", chassis="00:00:00:00:00:0c", mau=16)
    )
    topo = build(poll_all([a]))
    sp = [f for f in topo.findings if f.code == "speed-mismatch"]
    assert len(sp) == 1 and sp[0].port == "p1"


def test_norm_name():
    assert norm_name("SW2(FDO1234X)") == "sw2"
    assert norm_name("sw2.example.com.") == "sw2.example.com"


def test_name_collision_between_unrelated_neighbours_keeps_them_apart():
    a = (
        Dev("a", "00:00:00:00:00:0a")
        .iface(1, "p1")
        .iface(2, "p2")
        .lport(1, "p1")
        .lport(2, "p2")
        .rem(1, 1, "ap", "x", chassis="00:00:00:00:00:01", caps=lldp_caps("wlanAccessPoint"))
        .rem(2, 2, "ap", "x", chassis="00:00:00:00:00:02", caps=lldp_caps("wlanAccessPoint"))
    )
    topo = build(poll_all([a]))
    ext = [n for n in topo.nodes.values() if not n.polled]
    assert sorted(n.chassis_id for n in ext) == ["00:00:00:00:00:01", "00:00:00:00:00:02"]
    assert len({n.id for n in ext}) == 2 and "shared-port" not in [f.code for f in topo.findings]
