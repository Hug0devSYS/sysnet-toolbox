import re

from conftest import read_fixture

from netcfg_diff import cisco
from netcfg_diff.cli import diff_configs
from netcfg_diff.loader import detect, load
from netcfg_diff.render import render_text


def changes(old, new, masker, vendor="ios", **kw):
    return diff_configs(load(old, vendor, masker), load(new, vendor, masker), **kw)


def ops(chs):
    return [(c.op, c.path, c.node.text) for c in chs]


def test_hierarchy_and_terminators(masker):
    cfg = cisco.parse(
        "router bgp 1\n neighbor 1.1.1.1 remote-as 2\n address-family ipv4\n  network 10.0.0.0\n"
        " exit-address-family\n address-family ipv6\n  network 2001:db8::/32\n exit-address-family\n!\nend\n",
        masker=masker,
    )
    bgp = cfg.root.children[0]
    assert [c.text for c in bgp.children] == [
        "neighbor 1.1.1.1 remote-as 2",
        "address-family ipv4",
        "address-family ipv6",
    ]
    assert bgp.children[2].children[0].text == "network 2001:db8::/32"


def test_iosxr_route_policy_terminators(masker):
    text = (
        "route-policy PASS\n  if destination in P1 then\n    pass\n  endif\nend-policy\n!\n"
        "route-policy DROP\n  drop\nend-policy\n"
    )
    cfg = cisco.parse(text, "iosxr", masker)
    assert [c.text for c in cfg.root.children] == ["route-policy PASS", "route-policy DROP"]
    assert cfg.root.children[0].ordered


def test_fixture_changes(masker):
    chs = changes(read_fixture("ios_old.cfg"), read_fixture("ios_new.cfg"), masker)
    got = {(c.op, c.path, c.node.text) for c in chs}
    assert ("modify", ("interface GigabitEthernet0/0/1",), "description LAN-Core") in got
    assert ("modify", ("interface GigabitEthernet0/0/1",), "no shutdown") in got
    assert ("modify", ("interface GigabitEthernet0/0/0",), "ip access-group EDGE-IN-V2 in") in got
    assert ("move", ("ip access-list extended EDGE-IN",), "permit icmp any any echo-reply") in got
    assert ("add", (), "interface Vlan40") in got
    assert ("modify", ("line vty 0 4",), "exec-timeout 5 0") in got
    vlan = [c for c in chs if "allowed vlan" in c.node.text][0]
    assert vlan.detail == {"added": [33], "removed": []}
    # no noise: interface order, router ospf statement order, prefix-list resequencing, ntp clock-period
    assert not any("ospf" in " ".join(c.path) or "prefix-list" in c.node.text for c in chs)
    assert not any("clock-period" in c.node.text for c in chs)
    assert len(chs) == 9


def test_identical_after_reordering_unordered_contexts(masker):
    a = "interface A\n description x\n mtu 9000\ninterface B\n shutdown\n"
    b = "interface B\n shutdown\ninterface A\n mtu 9000\n description x\n"
    assert changes(a, b, masker) == []


def test_trunk_vlan_semantics(masker):
    a = "interface Po1\n switchport trunk allowed vlan 1-10\n switchport trunk allowed vlan remove 5\n"
    b = "interface Po1\n switchport trunk allowed vlan 1-4,6-10\n"
    assert changes(a, b, masker) == []
    c = "interface Po1\n switchport trunk allowed vlan except 1-4093\n"
    d = "interface Po1\n switchport trunk allowed vlan 4094\n"
    assert changes(c, d, masker) == []
    e = "interface Po1\n switchport trunk allowed vlan all\n"
    chs = changes(d, e, masker)
    assert chs[0].op == "modify" and chs[0].detail["added"] == list(range(1, 4094))
    # unknown syntax is left untouched rather than misinterpreted
    cfg = cisco.parse("interface Po1\n switchport trunk allowed vlan foo\n", masker=masker)
    assert cfg.root.children[0].children[0].text == "switchport trunk allowed vlan foo"


def test_acl_sequence_numbers_are_not_significant(masker):
    a = "ip access-list ACL\n 10 permit ip any 10.0.0.0/8\n 20 deny ip any any\n"
    b = "ip access-list ACL\n 100 permit ip any 10.0.0.0/8\n 200 deny ip any any\n"
    assert changes(a, b, masker, "nxos") == []
    c = "ip access-list ACL\n 10 deny ip any any\n 20 permit ip any 10.0.0.0/8\n"
    assert [x.op for x in changes(a, c, masker, "nxos")] == ["move"]


def test_numbered_acl_grouping_and_order(masker):
    a = "access-list 101 permit tcp any any eq 22\naccess-list 101 deny ip any any\nhostname r\n"
    b = "hostname r\naccess-list 101 deny ip any any\naccess-list 101 permit tcp any any eq 22\n"
    chs = changes(a, b, masker)
    assert ops(chs) == [("move", ("access-list 101",), "access-list 101 deny ip any any")]


def test_negation_pairs_with_positive_form(masker):
    a = "interface A\n ip redirects\n"
    b = "interface A\n no ip redirects\n"
    assert ops(changes(a, b, masker)) == [("modify", ("interface A",), "no ip redirects")]
    assert cisco.statement_key("no shutdown") == "shutdown"
    assert cisco.statement_key("ip access-group X out") == "ip access-group out"
    assert (
        cisco.statement_key("ip address 1.1.1.1 255.0.0.0 secondary")
        == "ip address 1.1.1.1 255.0.0.0 secondary"
    )
    assert cisco.statement_key("neighbor 1.1.1.1 route-map RM in") == "neighbor 1.1.1.1 route-map in"


def test_duplicate_context_is_merged(masker):
    cfg = cisco.parse("interface A\n mtu 1500\ninterface B\ninterface A\n description x\n", masker=masker)
    assert [c.text for c in cfg.root.children] == ["interface A", "interface B"]
    assert [c.text for c in cfg.root.children[0].children] == ["mtu 1500", "description x"]


def test_banner_parsing(masker):
    text = "banner motd ^C\nLine one\n  indented\n^C\nbanner login #single#\nhostname r\n"
    cfg = cisco.parse(text, masker=masker)
    motd, login, host = cfg.root.children
    assert motd.text == "banner motd" and [c.text for c in motd.children] == ["Line one", "  indented"]
    assert [c.text for c in login.children] == ["single"]
    assert host.text == "hostname r"
    etx = cisco.parse("banner exec \x03\nhello\n\x03\n", masker=masker)
    assert [c.text for c in etx.root.children[0].children] == ["hello"]


def test_secrets_never_printed(masker):
    a = read_fixture("ios_old.cfg")
    b = read_fixture("ios_new.cfg") + (
        "snmp-server community n3w-c0mm RW\nsnmp-server user u g v3 auth sha AuThPaSs priv aes 128 PrIvPaSs\n"
        "crypto isakmp key IsAkMpKeY address 0.0.0.0\ntacacs server T\n key 7 1234ABCD\n"
        "key chain K\n key 1\n  key-string 7 0011AABB\n"
    )
    left, right = load(a, "ios", masker), load(b, "ios", masker)
    out = render_text(_result(left, right, diff_configs(left, right)))
    for secret in (
        "$9$",
        "0822455D0A16",
        "s3cr3t-ro",
        "n3w-c0mm",
        "AuThPaSs",
        "PrIvPaSs",
        "IsAkMpKeY",
        "1234ABCD",
        "0011AABB",
    ):
        assert secret not in out
    assert "key 1" in out  # key-chain identifiers are not secrets
    assert re.search(r"secret 9 <secret:[0-9a-f]{8}>", out)


def _result(left, right, chs):
    from netcfg_diff.render import Result

    return Result("a", "b", left, right, chs)


def test_secret_modes():
    from netcfg_diff.masking import Masker

    a = "username admin secret 9 $9$aaaa$bbbb\n"
    b = "username admin secret 9 $9$cccc$dddd\n"
    m = Masker("mask")
    assert len(changes(a, b, m)) == 1
    p = Masker("presence")
    assert changes(a, b, p) == []
    s = Masker("show")
    assert "$9$cccc$dddd" in changes(a, b, s)[0].after.text
    assert Masker("mask").line("service password-encryption") == "service password-encryption"
    assert Masker("mask").line("password encryption aes") == "password encryption aes"


def test_volatile_and_ignore(masker):
    a = "hostname r\nntp clock-period 1\n"
    b = "hostname r\nntp clock-period 2\n"
    assert diff_configs(load(a, "ios", masker), load(b, "ios", masker)) == []
    kept = diff_configs(
        load(a, "ios", masker, keep_volatile=True), load(b, "ios", masker, keep_volatile=True)
    )
    assert len(kept) == 2
    ig = [re.compile(r"^hostname ")]
    assert (
        diff_configs(load("hostname a\n", "ios", masker, ig), load("hostname b\n", "ios", masker, ig)) == []
    )


def test_detection():
    assert detect(read_fixture("ios_old.cfg")) == "ios"
    assert detect("!Command: show running-config\nfeature bgp\nhostname n9k\n") == "nxos"
    assert (
        detect("!! IOS XR Configuration 7.9.2\nhostname xr\nroute-policy P\n  pass\nend-policy\n") == "iosxr"
    )
    assert detect("! device: leaf1 (DCS-7050SX3, EOS-4.30.1F)\nhostname leaf1\n") == "eos"
    assert detect(read_fixture("junos_old.conf")) == "junos"
    assert detect(read_fixture("junos_new.set")) == "junos"
    assert detect(read_fixture("fortios_old.conf")) == "fortios"
    assert detect("") == "ios"
