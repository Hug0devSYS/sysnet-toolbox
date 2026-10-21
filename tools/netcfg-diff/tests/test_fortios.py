from conftest import read_fixture

from netcfg_diff import fortios
from netcfg_diff.cli import diff_configs
from netcfg_diff.loader import load
from netcfg_diff.masking import Masker


def test_structure_and_meta(masker):
    cfg = fortios.parse(read_fixture("fortios_old.conf"), masker=masker)
    assert cfg.meta["version"] == "FGT60F-7.2.5-FW-build1517-230606"
    policy = cfg.root.find("config firewall policy")
    assert policy.ordered and [c.key for c in policy.children] == ["edit 1", "edit 2"]
    wan = cfg.root.find("config system interface").find("edit wan1")
    assert wan.text == 'edit "wan1"'
    allow = wan.find("set allowaccess")
    assert allow.members == ("ping", "https", "ssh")


def test_fixture_diff(masker):
    old = load(read_fixture("fortios_old.conf"), "fortios", masker)
    new = load(read_fixture("fortios_new.conf"), "fortios", masker)
    chs = diff_configs(old, new)
    got = {(c.op, c.node.text) for c in chs}
    assert ("move", "edit 2") in got
    assert ("modify", "set admintimeout 5") in got
    assert ("add", "set logtraffic all") in got
    assert ("add", 'edit "srv-dns"') in got
    member = [c for c in chs if c.node.key == "set member"][0]
    assert member.detail == {"added": ["srv-dns"], "removed": []}
    # wan1 allowaccess only reordered: no change; secrets masked
    assert not any("wan1" in " ".join(c.path) for c in chs)
    assert all("AbCdEf" not in c.node.text for c in chs)


def test_enc_values_presence_mode():
    old, new = read_fixture("fortios_old.conf"), read_fixture("fortios_new.conf")
    m = Masker("presence")
    chs = diff_configs(load(old, "fortios", m), load(new, "fortios", m))
    assert not any("psksecret" in c.node.text for c in chs)


def test_append_unset_unselect_and_duplicates(masker):
    text = """config firewall addrgrp
    edit "g"
        set member "a"
        append member "b" "c"
        unselect member "a"
        set comment "x"
        set comment "y"
    next
end
config system dns
    unset secondary
end
"""
    cfg = fortios.parse(text, masker=masker)
    g = cfg.root.find("config firewall addrgrp").find("edit g")
    assert g.find("set member").members == ("b", "c")
    assert [c.text for c in g.children] == ['set member "b" "c"', 'set comment "y"']
    other = fortios.parse("config system dns\n    set secondary 1.1.1.1\nend\n", masker=masker)
    chs = diff_configs(other, cfg)
    assert any(c.op == "modify" and c.node.text == "unset secondary" for c in chs)


def test_multiline_private_key_and_snmp_community(masker):
    text = """config vpn certificate local
    edit "srv"
        set password ENC abcdef==
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI
-----END ENCRYPTED PRIVATE KEY-----"
        set certificate "-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBa
-----END CERTIFICATE-----"
    next
end
config system snmp community
    edit 1
        set name "pr1vate-comm"
    next
end
"""
    cfg = fortios.parse(text, masker=masker)
    srv = cfg.root.find("config vpn certificate local").find("edit srv")
    texts = [c.text for c in srv.children]
    assert texts[0].startswith("set password <secret:")
    assert texts[1].startswith("set private-key <secret:") and "MIIF" not in texts[1]
    assert "BEGIN CERTIFICATE" in texts[2]  # certificates are public
    comm = cfg.root.find("config system snmp community").find("edit 1").children[0].text
    assert "pr1vate-comm" not in comm


def test_unbalanced_end_next_is_tolerated(masker):
    cfg = fortios.parse("next\nend\nconfig system global\n    set hostname a\nend\nend\n", masker=masker)
    assert cfg.root.find("config system global").find("set hostname").cmp == ("a",)
