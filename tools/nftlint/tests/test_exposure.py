"""Symbolic evaluation of the input path and socket correlation."""

import pytest
from conftest import ACCEPT, DROP, chain, m, meta, nft_doc, payload, rule

from nftlint.exposure import Packet, Simulator, analyse_exposure, exposure_findings
from nftlint.iptables import parse_iptables_save
from nftlint.model import IPV4, IPV6
from nftlint.nftjson import parse_nft_json
from nftlint.ss import parse_ss
from nftlint.values import DEFAULT_SENSITIVE_PORTS, format_addresses

TCP = 6
DPORT = payload("tcp", "dport")
SADDR = payload("ip", "saddr")
TEN = {"prefix": {"addr": "10.0.0.0", "len": 8}}


def evaluate(doc, port, family=IPV4, daddr=None, proto=TCP):
    sim = Simulator(parse_nft_json(doc, "t"))
    return sim.evaluate(Packet(family, proto, port, daddr))


def sources(res):
    return format_addresses(res.accepted, 4 if res.family == IPV4 else 6)


def test_open_restricted_filtered():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(DPORT, 80), ACCEPT),
        rule("in", m(DPORT, 22), m(SADDR, TEN), ACCEPT),
    )
    assert evaluate(doc, 80).status == "open"
    r = evaluate(doc, 22)
    assert r.status == "restricted" and sources(r) == "10.0.0.0/8"
    assert evaluate(doc, 22, IPV6).status == "filtered"
    assert evaluate(doc, 25).status == "filtered"


def test_default_policy_accept_flagged():
    doc = nft_doc(chain("in", hook="input", policy="accept"), rule("in", m(DPORT, 22), m(SADDR, TEN), DROP))
    r = evaluate(doc, 22)
    assert r.status == "restricted" and r.via_policy_only
    assert sources(r) == "any except 10.0.0.0/8"


def test_ct_state_and_loopback_rules_do_not_match_new_external_packets():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(meta("iif"), "lo"), ACCEPT),
        rule("in", m({"ct": {"key": "state"}}, ["established", "related"], "in"), ACCEPT),
        rule("in", m(meta("iifname"), "lo", "!="), m(DPORT, 22), ACCEPT),
    )
    assert evaluate(doc, 80).status == "filtered"
    assert evaluate(doc, 22).status == "open"


def test_jump_return_and_goto_semantics(fixture_text):
    sim = Simulator(parse_nft_json(fixture_text("multichain.json"), "m"))
    r = sim.evaluate(Packet(IPV4, TCP, 2222))
    # early: goto ssh_gate -> 10/8 returns to the base chain's policy (accept),
    # others dropped; late: accepts 2222.
    assert r.status == "restricted" and sources(r) == "10.0.0.0/8"
    r = sim.evaluate(Packet(IPV4, TCP, 8080))
    assert sources(r) == "any except 198.51.100.0/24"
    assert sim.evaluate(Packet(IPV6, TCP, 8080)).status == "open"
    r = sim.evaluate(Packet(IPV4, TCP, 8081))  # meta mark: unknown
    assert r.status == "conditional" and r.maybe_rules
    r = sim.evaluate(Packet(IPV4, TCP, 8082))  # iifname eth1: unknown
    assert r.status == "conditional"


def test_jump_falls_through_to_caller():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(DPORT, 22), {"jump": {"target": "sub"}}),
        rule("in", m(DPORT, 22), m(SADDR, {"prefix": {"addr": "192.0.2.0", "len": 24}}), ACCEPT),
        chain("sub"),
        rule("sub", m(SADDR, TEN), ACCEPT),
    )
    assert sources(evaluate(doc, 22)) == "10.0.0.0/8, 192.0.2.0/24"


def test_vmap_on_source_and_port():
    vmap_src = {
        "vmap": {
            "key": SADDR,
            "data": {"set": [[TEN, ACCEPT], [{"prefix": {"addr": "0.0.0.0", "len": 0}}, DROP]]},
        }
    }
    vmap_port = {"vmap": {"key": DPORT, "data": {"set": [[22, {"jump": {"target": "ssh"}}], [80, ACCEPT]]}}}
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(DPORT, 5000), vmap_src),
        rule("in", vmap_port),
        chain("ssh"),
        rule("ssh", m(SADDR, "203.0.113.7"), ACCEPT),
    )
    assert sources(evaluate(doc, 5000)) == "10.0.0.0/8"
    assert evaluate(doc, 80).status == "open"
    assert sources(evaluate(doc, 22)) == "203.0.113.7/32"


def test_wildcard_destination_handling():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(payload("ip", "daddr"), {"prefix": {"addr": "224.0.0.0", "len": 4}}), DROP),
        rule("in", m(payload("ip", "daddr"), "192.0.2.5"), m(DPORT, 443), ACCEPT),
        rule("in", m(DPORT, 80), ACCEPT),
    )
    r = evaluate(doc, 80)
    assert r.status == "open" and not r.caveats  # multicast drop cannot hit unicast traffic
    assert evaluate(doc, 443).status == "conditional"  # unknown which address
    assert evaluate(doc, 443, daddr=0xC0000205).status == "open"
    assert evaluate(doc, 443, daddr=0xC0000206).status == "filtered"


def test_maybe_drop_is_reported_as_caveat_not_assumed():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(meta("mark"), 7), DROP),
        rule("in", m(DPORT, 80), ACCEPT),
    )
    r = evaluate(doc, 80)
    assert r.status == "open" and len(r.caveats) == 1


def test_tcp_syn_condition_is_satisfied_by_first_packet():
    flags = payload("tcp", "flags")
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(flags, "syn", "in"), m(DPORT, 22), ACCEPT),
    )
    assert evaluate(doc, 22).status == "open"


def test_no_input_chain_is_unfiltered():
    doc = nft_doc(chain("out", hook="output", policy="accept"))
    assert evaluate(doc, 22).status == "unfiltered"


def test_jump_loop_is_bounded():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", {"jump": {"target": "a"}}),
        chain("a"),
        rule("a", {"jump": {"target": "a"}}),
    )
    assert evaluate(doc, 22).status == "filtered"


@pytest.fixture
def iptables_exposure(fixture_text):
    rs = parse_iptables_save(fixture_text("iptables.txt"), "ipt", "ip")
    listeners = parse_ss(fixture_text("ss.txt"))
    return rs, listeners, analyse_exposure(rs, listeners)


def test_iptables_exposure(iptables_exposure):
    rs, listeners, exps = iptables_exposure
    st = {(e.listener.proto, e.listener.port, e.listener.raw_address): e for e in exps}
    assert st[("tcp", 22, "0.0.0.0")].status == "restricted"
    assert st[("tcp", 5432, "0.0.0.0")].status == "conditional"  # -m set
    assert st[("tcp", 3306, "127.0.0.1")].status == "local"
    assert st[("tcp", 22, "[::]")].status == "unknown"
    found = exposure_findings(rs, exps, listeners, DEFAULT_SENSITIVE_PORTS)
    codes = sorted({f.code for f in found})
    assert codes == ["NFT008", "NFT014"]  # 161, 443 and 9100 have listeners
    (redis,) = [f for f in found if f.code == "NFT008"]
    assert "6379" in redis.message and "almost any" in redis.message
    (unknown,) = [f for f in found if f.code == "NFT014"]
    assert unknown.extra["count"] == 3


def test_ip6tables_fills_the_gap(fixture_text):
    rs = parse_iptables_save(fixture_text("iptables.txt"), "ipt", "ip")
    rs.merge(parse_iptables_save(fixture_text("ip6tables.txt"), "ip6t", "ip6"))
    listeners = parse_ss(fixture_text("ss.txt"))
    exps = analyse_exposure(rs, listeners)
    found = exposure_findings(rs, exps, listeners, DEFAULT_SENSITIVE_PORTS)
    assert not [f for f in found if f.code == "NFT014"]
    nginx = [f for f in found if f.code == "NFT011" and "443" in f.message]
    assert nginx and "default accept policy" in nginx[0].message


def test_stale_openings_need_matching_protocol(fixture_text):
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(payload("udp", "dport"), 22), ACCEPT),
        rule("in", m(DPORT, 22), ACCEPT),
        rule("in", m(DPORT, {"range": [1, 65535]}), ACCEPT),
    )
    rs = parse_nft_json(doc, "t")
    listeners = parse_ss("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
    found = exposure_findings(rs, analyse_exposure(rs, listeners), listeners, DEFAULT_SENSITIVE_PORTS)
    stale = [f for f in found if f.code == "NFT009"]
    assert [f.rule.index for f in stale] == [1]
