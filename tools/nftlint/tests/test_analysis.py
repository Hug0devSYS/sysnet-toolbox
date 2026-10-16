"""Static checks on synthetic and fixture rulesets."""

from conftest import ACCEPT, DROP, chain, m, meta, nft_doc, payload, rule

from nftlint.analysis import run_static_checks
from nftlint.iptables import parse_iptables_save
from nftlint.nftjson import parse_nft_json
from nftlint.values import DEFAULT_SENSITIVE_PORTS


def check(doc):
    return run_static_checks(parse_nft_json(doc, "t"), DEFAULT_SENSITIVE_PORTS)


def codes(findings):
    return sorted(f.code for f in findings)


def by_code(findings, code):
    return [f for f in findings if f.code == code]


DPORT = payload("tcp", "dport")
SADDR = payload("ip", "saddr")


def test_shadowed_with_conflicting_verdict():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(DPORT, {"set": [80, 443]}), ACCEPT, handle=10),
        rule("in", m(DPORT, 443), m(SADDR, "192.0.2.1"), DROP, handle=11),
    )
    (f,) = by_code(check(doc), "NFT001")
    assert f.severity == "high" and f.rule.handle == 11 and f.related.handle == 10
    assert "accept instead of drop" in f.message


def test_redundant_same_class_and_reject_vs_drop():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(DPORT, {"range": [1, 1024]}), DROP),
        rule("in", m(DPORT, 23), {"reject": None}),
        rule("in", m(DPORT, 22), {"counter": None}),
    )
    found = by_code(check(doc), "NFT002")
    assert [f.rule.index for f in found] == [2, 3]


def test_partial_overlap_is_not_shadowing():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(DPORT, {"range": [1, 100]}), ACCEPT),
        rule("in", m(DPORT, {"range": [50, 200]}), DROP),
        rule("in", m(meta("mark"), 1), DROP),
        rule("in", m(DPORT, 60), {"jump": {"target": "x"}}),
    )
    found = check(doc)
    assert by_code(found, "NFT001")[0].rule.index == 4  # jump shadowed by #1
    assert all(f.rule.index != 2 for f in found if f.rule is not None and f.code != "NFT007")


def test_non_terminal_rules_do_not_shadow():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", {"counter": None}),
        rule("in", m(DPORT, 22), {"jump": {"target": "x"}}),
        rule("in", m(DPORT, 22), ACCEPT),
        chain("x"),
    )
    assert not by_code(check(doc), "NFT001") and not by_code(check(doc), "NFT002")


def test_unreachable_after_catch_all():
    doc = nft_doc(
        chain("in", hook="input", policy="accept"),
        rule("in", m(DPORT, 22), ACCEPT),
        rule("in", DROP),
        rule("in", m(DPORT, 80), ACCEPT),
        rule("in", m(DPORT, 81), ACCEPT),
    )
    found = check(doc)
    (f,) = by_code(found, "NFT003")
    assert f.rule.index == 3 and f.extra["count"] == 2
    assert not by_code(found, "NFT006")  # catch-all drop makes the chain restrictive


def test_unreachable_and_undefined_chains():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(DPORT, 22), {"jump": {"target": "used"}}),
        rule("in", m(DPORT, 23), {"goto": {"target": "missing"}}),
        chain("used"),
        chain("orphan"),
        rule("orphan", {"jump": {"target": "orphan_child"}}),
        chain("orphan_child"),
    )
    found = check(doc)
    unreachable = {f.chain.name: f for f in by_code(found, "NFT004")}
    assert set(unreachable) == {"orphan", "orphan_child"}
    assert "only referenced" in unreachable["orphan_child"].message
    (undef,) = by_code(found, "NFT013")
    assert "missing" in undef.message


def test_any_any_variants():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(meta("iifname"), "lo"), ACCEPT),
        rule("in", m({"ct": {"key": "state"}}, ["established", "related"], "in"), ACCEPT),
        rule("in", m(meta("l4proto"), {"set": ["icmp", "ipv6-icmp"]}), ACCEPT),
        rule("in", m(meta("iifname"), "wg0"), ACCEPT),
        rule("in", m(meta("l4proto"), "tcp"), ACCEPT),
    )
    found = by_code(check(doc), "NFT005")
    assert [(f.rule.index, f.severity) for f in found] == [(4, "low"), (5, "high")]


def test_sensitive_ports():
    doc = nft_doc(
        chain("in", hook="input", policy="drop"),
        rule("in", m(DPORT, 22), m(SADDR, {"prefix": {"addr": "10.0.0.0", "len": 8}}), ACCEPT),
        rule("in", m(DPORT, 3306), m(SADDR, {"prefix": {"addr": "10.0.0.0", "len": 8}}, "!="), ACCEPT),
        rule("in", m(DPORT, {"set": [80, 5432]}), ACCEPT),
        rule("in", m(DPORT, {"range": [1, 65535]}), m(meta("iifname"), "eth9"), ACCEPT),
    )
    found = by_code(check(doc), "NFT007")
    assert [(f.rule.index, f.extra["ports"]) for f in found] == [(2, [3306]), (3, [5432])]


def test_permissive_policy_considers_all_chains_on_hook():
    doc = nft_doc(
        chain("a", hook="input", policy="accept", prio=-10),
        rule("a", m(DPORT, 22), ACCEPT),
        chain("b", hook="input", policy="drop", table="u"),
    )
    assert not by_code(check(doc), "NFT006")
    doc2 = nft_doc(
        chain("a", hook="input", policy="accept"),
        rule("a", m(DPORT, 22), ACCEPT),
        rule("a", {"jump": {"target": "tail"}}),
        chain("tail"),
        rule("tail", {"reject": None}),
    )
    assert not by_code(check(doc2), "NFT006")
    doc3 = nft_doc(chain("a", hook="input", policy="accept"), rule("a", m(DPORT, 22), DROP))
    (f,) = by_code(check(doc3), "NFT006")
    assert f.severity == "high" and f.extra["families"] == ["IPv4", "IPv6"]


def test_ipv4_only_ruleset(fixture_text):
    found = run_static_checks(parse_nft_json(fixture_text("ipv4only.json"), "x"), DEFAULT_SENSITIVE_PORTS)
    assert "NFT010" in codes(found)
    assert "NFT006" in codes(found)


def test_nat_chains_are_skipped(fixture_text):
    rs = parse_iptables_save(fixture_text("iptables.txt"), "ipt", "ip")
    found = run_static_checks(rs, DEFAULT_SENSITIVE_PORTS)
    assert not [f for f in found if f.rule is not None and f.rule.chain.table == "nat"]
    assert {f.chain.name for f in by_code(found, "NFT004")} == {"UNUSED"}


def test_server_fixture_expected_findings(fixture_text):
    found = run_static_checks(parse_nft_json(fixture_text("server.json"), "s"), DEFAULT_SENSITIVE_PORTS)
    summary = sorted((f.code, f.location()) for f in found if f.code != "NFT000")
    locs = {c: [loc for cc, loc in summary if cc == c] for c, _ in summary}
    assert any("#9" in loc for loc in locs["NFT001"])  # tcp dport 8443 accept after drop
    assert any("#7" in loc for loc in locs["NFT002"])  # tcp dport 443 after {80,443}
    assert locs["NFT003"] == ["inet filter forward #2 (handle 30)"]
    assert locs["NFT004"] == ["inet filter legacy"]
    assert "NFT005" in locs and "NFT006" in locs and len(locs["NFT007"]) == 2


def test_clean_fixture_has_no_actionable_findings(fixture_text):
    found = run_static_checks(parse_nft_json(fixture_text("clean.json"), "c"), DEFAULT_SENSITIVE_PORTS)
    assert codes(found) == ["NFT000"]
