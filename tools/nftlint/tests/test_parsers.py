"""nft JSON and iptables-save parsers."""

import pytest
from conftest import ACCEPT, DROP, chain, m, meta, nft_doc, payload, rule

from nftlint.iptables import looks_like_ipv6, parse_iptables_save
from nftlint.model import CTSTATE, DPORT, L4PROTO, NFPROTO, SADDR4, SADDR6, values
from nftlint.nftjson import TCP_SYN, ParseError, parse_nft_json


def rules_of(rs, name):
    return next(c for c in rs.chains.values() if c.name == name).rules


class TestNftJson:
    def test_server_fixture(self, fixture_text):
        rs = parse_nft_json(fixture_text("server.json"), "server.json")
        assert rs.sources[0]["format"] == "nft-json"
        inp = next(c for c in rs.chains.values() if c.name == "input")
        assert inp.base and inp.hook == "input" and inp.policy == "drop"
        assert inp.nfprotos == frozenset({0, 1})
        r = inp.rules[4]  # tcp dport 22 ip saddr @admin_v4 accept
        assert r.text == "tcp dport 22 ip saddr @admin_v4 accept"
        assert r.match.get(DPORT) == values(DPORT, 22)
        assert r.match.get(L4PROTO) == values(L4PROTO, 6)
        assert r.match.get(NFPROTO) == values(NFPROTO, 0)
        assert r.match.get(SADDR4).size() == 65536 + 1
        assert r.handle is not None and r.verdict.kind == "accept"

    def test_dynamic_set_is_opaque(self, fixture_text):
        rs = parse_nft_json(fixture_text("server.json"), "s")
        r = rules_of(rs, "input")[3]  # ip saddr @f2b drop
        assert r.match.opaque and SADDR4 not in r.match.dims
        assert any("@f2b" in n for n in rs.notes)

    def test_vmap(self, fixture_text):
        rs = parse_nft_json(fixture_text("server.json"), "s")
        r = next(x for x in rules_of(rs, "input") if x.vmap)
        assert r.vmap.dim == DPORT
        kinds = {(s.spans[0][0], v.kind, v.target) for s, v in r.vmap.entries}
        assert kinds == {(5432, "jump", "db"), (3306, "drop", None)}
        assert ("jump", "db") in r.targets()

    def test_ct_state_and_negation(self):
        doc = nft_doc(
            chain("in", hook="input"),
            rule("in", m({"ct": {"key": "state"}}, ["established", "related"], "in"), ACCEPT),
            rule("in", m(payload("tcp", "dport"), {"range": [1000, 2000]}, "!="), DROP),
            rule("in", m(payload("th", "dport"), 1024, "<"), ACCEPT),
            rule("in", m(meta("iifname"), {"set": ["eth0", "wg*"]}), ACCEPT),
        )
        rs = parse_nft_json(doc, "x")
        r1, r2, r3, r4 = rules_of(rs, "in")
        assert r1.match.get(CTSTATE) == values(CTSTATE, 1, 2)
        assert r2.match.get(DPORT).size() == 65536 - 1001
        assert r3.match.get(DPORT).spans == ((0, 1023),)
        assert r4.match.ifaces["iif"].patterns == frozenset({"eth0", "wg*"})

    def test_tcp_syn_forms(self):
        flags = payload("tcp", "flags")
        doc = nft_doc(
            chain("in", hook="input"),
            rule("in", m({"&": [flags, ["fin", "syn", "rst", "ack"]]}, "syn"), ACCEPT),
            rule("in", m(flags, "syn", "in"), ACCEPT),
        )
        r1, r2 = rules_of(parse_nft_json(doc, "x"), "in")
        assert r1.match.opaque == frozenset({TCP_SYN})
        assert r2.match.opaque == frozenset({"tcp flags syn"})

    def test_unknown_expressions_are_opaque(self):
        doc = nft_doc(
            chain("in", hook="input"),
            rule("in", m(meta("mark"), 1), {"counter": {"packets": 0, "bytes": 0}}, ACCEPT),
            rule("in", {"xt": {"type": "match", "name": "multiport"}}, ACCEPT),
            rule("in", m(payload("ip6", "saddr"), "not-an-address"), DROP),
        )
        rs = parse_nft_json(doc, "x")
        r1, r2, r3 = rules_of(rs, "in")
        assert r1.match.opaque and r2.match.opaque and r3.match.opaque
        assert SADDR6 not in r3.match.dims
        assert rs.xt_rules == 1

    def test_rule_before_chain_object(self):
        doc = nft_doc(rule("c", ACCEPT), chain("c", hook="input", policy="drop"))
        rs = parse_nft_json(doc, "x")
        (c,) = rs.chains.values()
        assert c.base and c.policy == "drop" and len(c.rules) == 1

    @pytest.mark.parametrize("text", ["not json", '{"foo": []}', "[]"])
    def test_invalid_documents(self, text):
        with pytest.raises(ParseError):
            parse_nft_json(text, "bad")


class TestIptables:
    def test_fixture(self, fixture_text):
        rs = parse_iptables_save(fixture_text("iptables.txt"), "ipt", "ip")
        inp = next(c for c in rs.chains.values() if c.name == "INPUT" and c.table == "filter")
        assert inp.policy == "drop" and inp.hook == "input" and inp.type == "filter"
        r = {x.index: x for x in inp.rules}
        assert r[1].match.ifaces["iif"].only_loopback()
        assert r[2].match.get(CTSTATE) == values(CTSTATE, 1, 2)
        assert r[4].verdict.kind == "jump" and r[4].verdict.target == "SSH"
        assert r[5].match.get(DPORT).spans == ((80, 80), (443, 443), (8000, 8080))
        assert r[7].match.get(SADDR4).size() == 2**32 - 2**24
        assert r[7].verdict.kind == "reject"
        assert r[9].match.opaque  # -m set
        assert r[10].verdict.kind == "none" and TCP_SYN in r[10].match.opaque  # LOG
        assert r[11].match.get(SADDR4).size() == 6  # iprange
        assert r[15].match.ifaces["iif"].patterns == frozenset({"eth0*"})
        assert r[1].line == 8
        nat = next(c for c in rs.chains.values() if c.table == "nat" and c.name == "POSTROUTING")
        assert nat.rules[0].verdict.kind == "nat"

    def test_ip6tables(self, fixture_text):
        text = fixture_text("ip6tables.txt")
        assert looks_like_ipv6(text)
        rs = parse_iptables_save(text, "ip6", "ip6")
        inp = next(c for c in rs.chains.values() if c.name == "INPUT")
        assert inp.nfprotos == frozenset({1})
        assert inp.rules[2].match.get(SADDR6).size() == 2**80

    def test_old_style_negation_and_counters(self):
        text = "*filter\n:INPUT ACCEPT [0:0]\n[5:300] -A INPUT -s ! 10.0.0.0/8 -p ! tcp -j DROP\nCOMMIT\n"
        r = parse_iptables_save(text, "x").chains[("x", "ip", "filter", "INPUT")].rules[0]
        assert r.match.get(SADDR4).size() == 2**32 - 2**24
        assert not r.match.get(L4PROTO).contains(6)

    def test_uppercase_user_chain_and_extension_target(self):
        text = (
            "*filter\n:INPUT DROP [0:0]\n:MYCHAIN - [0:0]\n"
            "-A INPUT -j MYCHAIN\n-A INPUT -j LOG --log-prefix x\n-A INPUT -j NFQUEUE --queue-num 1\n"
            "COMMIT\n"
        )
        r1, r2, r3 = parse_iptables_save(text, "x").chains[("x", "ip", "filter", "INPUT")].rules
        assert (r1.verdict.kind, r1.verdict.target) == ("jump", "MYCHAIN")
        assert r2.verdict.kind == "none"
        assert r3.verdict.kind == "queue"

    @pytest.mark.parametrize(
        "text",
        [
            "-A INPUT -j ACCEPT\n",
            "*filter\n-N FOO\nCOMMIT\n",
            "*filter\nrandom words\nCOMMIT\n",
            "*filter\nCOMMIT\n",
            '*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m comment --comment "unterminated\nCOMMIT\n',
        ],
    )
    def test_errors(self, text):
        with pytest.raises(ParseError):
            parse_iptables_save(text, "bad")

    def test_unknown_options_consume_arguments(self):
        text = (
            "*filter\n:INPUT DROP [0:0]\n"
            "-A INPUT -p tcp -m recent --rcheck --seconds 60 --hitcount 4 --name ssh -j DROP\n"
            "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n"
        )
        r1, r2 = parse_iptables_save(text, "x").chains[("x", "ip", "filter", "INPUT")].rules
        assert r1.verdict.kind == "drop" and len(r1.match.opaque) == 4
        assert r2.match.get(DPORT) == values(DPORT, 22)
