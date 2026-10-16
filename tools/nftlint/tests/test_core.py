"""Interval algebra, match coverage, value conversion and ss parsing."""

import pytest

from nftlint.intervals import IntervalSet
from nftlint.model import (
    DPORT,
    L4PROTO,
    SADDR4,
    IfaceMatch,
    Match,
    span,
    universe,
    values,
)
from nftlint.ss import SsParseError, parse_ss
from nftlint.values import Unsupported, address_span, format_addresses, format_ports, port_number


class TestIntervalSet:
    def test_normalises_and_merges(self):
        s = IntervalSet(0, 100, [(10, 20), (21, 30), (5, 12), (90, 200), (-5, -1)])
        assert s.spans == ((5, 30), (90, 100))

    def test_algebra(self):
        a = IntervalSet(0, 99, [(10, 19), (50, 59)])
        b = IntervalSet(0, 99, [(15, 54)])
        assert (a & b).spans == ((15, 19), (50, 54))
        assert (a | b).spans == ((10, 59),)
        assert (a - b).spans == ((10, 14), (55, 59))
        assert a.complement().spans == ((0, 9), (20, 49), (60, 99))
        assert a.complement().complement() == a

    def test_predicates(self):
        a = IntervalSet(0, 9, [(2, 4)])
        assert 3 in a and 5 not in a
        assert a.size() == 3
        assert a.issubset(IntervalSet.full(0, 9))
        assert not IntervalSet.full(0, 9).issubset(a)
        assert IntervalSet.empty(0, 9).is_empty()
        assert IntervalSet.full(0, 9).is_full()

    def test_universe_mismatch(self):
        with pytest.raises(ValueError):
            _ = IntervalSet(0, 9) | IntervalSet(0, 10)

    def test_ipv6_scale(self):
        s = IntervalSet(0, 2**128 - 1, [(2**127, 2**128 - 1)])
        assert s.complement().size() == 2**127


class TestCoverage:
    def test_subset_ports(self):
        outer = Match()
        outer.constrain(L4PROTO, values(L4PROTO, 6))
        outer.constrain(DPORT, values(DPORT, 80, 443))
        inner = Match()
        inner.constrain(L4PROTO, values(L4PROTO, 6))
        inner.constrain(DPORT, values(DPORT, 443))
        assert outer.covers(inner)
        assert not inner.covers(outer)

    def test_unconstrained_inner_not_covered(self):
        outer = Match()
        outer.constrain(DPORT, values(DPORT, 22))
        assert not outer.covers(Match())
        assert Match().covers(outer)

    def test_opaque_is_conservative(self):
        outer = Match()
        outer.add_opaque("limit rate 5/second")
        inner = Match()
        inner.constrain(DPORT, values(DPORT, 22))
        assert not outer.covers(inner)
        assert inner.covers(Match(dims=dict(inner.dims), opaque=frozenset({"x"})))

    def test_negated_address(self):
        not_ten = Match()
        not_ten.constrain(SADDR4, span(SADDR4, *address_span(SADDR4, "10.0.0.0/8")).complement())
        host = Match()
        host.constrain(SADDR4, span(SADDR4, *address_span(SADDR4, "192.0.2.1")))
        assert not_ten.covers(host)
        inside = Match()
        inside.constrain(SADDR4, span(SADDR4, *address_span(SADDR4, "10.1.2.3")))
        assert not not_ten.covers(inside)

    def test_universal_and_impossible(self):
        assert Match().is_universal()
        m = Match()
        m.constrain(DPORT, values(DPORT, 1))
        m.constrain(DPORT, values(DPORT, 2))
        assert m.impossible()
        assert Match(dims={DPORT: universe(DPORT)}).is_universal()


class TestIfaceMatch:
    @pytest.mark.parametrize(
        "inner,outer,expected",
        [
            (IfaceMatch(frozenset({"eth0"})), IfaceMatch(frozenset({"eth*"})), True),
            (IfaceMatch(frozenset({"eth*"})), IfaceMatch(frozenset({"eth0"})), False),
            (IfaceMatch(frozenset({"eth0"})), IfaceMatch(frozenset({"lo"}), True), True),
            (IfaceMatch(frozenset({"lo"})), IfaceMatch(frozenset({"l*"}), True), False),
            (IfaceMatch(frozenset({"lo", "eth*"}), True), IfaceMatch(frozenset({"lo"}), True), True),
            (IfaceMatch(frozenset({"lo"}), True), IfaceMatch(frozenset({"eth0"})), False),
        ],
    )
    def test_issubset(self, inner, outer, expected):
        assert inner.issubset(outer) is expected

    def test_matches_name(self):
        assert IfaceMatch(frozenset({"wg*"})).matches_name("wg0")
        assert not IfaceMatch(frozenset({"lo"}), True).matches_name("lo")
        assert IfaceMatch(frozenset({"lo"})).only_loopback()


class TestValues:
    def test_address_span_forms(self):
        assert address_span(SADDR4, "10.0.0.0/8") == (0x0A000000, 0x0AFFFFFF)
        assert address_span(SADDR4, "10.0.0.1-10.0.0.3") == (0x0A000001, 0x0A000003)
        with pytest.raises(Unsupported):
            address_span(SADDR4, "2001:db8::1")
        with pytest.raises(Unsupported):
            address_span(SADDR4, "not-an-ip")

    def test_ports(self):
        assert port_number("443") == 443
        with pytest.raises(Unsupported):
            port_number(70000)

    def test_formatting(self):
        s = span(SADDR4, *address_span(SADDR4, "10.0.0.0/8"))
        assert format_addresses(s, 4) == "10.0.0.0/8"
        assert format_addresses(s.complement(), 4) == "any except 10.0.0.0/8"
        assert format_ports(IntervalSet(0, 65535, [(22, 22), (8000, 8080)])) == "22,8000-8080"


class TestSs:
    def test_netid_format(self, fixture_text):
        ls = parse_ss(fixture_text("ss.txt"))
        by = {(x.proto, x.port, x.raw_address): x for x in ls}
        sshd4 = by[("tcp", 22, "0.0.0.0")]
        assert sshd4.address is None and sshd4.families == [0] and sshd4.process == "sshd"
        assert by[("tcp", 22, "[::]")].families == [1]
        assert by[("tcp", 443, "*")].families == [0, 1]
        assert by[("tcp", 3306, "127.0.0.1")].loopback
        assert by[("udp", 53, "127.0.0.53%lo")].loopback
        hap = by[("tcp", 8443, "192.0.2.50%eth0")]
        assert hap.scope == "eth0" and hap.daddr(0) == 0xC0000232 and not hap.loopback

    def test_headerless_without_netid(self):
        text = (
            'LISTEN 0 128 [::ffff:192.0.2.1]:8080 [::]:* users:(("java",pid=7,fd=9))\n'
            "UNCONN 0 0 [::1]:323 [::]:*\n"
            "ESTAB 0 0 10.0.0.1:22 10.0.0.2:5555\n"
        )
        ls = parse_ss(text)
        assert len(ls) == 2
        assert ls[0].proto == "tcp" and ls[0].families == [0] and ls[0].daddr(0) == 0xC0000201
        assert ls[1].proto == "udp" and ls[1].loopback

    def test_garbage(self):
        with pytest.raises(SsParseError):
            parse_ss("tcp LISTEN\n")
