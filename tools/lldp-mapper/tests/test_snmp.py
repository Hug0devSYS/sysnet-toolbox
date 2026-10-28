import os
import time

import pytest
from conftest import FIXTURES
from lab import FakeAgent, reference_lab

from lldp_mapper import ber
from lldp_mapper.ber import Value
from lldp_mapper.snmp import (
    FileWalker,
    NativeWalker,
    NetSnmpConfig,
    NetSnmpWalker,
    SnmpError,
    SnmpTimeout,
    V3Credentials,
    dump_walk,
    parse_walk,
)

IFTABLE = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)


@pytest.fixture
def lab_data():
    return reference_lab()[0].sorted()


def expected(data, root):
    return [vb for vb in data if len(vb[0]) > len(root) and vb[0][: len(root)] == root]


@pytest.mark.parametrize("version,reps", [("2c", 25), ("2c", 3), ("1", 25)])
def test_native_walk_matches_data(lab_data, version, reps):
    agent = FakeAgent(lab_data)
    try:
        w = NativeWalker("127.0.0.1", b"s3cret", version=version, port=agent.port, max_repetitions=reps)
        for root in (IFTABLE, (1, 0, 8802, 1, 1, 2, 1), (1, 3, 6, 1, 2, 1, 1, 5), (1, 3, 6, 1, 99)):
            assert w.walk(root) == expected(lab_data, root)
        w.close()
    finally:
        agent.close()


def test_walk_to_end_of_mib(lab_data):
    agent = FakeAgent(lab_data)
    try:
        w = NativeWalker("127.0.0.1", b"s3cret", port=agent.port)
        last_root = (1, 3, 6, 1, 4, 1, 9)
        assert w.walk(last_root) == expected(lab_data, last_root)
    finally:
        agent.close()


def test_retry_after_lost_datagrams(lab_data):
    agent = FakeAgent(lab_data, drop_first=2)
    try:
        w = NativeWalker("127.0.0.1", b"s3cret", port=agent.port, timeout=0.2, retries=2)
        assert w.walk(IFTABLE) == expected(lab_data, IFTABLE)
        assert w.requests >= 3
    finally:
        agent.close()


def test_too_big_halves_max_repetitions(lab_data):
    agent = FakeAgent(lab_data, too_big_over=4)
    try:
        w = NativeWalker("127.0.0.1", b"s3cret", port=agent.port, max_repetitions=20)
        assert w.walk(IFTABLE) == expected(lab_data, IFTABLE)
        assert agent.max_reps_seen[:3] == [20, 10, 5] and agent.max_reps_seen[3] <= 4
    finally:
        agent.close()


def test_wrong_community_times_out(lab_data):
    agent = FakeAgent(lab_data)
    try:
        w = NativeWalker("127.0.0.1", b"nope", port=agent.port, timeout=0.15, retries=1)
        t0 = time.monotonic()
        with pytest.raises(SnmpTimeout, match="no response after 2 attempt"):
            w.walk(IFTABLE)
        assert time.monotonic() - t0 < 1.5
    finally:
        agent.close()


def test_device_deadline_is_enforced(lab_data):
    agent = FakeAgent(lab_data, community=b"other")
    try:
        w = NativeWalker("127.0.0.1", b"s3cret", port=agent.port, timeout=5, retries=5, deadline=time.monotonic() + 0.3)
        t0 = time.monotonic()
        with pytest.raises(SnmpTimeout):
            w.walk(IFTABLE)
        assert time.monotonic() - t0 < 1.0
    finally:
        agent.close()


def test_non_increasing_oid_is_detected(lab_data):
    def loop(out):
        return [(IFTABLE + (1,), out[0][1])]

    agent = FakeAgent(lab_data, mutate=loop)
    try:
        w = NativeWalker("127.0.0.1", b"s3cret", port=agent.port)
        with pytest.raises(SnmpError, match="non-increasing"):
            w.walk(IFTABLE)
    finally:
        agent.close()


def test_port_unreachable_fails_fast():
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    w = NativeWalker("127.0.0.1", b"x", port=port, timeout=2, retries=3)
    t0 = time.monotonic()
    with pytest.raises(SnmpError, match="port unreachable"):
        w.walk(IFTABLE)
    assert time.monotonic() - t0 < 1.0


def test_unresolvable_host():
    with pytest.raises(SnmpError, match="cannot resolve"):
        NativeWalker("no-such-host.invalid", b"x").walk(IFTABLE)


def test_native_rejects_v3():
    with pytest.raises(ValueError):
        NativeWalker("h", b"x", version="3")


# --------------------------------------------------------------------------- walk files


def test_dump_parse_roundtrip(lab_data):
    data = lab_data + [
        ((1, 3, 6, 1, 9, 1), Value(ber.TIMETICKS, 123)),
        ((1, 3, 6, 1, 9, 2), Value(ber.COUNTER64, 2**40)),
        ((1, 3, 6, 1, 9, 3), Value(ber.OCTET_STRING, b"")),
    ]
    data.sort(key=lambda vb: vb[0])
    assert parse_walk(dump_walk(data)) == data


def test_parse_typed_fixture():
    vbs = dict(FileWalker.from_file(os.path.join(FIXTURES, "c9300-typed.walk")).varbinds)
    descr = vbs[(1, 3, 6, 1, 2, 1, 1, 1, 0)].value
    assert descr.startswith(b"Cisco IOS") and descr.count(b"\n") == 2 and descr.endswith(b"Inc.")
    assert vbs[(1, 3, 6, 1, 2, 1, 10, 7, 2, 1, 19, 9)] == Value(ber.INTEGER, 2)
    assert vbs[(1, 0, 8802, 1, 1, 2, 1, 3, 2, 0)].value == bytes.fromhex("700f6a112233")
    assert vbs[(1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 11, 0, 1, 1)].value == b"\x28\x00"
    assert vbs[(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18, 9)].value == b""
    assert (1, 0, 8802, 1, 1, 2, 1, 5, 32962, 1, 2, 1, 1, 1, 1) not in vbs  # "No Such Object" skipped
    assert vbs[(1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 10, 20, 0, 11)].value == bytes([10, 20, 0, 11])


@pytest.mark.parametrize(
    "line,value",
    [
        ('.1.3.6.1 = STRING: "a \\"quoted\\" word"', b'a "quoted" word'),
        (".1.3.6.1 = INTEGER: -5", -5),
        (".1.3.6.1 = Gauge32: 1000 Mbps", 1000),
        (".1.3.6.1 = Timeticks: (8642) 0:01:26.42", 8642),
        (".1.3.6.1 = Hex-STRING: 00 1A 2B", b"\x00\x1a\x2b"),
        ("iso.3.6.1 = INTEGER: 7", 7),
        (".1.3.6.1 = OID: .1.3.6.1.4.1.9", (1, 3, 6, 1, 4, 1, 9)),
        (".1.3.6.1 = Counter32: 42", 42),
    ],
)
def test_parse_value_variants(line, value):
    assert parse_walk(line)[0][1].value == value


def test_parse_walk_rejects_symbolic_oids():
    with pytest.raises(ber.BerError, match="-On"):
        parse_walk('IF-MIB::ifName.1 = STRING: "Gi1/0/1"')
    with pytest.raises(ber.BerError, match="not walk data"):
        parse_walk("Timeout: No Response from 10.0.0.1")


def test_multiline_hex_string():
    text = ".1.3.6.1 = Hex-STRING: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n10 11\n.1.3.6.2 = INTEGER: 1\n"
    vbs = parse_walk(text)
    assert vbs[0][1].value == bytes(range(18))


def test_file_walker_subtrees(lab_data):
    fw = FileWalker("x", list(lab_data))
    assert fw.walk(IFTABLE) == expected(lab_data, IFTABLE)
    assert fw.walk((1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)) == []  # a leaf is not its own subtree


# --------------------------------------------------------------------------- net-snmp back-end


class FakeRunner:
    def __init__(self, rc=0, out="", err=""):
        self.rc, self.out, self.err = rc, out, err
        self.calls = []

    def __call__(self, cmd, env, timeout):
        self.calls.append((cmd, env, timeout))
        with open(os.path.join(env["SNMPCONFPATH"], "snmp.conf")) as fh:
            self.conf = fh.read()
        return self.rc, self.out, self.err


def test_netsnmp_v3_credentials_stay_off_argv(tmp_path):
    creds = V3Credentials("nms", "SHA-256", 'pa ss"word\\x', "AES", "privpass99")
    conf = NetSnmpConfig("3", None, creds)
    runner = FakeRunner(out=".1.3.6.1.2.1.1.5.0 = Hex-STRING: 73 77 31\n")
    try:
        w = NetSnmpWalker("2001:db8::1", conf, version="3", runner=runner, max_repetitions=10)
        w._binary = lambda: "/usr/bin/snmpbulkwalk"
        assert w.walk((1, 3, 6, 1, 2, 1, 1, 5)) == [((1, 3, 6, 1, 2, 1, 1, 5, 0), Value(ber.OCTET_STRING, b"sw1"))]
        cmd, env, _ = runner.calls[0]
        joined = " ".join(cmd)
        assert "privpass99" not in joined and "pa ss" not in joined and "nms" not in joined
        assert "-Cr10" in cmd and "udp6:[2001:db8::1]:161" in cmd and "-On" in cmd
        assert 'defAuthPassphrase "pa ss\\"word\\\\x"' in runner.conf
        assert "defSecurityLevel authPriv" in runner.conf
        assert oct(os.stat(os.path.join(conf.dir, "snmp.conf")).st_mode & 0o777) == "0o600"
    finally:
        conf.cleanup()
    assert not os.path.exists(conf.dir)


def test_netsnmp_errors_are_mapped():
    conf = NetSnmpConfig("2c", b"c0mm", None)
    try:
        w = NetSnmpWalker(
            "10.0.0.1", conf, version="2c", runner=FakeRunner(1, "", "Timeout: No Response from 10.0.0.1")
        )
        w._binary = lambda: "snmpbulkwalk"
        with pytest.raises(SnmpTimeout):
            w.walk(IFTABLE)
        w = NetSnmpWalker("10.0.0.1", conf, version="2c", runner=FakeRunner(1, "", "Unknown user name"))
        w._binary = lambda: "snmpbulkwalk"
        with pytest.raises(SnmpError, match="Unknown user name"):
            w.walk(IFTABLE)
    finally:
        conf.cleanup()


def test_netsnmp_conf_rejects_newlines():
    with pytest.raises(SnmpError):
        NetSnmpConfig("2c", b"bad\ncommunity", None)
