import json
import os

import pytest
from lab import FakeAgent, reference_lab

from lldp_mapper.cli import main
from lldp_mapper.snmp import FileWalker, SnmpTimeout, dump_walk

IPS = {"10.0.0.1": 0, "10.0.0.2": 1, "10.0.0.3": 2}


@pytest.fixture
def walk_dir(tmp_path):
    for d in reference_lab():
        (tmp_path / f"{d.name}.walk").write_text(dump_walk(d.sorted()))
    return tmp_path


def lab_opener(seen):
    devs = reference_lab()

    def opener(target, deadline):
        seen.append(target)
        if target not in IPS:

            def dead(root):
                raise SnmpTimeout(f"{target}: no response")

            return dead, lambda: None, lambda: 1
        fw = FileWalker(target, devs[IPS[target]].sorted())
        return fw.walk, fw.close, lambda: fw.requests

    return opener


def run(capsys, argv, **kw):
    code = main(argv, **kw)
    out, err = capsys.readouterr()
    return code, out, err


def test_offline_text_report(capsys, walk_dir):
    code, out, _ = run(capsys, ["--from-walks", str(walk_dir)])
    assert code == 2
    assert "CRITICAL duplex-mismatch" in out and "3 device(s) polled" in out
    assert out.rstrip().endswith("(exit 2)")


def test_offline_json(capsys, walk_dir):
    code, out, _ = run(capsys, ["--from-walks", str(walk_dir), "--json"])
    doc = json.loads(out)
    assert code == 2 and doc["summary"]["exit_code"] == 2 and doc["summary"]["status"] == "CRITICAL"
    assert doc["summary"]["findings"] == {"critical": 1, "warning": 3, "unknown": 0, "info": 1}
    link = [lk for lk in doc["links"] if "duplex-mismatch" in lk["findings"]][0]
    sides = {link["a"]["facts"]["duplex"]["value"], link["b"]["facts"]["duplex"]["value"]}
    assert sides == {"full", "half"}


def test_ignore_and_min_severity_change_exit_code(capsys, walk_dir):
    code, _, _ = run(capsys, ["--from-walks", str(walk_dir), "--ignore", "duplex-mismatch"])
    assert code == 1
    code, out, _ = run(
        capsys,
        [
            "--from-walks",
            str(walk_dir),
            "--ignore",
            "duplex-mismatch,autoneg-mismatch",
            "--ignore",
            "native-vlan-mismatch",
            "--min-severity",
            "critical",
        ],
    )
    assert code == 0 and "Findings\n  none" in out


def test_graph_outputs(capsys, walk_dir, tmp_path):
    mmd, dot, js = tmp_path / "t.mmd", tmp_path / "t.dot", tmp_path / "t.json"
    code, _, _ = run(
        capsys,
        [
            "--from-walks",
            str(walk_dir),
            "--graph",
            str(mmd),
            "--graph",
            str(dot),
            "--graph",
            str(js),
            "--format",
            "mermaid",
        ],
    )
    assert code == 2
    m = mmd.read_text()
    assert m.startswith("graph LR") and "linkStyle" in m and 'n_sw1["sw1"]' in m
    d = dot.read_text()
    assert d.startswith("graph topology {") and 'color="#d62728"' in d and "style=dashed" in d
    assert json.loads(js.read_text())["tool"] == "lldp-mapper"


def test_crawl_follows_in_scope_neighbours(capsys, monkeypatch):
    monkeypatch.setenv("SNMP_COMMUNITY", "x")
    seen = []
    code, out, err = run(
        capsys, ["--crawl", "--scope", "10.0.0.0/24", "10.0.0.1", "--json", "--progress"], opener=lab_opener(seen)
    )
    doc = json.loads(out)
    assert sorted(seen) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]  # srv1 (10.0.9.10) is out of scope
    assert doc["summary"]["devices_polled"] == 3 and "depth 1" in err
    assert {d["depth"] for d in doc["devices"]} == {0, 1}


def test_crawl_depth_and_capability_filter(capsys):
    seen = []
    run(capsys, ["--crawl", "--scope", "10.0.0.0/8", "--max-depth", "0", "10.0.0.1"], opener=lab_opener(seen))
    assert seen == ["10.0.0.1"]
    seen = []
    run(
        capsys, ["--crawl", "--scope", "10.0.0.0/8", "--crawl-caps", "stationOnly", "10.0.0.1"], opener=lab_opener(seen)
    )
    assert seen == ["10.0.0.1", "10.0.9.10"]


def test_unreachable_seed_is_unknown(capsys):
    code, out, _ = run(capsys, ["192.0.2.1", "--json"], opener=lab_opener([]))
    doc = json.loads(out)
    assert code == 3 and doc["findings"][0]["code"] == "poll-failed"


def test_partial_failure_keeps_worst_status(capsys):
    code, out, _ = run(capsys, ["10.0.0.1", "192.0.2.1"], opener=lab_opener([]))
    assert code == 2 and "UNKNOWN  poll-failed" in out


@pytest.mark.parametrize(
    "argv,msg",
    [
        ([], "no target"),
        (["--crawl", "10.0.0.1"], "--scope"),
        (["--graph", "x.png", "10.0.0.1"], "unknown extension"),
        (["--scope", "10.0.0.300/24", "--crawl", "h"], "--scope"),
        (["--crawl-caps", "bridge,toaster", "h"], "unknown capability"),
        (["--timeout", "0", "h"], "--timeout"),
        (["h;rm"], "invalid target"),
        (["--from-walks", "/nonexistent"], "no such file"),
    ],
)
def test_usage_errors(capsys, argv, msg):
    code, _, err = run(capsys, argv, opener=lab_opener([]))
    assert code == 3 and msg in err


def test_missing_credentials(capsys, monkeypatch):
    monkeypatch.delenv("SNMP_COMMUNITY", raising=False)
    code, _, err = run(capsys, ["10.0.0.1"])
    assert code == 3 and "SNMP_COMMUNITY" in err
    code, _, err = run(capsys, ["-s", "3", "10.0.0.1"])
    assert code == 3 and "--user" in err
    monkeypatch.setenv("SNMP_AUTH_PASS", "short")
    code, _, err = run(capsys, ["-s", "3", "--user", "u", "--auth-proto", "SHA", "10.0.0.1"])
    assert code == 3 and "8 characters" in err
    code, _, err = run(capsys, ["-s", "3", "--user", "u", "--priv-proto", "AES", "10.0.0.1"])
    assert code == 3 and "requires --auth-proto" in err
    code, out, _ = run(capsys, ["-s", "3", "--backend", "native", "--user", "u", "10.0.0.1", "--json"])
    assert code == 3 and "SNMPv3" in json.loads(out)["error"]


def test_native_end_to_end_with_community_file(capsys, tmp_path):
    agent = FakeAgent(reference_lab()[0].sorted(), community=b"from-file")
    cf = tmp_path / "community"
    cf.write_text("from-file\n")
    os.chmod(cf, 0o644)
    try:
        save = tmp_path / "walks"
        code, out, err = run(
            capsys, ["--community-file", str(cf), "--port", str(agent.port), "127.0.0.1", "--save-walks", str(save)]
        )
    finally:
        agent.close()
    assert "readable by group/others" in err
    assert code == 2 and "sw1" in out
    # The saved walk reproduces the same analysis offline.
    code2, out2, _ = run(capsys, ["--from-walks", str(save)])
    assert code2 == code and out2.split("Findings")[1] == out.split("Findings")[1]


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0 and "lldp-mapper" in capsys.readouterr().out
