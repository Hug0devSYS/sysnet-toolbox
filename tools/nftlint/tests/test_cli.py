"""End-to-end CLI behaviour (live commands are mocked)."""

import io
import json

import pytest

from nftlint import __version__
from nftlint.cli import InputError, detect_format, main, parse_ports


def run(argv, capsys, runner=None):
    kwargs = {"runner": runner} if runner else {}
    code = main(argv, **kwargs)
    out, err = capsys.readouterr()
    return code, out, err


def test_text_report_and_exit_code(fixture_path, capsys):
    code, out, _ = run([fixture_path("server.json"), "--ss", fixture_path("ss.txt")], capsys)
    assert code == 2
    assert "NFT001 shadowed-rule" in out and "Exposure of listening sockets" in out
    assert "CRITICAL (exit 2)" in out


def test_clean_ruleset_exits_zero(fixture_path, capsys):
    code, out, _ = run([fixture_path("clean.json")], capsys)
    assert code == 0 and "OK (exit 0)" in out


def test_json_output(fixture_path, capsys):
    code, out, _ = run([fixture_path("iptables.txt"), "--ss", fixture_path("ss.txt"), "--json"], capsys)
    doc = json.loads(out)
    assert doc["version"] == __version__ and doc["exit_code"] == code == 2
    assert doc["sources"][0]["format"] == "iptables-save"
    assert {f["code"] for f in doc["findings"]} >= {"NFT001", "NFT008"}
    shadow = next(f for f in doc["findings"] if f["code"] == "NFT001")
    assert shadow["rule"]["line"] == 21 and shadow["related_rule"]["text"].endswith("-j ACCEPT")
    ssh = next(e for e in doc["exposure"] if e["port"] == 22 and e["address"] == "0.0.0.0")
    assert ssh["status"] == "restricted" and ssh["families"][0]["allowed_sources"] == "10.0.0.0/8"


def test_ignore_and_min_severity(fixture_path, capsys):
    argv = [fixture_path("server.json"), "--json"]
    code, out, _ = run([*argv, "--min-severity", "high"], capsys)
    doc = json.loads(out)
    assert {f["severity"] for f in doc["findings"]} == {"high"}
    code, out, _ = run([*argv, "--ignore", "NFT001,nft005", "--ignore", "NFT006"], capsys)
    doc = json.loads(out)
    assert not {"NFT001", "NFT005", "NFT006"} & {f["code"] for f in doc["findings"]}
    assert code == 1


def test_ip6tables_option_and_stdin(fixture_path, fixture_text, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(fixture_text("iptables.txt")))
    code, out, _ = run(["-", "-6", fixture_path("ip6tables.txt"), "--json"], capsys)
    doc = json.loads(out)
    assert [s["format"] for s in doc["sources"]] == ["iptables-save", "ip6tables-save"]


def test_sensitive_ports_override(fixture_path, capsys):
    code, out, _ = run([fixture_path("server.json"), "--json", "--sensitive-ports", "9999"], capsys)
    assert not [f for f in json.loads(out)["findings"] if f["code"] == "NFT007"]
    assert parse_ports("22,6000-6002/x11") == {22: "ssh", 6000: "x11", 6001: "x11", 6002: "x11"}


@pytest.mark.parametrize(
    "argv_suffix,needle",
    [
        ([], "no ruleset given"),
        (["/nonexistent/file.json"], "No such file"),
    ],
)
def test_usage_errors(argv_suffix, needle, capsys):
    code, _, err = run(argv_suffix, capsys)
    assert code == 3 and needle in err


def test_nft_text_syntax_is_rejected(tmp_path, capsys):
    p = tmp_path / "rules.nft"
    p.write_text("table inet filter {\n}\n")
    code, out, _ = run([str(p), "--json"], capsys)
    assert code == 3 and "nft -j list ruleset" in json.loads(out)["error"]


def test_detect_format():
    assert detect_format('  {"nftables": []}') == "nft-json"
    assert detect_format("# c\n*filter\n") == "iptables-save"
    with pytest.raises(InputError):
        detect_format("hello")


class FakeRunner:
    def __init__(self, outputs):
        self.outputs = outputs
        self.calls = []

    def __call__(self, cmd, timeout):
        self.calls.append((cmd[0], timeout))
        out = self.outputs.get(cmd[0])
        if isinstance(out, Exception):
            raise out
        if out is None:
            raise InputError(f"{cmd[0]}: command not found")
        return out


def test_live_nft(fixture_text, capsys):
    runner = FakeRunner({"nft": fixture_text("server.json"), "ss": fixture_text("ss.txt")})
    code, out, _ = run(["--live", "--json", "--timeout", "3"], capsys, runner)
    doc = json.loads(out)
    assert code == 2 and doc["sources"][0]["path"] == "live:nft" and doc["exposure"]
    assert runner.calls == [("nft", 3.0), ("ss", 3.0)]


def test_live_falls_back_to_iptables_and_tolerates_missing_ss(fixture_text, capsys):
    runner = FakeRunner(
        {
            "nft": InputError("nft -j list ruleset failed: Operation not permitted"),
            "iptables-save": fixture_text("iptables.txt"),
            "ip6tables-save": fixture_text("ip6tables.txt"),
        }
    )
    code, out, _ = run(["--live", "--json"], capsys, runner)
    doc = json.loads(out)
    assert [s["path"] for s in doc["sources"]] == ["live:iptables-save", "live:ip6tables-save"]
    assert "exposure" not in doc
    assert any("exposure analysis skipped" in f["message"] for f in doc["findings"])


def test_live_reports_original_nft_error(capsys):
    runner = FakeRunner({"nft": InputError("nft -j list ruleset failed: denied")})
    code, _, err = run(["--live"], capsys, runner)
    assert code == 3 and "denied" in err


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0 and __version__ in capsys.readouterr().out
