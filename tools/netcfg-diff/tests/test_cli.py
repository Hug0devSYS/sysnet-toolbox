import gzip
import json
import os
import shutil

import pytest
from conftest import fixture_path, read_fixture

from netcfg_diff.cli import main


def run(capsys, *args):
    code = main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


def test_exit_codes_and_text(capsys):
    code, out, _ = run(capsys, "--color", "never", fixture_path("ios_old.cfg"), fixture_path("ios_new.cfg"))
    assert code == 1
    assert out.startswith("--- ") and "9 change(s)" in out
    code, out, _ = run(capsys, fixture_path("ios_old.cfg"), fixture_path("ios_old.cfg"))
    assert code == 0 and "No semantic differences." in out
    code, out, _ = run(capsys, "-q", fixture_path("ios_old.cfg"), fixture_path("ios_new.cfg"))
    assert code == 1 and out == ""


def test_errors(capsys, tmp_path):
    code, _, err = run(capsys, fixture_path("ios_old.cfg"), str(tmp_path / "missing.cfg"))
    assert code == 2 and "missing.cfg" in err
    code, _, err = run(capsys, fixture_path("ios_old.cfg"), fixture_path("junos_old.conf"))
    assert code == 2 and "cannot compare" in err
    code, _, err = run(capsys, "--format", "set", fixture_path("ios_old.cfg"), fixture_path("ios_new.cfg"))
    assert code == 2 and "Junos" in err
    code, _, err = run(capsys, "--ignore", "(", fixture_path("ios_old.cfg"), fixture_path("ios_new.cfg"))
    assert code == 2 and "invalid regular expression" in err
    bad = tmp_path / "bad.conf"
    bad.write_text("system {\n host-name r1;\n")
    code, _, err = run(capsys, "--vendor", "junos", str(bad), fixture_path("junos_old.conf"))
    assert code == 2 and "bad.conf: line 2" in err
    binary = tmp_path / "bin.cfg"
    binary.write_bytes(b"\x00\x01\x02")
    code, _, err = run(capsys, str(binary), fixture_path("ios_old.cfg"))
    assert code == 2 and "binary" in err
    code, _, err = run(capsys, "-", "-")
    assert code == 2
    code, _, err = run(capsys, str(tmp_path), fixture_path("ios_old.cfg"))
    assert code == 2 and "both directories" in err


def test_json_output(capsys):
    code, out, _ = run(capsys, "--json", fixture_path("junos_old.conf"), fixture_path("junos_new.set"))
    doc = json.loads(out)
    assert code == 1 and doc["tool"] == "netcfg-diff" and not doc["identical"]
    assert doc["left"]["format"] == "brace" and doc["right"]["format"] == "set"
    assert doc["summary"]["total"] == len(doc["changes"]) == 9
    mv = [c for c in doc["changes"] if c["op"] == "move" and c["statement"] == "icmp"][0]
    assert mv["commands"] == ["insert firewall family inet filter PROTECT-RE term icmp before term ssh"]
    code, out, _ = run(capsys, "--json", fixture_path("ios_old.cfg"), fixture_path("ios_new.cfg"))
    doc = json.loads(out)
    vlan = [c for c in doc["changes"] if "allowed vlan" in c["statement"]][0]
    assert vlan["detail"] == {"added": [33], "added_ranges": "33"}
    added = [c for c in doc["changes"] if c["op"] == "add"][0]
    assert added["lines"] == [
        "interface Vlan40",
        "  description Guest",
        "  ip address 10.40.0.1 255.255.255.0",
    ]


def test_section_brief_summary(capsys):
    code, out, _ = run(
        capsys,
        "--section",
        "^interface ",
        "--brief",
        fixture_path("ios_old.cfg"),
        fixture_path("ios_new.cfg"),
    )
    assert code == 1
    assert "snmp-server" not in out and "line vty" not in out
    assert "+ interface Vlan40  # 2 sub-statement(s)" in out
    code, out, _ = run(
        capsys, "--format", "summary", fixture_path("fortios_old.conf"), fixture_path("fortios_new.conf")
    )
    assert "config firewall policy" in out and "7 change(s)" in out
    code, out, _ = run(
        capsys, "--section", "^nothing-matches$", fixture_path("ios_old.cfg"), fixture_path("ios_new.cfg")
    )
    assert code == 0


def test_set_format(capsys):
    code, out, _ = run(
        capsys, "--format", "set", fixture_path("junos_old.conf"), fixture_path("junos_new.set")
    )
    lines = out.splitlines()
    assert code == 1 and lines[0].startswith("delete ")
    assert "deactivate interfaces ge-0/0/2" in lines and "activate interfaces ge-0/0/1" in lines


def test_ignore_file_and_order(capsys, tmp_path):
    ign = tmp_path / "ignore.txt"
    ign.write_text("# volatile\n^snmp-server location\n^line vty\n")
    code, out, _ = run(
        capsys,
        "--ignore-file",
        str(ign),
        "--ignore-order",
        "--color",
        "never",
        fixture_path("ios_old.cfg"),
        fixture_path("ios_new.cfg"),
    )
    assert code == 1 and "snmp-server location" not in out and "moved" not in out and "6 change(s)" in out


def test_no_secret_leaks_in_any_format(capsys):
    leaks = ("$9$", "0822455D0A16", "s3cr3t", "$6$abc", "SH2xyz", "AbCdEf", "ZzYyXx")
    for a, b in (
        ("ios_old.cfg", "ios_new.cfg"),
        ("junos_old.conf", "junos_new.set"),
        ("fortios_old.conf", "fortios_new.conf"),
    ):
        for fmt in ("text", "json", "summary") + (("set",) if a.startswith("junos") else ()):
            _, out, _ = run(capsys, "--format", fmt, "--brief", fixture_path(a), fixture_path(b))
            for leak in leaks:
                assert leak not in out, (a, fmt, leak)
    _, out, _ = run(capsys, "--secrets", "show", fixture_path("ios_old.cfg"), fixture_path("ios_new.cfg"))
    assert "$9$cccccccccccccc$" in out


def test_stdin_and_gzip(capsys, tmp_path, monkeypatch):
    gz = tmp_path / "old.cfg.gz"
    with gzip.open(gz, "wb") as fh:
        fh.write(read_fixture("ios_old.cfg").encode())

    class FakeStdin:
        buffer = open(fixture_path("ios_new.cfg"), "rb")  # noqa: SIM115

    monkeypatch.setattr("sys.stdin", FakeStdin)
    code, out, _ = run(capsys, str(gz), "-")
    FakeStdin.buffer.close()
    assert code == 1 and "9 change(s)" in out


@pytest.fixture
def backup_dirs(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    (a / "site1").mkdir(parents=True)
    (b / "site1").mkdir(parents=True)
    shutil.copy(fixture_path("ios_old.cfg"), a / "site1" / "r1.cfg")
    shutil.copy(fixture_path("ios_new.cfg"), b / "site1" / "r1.cfg")
    shutil.copy(fixture_path("junos_old.conf"), a / "mx1.conf")
    shutil.copy(fixture_path("junos_old.conf"), b / "mx1.conf")
    shutil.copy(fixture_path("fortios_old.conf"), a / "gone.conf")
    shutil.copy(fixture_path("fortios_new.conf"), b / "new.conf")
    (a / ".git").mkdir()
    (a / ".git" / "HEAD").write_text("ref")
    return str(a), str(b)


def test_directory_mode(capsys, backup_dirs):
    a, b = backup_dirs
    code, out, _ = run(capsys, "--color", "never", a, b)
    assert code == 1
    assert "Only in" in out and "gone.conf" in out and "new.conf" in out
    assert "2 file(s) compared, 1 with differences, 2 unpaired, 0 error(s)" in out
    assert "HEAD" not in out
    code, out, _ = run(capsys, "--json", a, b)
    doc = json.loads(out)
    assert doc["summary"] == {
        "compared": 2,
        "different": 1,
        "only_left": 1,
        "only_right": 1,
        "errors": 0,
        "changes": 9,
    }
    os.remove(os.path.join(b, "new.conf"))
    os.remove(os.path.join(a, "gone.conf"))
    os.remove(os.path.join(b, "site1", "r1.cfg"))
    shutil.copy(fixture_path("ios_old.cfg"), os.path.join(b, "site1", "r1.cfg"))
    code, _, _ = run(capsys, a, b)
    assert code == 0


def test_directory_mode_reports_errors(capsys, backup_dirs):
    a, b = backup_dirs
    with open(os.path.join(b, "mx1.conf"), "w") as fh:
        fh.write("system {\n")
    code, _, err = run(capsys, a, b)
    assert code == 2 and "mx1.conf" in err


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "netcfg-diff 0.1.0" in capsys.readouterr().out
