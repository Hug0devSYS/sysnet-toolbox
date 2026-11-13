import sys

import pytest

from sysnet_presence import cli
from sysnet_presence.ipc import Client, IPCError, candidate_paths

CID = "123456789012345678"


def factory(server):
    return lambda cid, timeout: Client(cid, timeout=0.5, paths=["/nonexistent/discord-ipc-0", server.path])


def test_candidate_paths():
    linux = candidate_paths({"XDG_RUNTIME_DIR": "/run/user/1000"}, "linux")
    assert linux[0] == "/run/user/1000/discord-ipc-0"
    assert "/run/user/1000/app/com.discordapp.Discord/discord-ipc-0" in linux
    assert "/run/user/1000/snap.discord/discord-ipc-0" in linux
    assert "/tmp/discord-ipc-9" in linux
    assert candidate_paths({}, "win32")[0] == r"\\.\pipe\discord-ipc-0"


def test_handshake_and_activity(discord):
    srv = discord()
    c = Client(CID, timeout=1, paths=[srv.path])
    c.connect()
    assert c.user["username"] == "hugo" and c.endpoint == srv.path
    assert c.set_activity({"details": "x1"}, pid=42) == {"details": "x1"}
    c.clear()
    c.close()
    srv.closed.wait(2)
    ops = [op for op, _ in srv.frames]
    assert ops[0] == 0 and srv.frames[0][1] == {"v": 1, "client_id": CID}
    assert srv.frames[1][1]["args"]["pid"] == 42
    assert srv.activities() == [{"details": "x1"}, None]
    assert ops[-1] == 2
    assert (4, {"x": 1}) in srv.frames  # ping answered with pong


@pytest.mark.parametrize(
    "mode,msg",
    [("refuse", "Invalid Client ID"), ("silent", "no answer"), ("huge", "oversized")],
)
def test_handshake_failures(discord, mode, msg):
    srv = discord(mode)
    c = Client(CID, timeout=0.3, paths=[srv.path])
    with pytest.raises(IPCError, match=msg):
        c.connect()


def test_rejected_activity_and_errors(discord):
    srv = discord("reject")
    c = Client(CID, timeout=1, paths=[srv.path])
    c.connect()
    with pytest.raises(IPCError, match="rejected"):
        c.set_activity({"details": "x1"})
    c.close()
    with pytest.raises(IPCError, match="not found"):
        Client(CID, paths=["/nonexistent/discord-ipc-0"]).connect()
    with pytest.raises(IPCError, match="invalid Discord application ID"):
        Client("abc")


def test_wrapped_command_exit_code_and_privacy(discord, capsys):
    srv = discord()
    secret_arg = "core-rtr-01.corp.example"
    code = cli.main(
        ["--client-id", CID, "--", sys.executable, "-c", "import sys; sys.exit(3)", secret_arg],
        client_factory=factory(srv),
    )
    assert code == 3
    srv.closed.wait(2)
    first, last = srv.activities()
    assert last is None  # presence cleared at the end
    assert first["details"] == "Running python3" or first["details"].startswith("Running python")
    assert first["assets"] == {"large_image": "logo", "large_text": "sysnet-toolbox"}
    assert first["buttons"][0]["url"] == cli.REPO_URL
    assert "start" in first["timestamps"]
    assert secret_arg not in str(srv.frames)


def test_known_tool_state():
    args = cli.build_parser().parse_args(["--no-timer", "--no-button", "--small-image", "tool", "--", "x"])
    act = cli.build_activity(args, "netcfg-diff", 1.0)
    assert act == {
        "details": "Running netcfg-diff",
        "state": "Network configuration diff",
        "assets": {
            "large_image": "logo",
            "large_text": "sysnet-toolbox",
            "small_image": "tool",
            "small_text": "netcfg-diff",
        },
    }
    args = cli.build_parser().parse_args(["--details", "a", "--state", "y" * 300, "--", "x"])
    act = cli.build_activity(args, "other", 1.0)
    assert act["details"] == "a " and len(act["state"]) == 128 and act["state"].endswith("\u2026")


def test_command_runs_without_discord(capsys, monkeypatch):
    monkeypatch.delenv(cli.ENV_CLIENT_ID, raising=False)
    assert cli.main(["--", sys.executable, "-c", "print('hi')"]) == 0
    assert cli.main(["-v", "--", sys.executable, "-c", "pass"]) == 0
    assert "no Discord application ID" in capsys.readouterr().err
    gone = lambda cid, t: Client(cid, timeout=0.2, paths=["/nonexistent/discord-ipc-0"])  # noqa: E731
    assert cli.main(["--client-id", CID, "-v", "--", sys.executable, "-c", "pass"], client_factory=gone) == 0
    assert "Discord desktop client not found" in capsys.readouterr().err
    assert cli.main(["--", "/nonexistent/tool"]) == 127


def test_signal_exit_code():
    code = cli.main(["--", sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"])
    assert code == 128 + 15


def test_check_and_hold(discord, capsys, monkeypatch):
    srv = discord()
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    assert cli.main(["--check", "--client-id", CID], client_factory=factory(srv)) == 0
    assert "Connected to Discord as hugo" in capsys.readouterr().out
    srv2 = discord()
    clock = iter(range(0, 1000, 30))
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(clock))
    assert cli.main(["--hold", "--duration", "2m", "--client-id", CID], client_factory=factory(srv2)) == 0
    srv2.closed.wait(2)
    assert srv2.activities()[0]["details"] == "Working with sysnet-toolbox"
    gone = lambda cid, t: Client(cid, timeout=0.2, paths=["/nonexistent/x"])  # noqa: E731
    assert cli.main(["--check", "--client-id", CID], client_factory=gone) == 1


def test_usage_errors(capsys):
    assert cli.main([]) == 2
    assert cli.main(["--check", "--", "ls"]) == 2
    assert cli.main(["--duration", "5m", "--", "ls"]) == 2
    assert cli.main(["--check", "--client-id", ""]) == 2
    with pytest.raises(SystemExit):
        cli.main(["--hold", "--duration", "soon"])
    assert (
        cli.parse_duration("90s") == 90 and cli.parse_duration("2h") == 7200 and cli.parse_duration("5") == 5
    )


@pytest.mark.parametrize(
    "command,name",
    [
        (["nftlint", "rules.json"], "nftlint"),
        (["/usr/local/bin/dnsdoctor", "example.com"], "dnsdoctor"),
        (["C:\\Tools\\tlsaudit.exe", "host"], "tlsaudit"),
        (["sudo", "-E", "nftlint", "--live"], "nftlint"),
        (["sudo", "-u", "netops", "lldp-mapper", "core1"], "lldp-mapper"),
        (["sudo", "-n", "nftlint"], "nftlint"),
        (["env", "-i", "SNMP_COMMUNITY=x", "lldp-mapper"], "lldp-mapper"),
        (["timeout", "-s", "KILL", "30", "pmtud-probe", "h"], "pmtud-probe"),
        (["nice", "-n", "10", "ionice", "-c", "3", "syslog-triage", "f"], "syslog-triage"),
        (["python3", "-m", "nftlint.cli", "x"], "nftlint"),
        (["python3.12", "-I", "customer-backup.py"], "python3.12"),
        (["python3", "-c", "import nftlint", "nftlint"], "python3"),
        (["python3", "-m", "http.server"], "python3"),
        (["python3", "-m", "lldp_mapper", "core1"], "lldp-mapper"),
        (["uv", "run", "netcfg-diff", "a", "b"], "netcfg-diff"),
        (["pipx", "run", "--spec", "x", "nftlint"], "nftlint"),
        (["go", "run", "./tools/subnet-planner/", "info"], "subnet-planner"),
        (["go", "run", "."], "go"),
        (["sudo"], "sudo"),
        (["sudo", "-u"], "sudo"),
        (["./weird name;rm"], "command"),
        ([], "sysnet-toolbox"),
    ],
)
def test_tool_name(command, name):
    assert cli.tool_name(command) == name


def test_every_tool_has_a_description():
    """The presence describes every tool of the repository."""
    tools_dir = __import__("pathlib").Path(__file__).resolve().parents[2]
    names = {p.name for p in tools_dir.iterdir() if p.is_dir() and p.name != "discord-presence"}
    if not names:
        pytest.skip("not running from a repository checkout")
    assert names <= set(cli.TOOLS), sorted(names - set(cli.TOOLS))


@pytest.mark.parametrize("value", ["inf", "nan", "-5m", "0", "1e400s"])
def test_duration_must_be_finite(value):
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        cli.parse_duration(value)


def test_timeout_must_be_finite(capsys):
    assert cli.main(["--timeout", "nan", "--", "ls"]) == 2
    assert cli.main(["--timeout", "inf", "--", "ls"]) == 2


def test_hold_deadline_passes_before_sleep(discord, monkeypatch):
    """The deadline can pass between the loop test and the sleep: a negative
    sleep used to raise ValueError."""
    srv = discord()
    clock = iter([0.0, 59.0, 61.0, 61.0, 61.0, 61.0])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(clock))
    slept = []
    monkeypatch.setattr(cli.time, "sleep", slept.append)
    assert cli.main(["--hold", "--duration", "60s", "--client-id", CID], client_factory=factory(srv)) == 0
    assert slept == [0.0]


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX signals")
def test_sigterm_is_forwarded(tmp_path):
    """SIGTERM sent to the wrapper reaches the wrapped command."""
    import os
    import signal
    import threading

    marker = tmp_path / "got-term"
    child = (
        "import signal, sys, time, pathlib\n"
        f"p = pathlib.Path({str(marker)!r})\n"
        "signal.signal(signal.SIGTERM, lambda *a: (p.write_text('x'), sys.exit(7)))\n"
        "p.with_suffix('.ready').write_text('r')\n"
        "time.sleep(10)\n"
    )

    def killer():
        ready = marker.with_suffix(".ready")
        for _ in range(500):
            if ready.exists():
                break
            threading.Event().wait(0.01)
        os.kill(os.getpid(), signal.SIGTERM)

    before = signal.getsignal(signal.SIGTERM)
    t = threading.Thread(target=killer)
    t.start()
    code = cli.main(["--", sys.executable, "-c", child])
    t.join()
    assert code == 7 and marker.exists()
    assert signal.getsignal(signal.SIGTERM) == before  # handler restored
