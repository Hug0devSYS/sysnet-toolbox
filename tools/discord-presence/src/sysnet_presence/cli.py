"""Command-line interface."""

from __future__ import annotations

import argparse
import contextlib
import os
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import __version__
from .ipc import Client, IPCError

REPO_URL = "https://github.com/Hug0devSYS/sysnet-toolbox"
ENV_CLIENT_ID = "SYSNET_DISCORD_CLIENT_ID"
EXIT_OK, EXIT_UNAVAILABLE, EXIT_USAGE = 0, 1, 2

# What the presence says for each toolbox tool (never the arguments).
TOOLS = {
    "dnsdoctor": "DNS zone diagnostics",
    "tlsaudit": "TLS fleet audit",
    "nftlint": "Firewall ruleset analysis",
    "netcfg-diff": "Network configuration diff",
}

DESCRIPTION = """\
Show the sysnet-toolbox tool you are running as Discord Rich Presence
("Playing sysnet-toolbox - Running netcfg-diff"), with the toolbox logo.

It talks to the Discord desktop client running on this computer through its
local IPC socket; nothing is sent anywhere else. Only the tool name is shown,
never its arguments (file names, host names, zones). If Discord is not
running, the command runs normally and nothing is displayed.
"""

EPILOG = f"""\
setup (once): create an application named "sysnet-toolbox" on
https://discord.com/developers/applications, upload assets/logo-1024.png as a
Rich Presence art asset named "logo", and export its Application ID:
  export {ENV_CLIENT_ID}=123456789012345678

examples:
  sysnet-presence -- netcfg-diff old.cfg new.cfg
  sysnet-presence -- dnsdoctor example.com
  sysnet-presence --hold --details "Auditing the DMZ firewalls" --duration 2h
  sysnet-presence --check
  alias netcfg-diff='sysnet-presence -- netcfg-diff'

exit codes: wrapped command's exit code (127 if not found); otherwise
            0 ok, 1 Discord unreachable or refused, 2 usage error
"""


def _field(text: str) -> str:
    """Discord requires 2-128 characters in text fields."""
    text = " ".join(text.split())
    if len(text) > 128:
        text = text[:127] + "…"
    return text if len(text) >= 2 else (text + "  ")[:2]


def parse_duration(value: str) -> float:
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    v = value.strip().lower()
    try:
        secs = float(v[:-1]) * units[v[-1]] if v and v[-1] in units else float(v)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid duration {value!r} (e.g. 90s, 30m, 2h)") from None
    if secs <= 0:
        raise argparse.ArgumentTypeError("duration must be positive")
    return secs


def build_activity(args: argparse.Namespace, tool: Optional[str], start: Optional[float]) -> Dict[str, Any]:
    details = args.details or (f"Running {tool}" if tool else "Working with sysnet-toolbox")
    state = args.state or (TOOLS.get(tool or "", "sysnet-toolbox") if tool else "Systems & network tooling")
    activity: Dict[str, Any] = {"details": _field(details), "state": _field(state)}
    assets: Dict[str, str] = {}
    if args.image:
        assets["large_image"] = args.image
        assets["large_text"] = _field(args.image_text)
    if args.small_image:
        assets["small_image"] = args.small_image
        assets["small_text"] = _field(tool or "sysnet-toolbox")
    if assets:
        activity["assets"] = assets
    if start is not None and not args.no_timer:
        activity["timestamps"] = {"start": int(start)}
    if not args.no_button:
        activity["buttons"] = [{"label": "sysnet-toolbox on GitHub", "url": REPO_URL}]
    return activity


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sysnet-presence",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage="sysnet-presence [options] -- COMMAND [ARGS...]\n"
        "       sysnet-presence [options] --hold [--duration D]\n"
        "       sysnet-presence [options] --check",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--hold", action="store_true", help="show the presence until Ctrl-C (or --duration)")
    mode.add_argument("--check", action="store_true", help="test the connection to Discord and exit")
    p.add_argument(
        "--duration", type=parse_duration, metavar="D", help="with --hold: stop after D (90s, 30m, 2h)"
    )
    p.add_argument(
        "--client-id",
        default=os.environ.get(ENV_CLIENT_ID, ""),
        metavar="ID",
        help=f"Discord application ID (default: ${ENV_CLIENT_ID})",
    )
    p.add_argument("--details", metavar="TEXT", help="first line (default: 'Running <tool>')")
    p.add_argument("--state", metavar="TEXT", help="second line (default: what the tool does)")
    p.add_argument("--image", default="logo", metavar="KEY", help="large art asset key (default: logo)")
    p.add_argument(
        "--image-text", default="sysnet-toolbox", metavar="TEXT", help="tooltip of the large image"
    )
    p.add_argument("--small-image", metavar="KEY", help="optional small art asset key")
    p.add_argument("--no-timer", action="store_true", help="do not show the elapsed time")
    p.add_argument("--no-button", action="store_true", help="do not show the GitHub button")
    p.add_argument("--timeout", type=float, default=2.0, metavar="S", help="Discord IPC timeout (default 2s)")
    p.add_argument("-v", "--verbose", action="store_true", help="report presence problems on stderr")
    p.add_argument("--version", action="version", version=f"sysnet-presence {__version__}")
    p.add_argument("command", nargs=argparse.REMAINDER, help="command to run (after --)")
    return p


ClientFactory = Callable[[str, float], Client]


def main(argv: Optional[Sequence[str]] = None, client_factory: ClientFactory = Client) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command: List[str] = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not (args.hold or args.check or command):
        parser.print_usage(sys.stderr)
        print("sysnet-presence: give a command after --, or --hold / --check", file=sys.stderr)
        return EXIT_USAGE
    if command and (args.hold or args.check):
        print("sysnet-presence: --hold/--check do not take a command", file=sys.stderr)
        return EXIT_USAGE
    if args.duration and not args.hold:
        print("sysnet-presence: --duration requires --hold", file=sys.stderr)
        return EXIT_USAGE
    if args.timeout <= 0:
        print("sysnet-presence: --timeout must be positive", file=sys.stderr)
        return EXIT_USAGE

    if args.check:
        return run_check(args, client_factory)
    if args.hold:
        return run_hold(args, client_factory)
    return run_wrapped(args, command, client_factory)


def _warn(args: argparse.Namespace, msg: str) -> None:
    if args.verbose:
        print(f"sysnet-presence: {msg}", file=sys.stderr)


def _start_presence(
    args, client_factory: ClientFactory, tool: Optional[str], start: float
) -> Optional[Client]:
    if not args.client_id:
        _warn(args, f"no Discord application ID (set ${ENV_CLIENT_ID} or --client-id); presence disabled")
        return None
    try:
        client = client_factory(args.client_id, args.timeout)
        client.connect()
        client.set_activity(build_activity(args, tool, start))
        return client
    except IPCError as exc:
        _warn(args, f"{exc}; presence disabled")
        return None


def _stop_presence(client: Optional[Client]) -> None:
    if client is not None:
        client.clear()
        client.close()


def run_check(args, client_factory: ClientFactory) -> int:
    if not args.client_id:
        print(
            f"sysnet-presence: no Discord application ID (set ${ENV_CLIENT_ID} or --client-id)",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        client = client_factory(args.client_id, args.timeout)
        client.connect()
        client.set_activity(build_activity(args, None, time.time()))
    except IPCError as exc:
        print(f"sysnet-presence: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    user = client.user.get("username") or "unknown user"
    print(f"Connected to Discord as {user} via {client.endpoint}; presence shown for 5 seconds.")
    with contextlib.suppress(KeyboardInterrupt):
        time.sleep(5)
    _stop_presence(client)
    return EXIT_OK


def run_hold(args, client_factory: ClientFactory) -> int:
    args.verbose = True  # interactive: say why nothing shows up
    client = _start_presence(args, client_factory, None, time.time())
    if client is None:
        return EXIT_UNAVAILABLE
    print("Presence shown; press Ctrl-C to stop.", file=sys.stderr)
    deadline = time.monotonic() + args.duration if args.duration else None
    try:
        while deadline is None or time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()) if deadline else 1.0)
    except KeyboardInterrupt:
        pass
    _stop_presence(client)
    return EXIT_OK


def run_wrapped(args, command: List[str], client_factory: ClientFactory) -> int:
    tool = os.path.splitext(os.path.basename(command[0]))[0]
    start = time.time()
    try:
        # Start the command first: the presence must never delay or break it.
        proc = subprocess.Popen(command)
    except FileNotFoundError:
        print(f"sysnet-presence: {command[0]}: command not found", file=sys.stderr)
        return 127
    except PermissionError:
        print(f"sysnet-presence: {command[0]}: permission denied", file=sys.stderr)
        return 126
    client = _start_presence(args, client_factory, tool, start)
    try:
        while True:
            try:
                code = proc.wait()
                break
            except KeyboardInterrupt:
                continue  # the child received the SIGINT too; wait for it to exit
    finally:
        _stop_presence(client)
    if code < 0:  # killed by a signal: shell convention
        return 128 - code
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
