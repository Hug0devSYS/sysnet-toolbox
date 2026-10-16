"""Command-line interface."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
from typing import Callable, List, Optional, Sequence, Tuple

from . import __version__
from .analysis import run_static_checks
from .exposure import analyse_exposure, exposure_findings
from .iptables import looks_like_ipv6, parse_iptables_save
from .model import SEVERITIES, SEVERITY_RANK, Ruleset
from .nftjson import ParseError, parse_nft_json
from .report import exit_code, render_json, render_text
from .ss import SsParseError, parse_ss
from .values import DEFAULT_SENSITIVE_PORTS, Unsupported, port_number

EXIT_UNKNOWN = 3

Runner = Callable[[List[str], float], str]

DESCRIPTION = """\
Static analysis of nftables (`nft -j list ruleset`) and iptables-save /
ip6tables-save rulesets: shadowed, redundant and unreachable rules,
unreachable chains, any-any accepts, permissive default policies, sensitive
ports open to the world, missing IPv6 filtering; and, given `ss -tulnp`
output, which listening sockets are actually reachable and from where.

nftlint never modifies the firewall: it only reads files, or runs read-only
listing commands with --live.
"""

EPILOG = """\
examples:
  nft -j list ruleset > rules.json; ss -tulnp > ss.txt
  nftlint rules.json --ss ss.txt
  nftlint iptables-save.txt -6 ip6tables-save.txt --ss ss.txt --json
  sudo nftlint --live
  nftlint rules.json --min-severity medium --ignore NFT002

exit codes: 0 no finding >= medium, 1 medium finding(s), 2 high finding(s),
            3 input/usage error (Nagios/Icinga compatible)
"""


class InputError(Exception):
    pass


def default_runner(cmd: List[str], timeout: float) -> str:
    exe = shutil.which(cmd[0]) or next(
        (p for p in (f"/usr/sbin/{cmd[0]}", f"/sbin/{cmd[0]}") if os.access(p, os.X_OK)), None
    )
    if exe is None:
        raise InputError(f"{cmd[0]}: command not found")
    try:
        proc = subprocess.run(
            [exe, *cmd[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as exc:
        raise InputError(f"{' '.join(cmd)}: timed out after {timeout:g}s") from exc
    except OSError as exc:
        raise InputError(f"{' '.join(cmd)}: {exc}") from exc
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        hint = " (root or CAP_NET_ADMIN is required)" if "ermission" in " ".join(err) else ""
        raise InputError(f"{' '.join(cmd)} failed: {err[-1] if err else proc.returncode}{hint}")
    return proc.stdout


def read_input(path: str) -> str:
    try:
        if path == "-":
            return sys.stdin.read()
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise InputError(f"{path}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"{path}: not a text file ({exc})") from exc


def detect_format(text: str) -> str:
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return "nft-json"
    for line in stripped.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            return "iptables-save"
        if line.startswith(("table ", "flush ruleset", "define ", "include ")):
            raise InputError(
                "nftables text syntax is not supported: export the ruleset as JSON with `nft -j list ruleset`"
            )
        break
    raise InputError("unrecognised ruleset format (expected nft JSON or iptables-save output)")


def load_ruleset(text: str, source: str, fmt: str, force_v6: bool = False) -> Ruleset:
    if fmt == "auto":
        fmt = detect_format(text)
    if fmt == "nft-json":
        return parse_nft_json(text, source)
    family = "ip6" if force_v6 or "ip6" in os.path.basename(source) or looks_like_ipv6(text) else "ip"
    return parse_iptables_save(text, source, family)


def parse_ports(text: str) -> dict:
    out = {}
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        name = None
        if "/" in part:
            part, name = part.split("/", 1)
        try:
            if "-" in part:
                a, b = (port_number(x) for x in part.split("-", 1))
                for p in range(a, b + 1):
                    out[p] = name or str(p)
            else:
                p = port_number(part)
                out[p] = name or DEFAULT_SENSITIVE_PORTS.get(p, str(p))
        except Unsupported as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nftlint",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "rulesets",
        nargs="*",
        metavar="RULESET",
        help="nft JSON or iptables-save file ('-' for stdin); iptables files are treated as "
        "IPv6 when the name contains 'ip6' or the content has IPv6 addresses",
    )
    p.add_argument(
        "-6",
        "--ip6tables",
        action="append",
        default=[],
        metavar="FILE",
        help="ip6tables-save file (forces IPv6); repeatable",
    )
    p.add_argument(
        "-F",
        "--format",
        choices=("auto", "nft-json", "iptables-save"),
        default="auto",
        help="ruleset format of the positional files (default: auto)",
    )
    p.add_argument("--ss", metavar="FILE", help="output of `ss -tulnp` ('-' for stdin)")
    p.add_argument(
        "--live",
        action="store_true",
        help="read the running ruleset (`nft -j list ruleset`, falling back to iptables-save / "
        "ip6tables-save) and sockets (`ss -tulnpH`) when no file is given; read-only, "
        "needs root or CAP_NET_ADMIN for the ruleset",
    )
    p.add_argument("--timeout", type=float, default=15.0, help="timeout for --live commands (s)")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="info",
        help="hide findings below this severity (also ignored for the exit code)",
    )
    p.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="CODE",
        help="suppress a finding code (e.g. NFT002); repeatable or comma-separated",
    )
    p.add_argument(
        "--sensitive-ports",
        type=parse_ports,
        metavar="LIST",
        help="replace the built-in sensitive port list, e.g. '22,3389,5432/postgres,6000-6010'",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="show deciding rules in the exposure table")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def collect(args: argparse.Namespace, runner: Runner) -> Tuple[Ruleset, Optional[list]]:
    rs = Ruleset()
    loaded = False
    if args.ss == "-" and "-" in args.rulesets:
        raise InputError("stdin can only be used for one input")
    for path in args.rulesets:
        rs.merge(load_ruleset(read_input(path), path, args.format))
        loaded = True
    for path in args.ip6tables:
        rs.merge(load_ruleset(read_input(path), path, "iptables-save", force_v6=True))
        loaded = True
    if not loaded and args.live:
        try:
            rs.merge(parse_nft_json(runner(["nft", "-j", "list", "ruleset"], args.timeout), "live:nft"))
        except InputError as nft_err:
            try:
                v4 = runner(["iptables-save"], args.timeout)
            except InputError:
                raise nft_err from None
            rs.merge(parse_iptables_save(v4, "live:iptables-save", "ip"))
            with contextlib.suppress(InputError, ParseError):
                v6 = runner(["ip6tables-save"], args.timeout)
                rs.merge(parse_iptables_save(v6, "live:ip6tables-save", "ip6"))
        loaded = True
    if not loaded:
        raise InputError("no ruleset given (pass a file, '-' for stdin, or --live)")
    if rs.rule_count() == 0 and not rs.chains:
        raise InputError("the ruleset is empty: nothing to analyse")
    listeners = None
    if args.ss:
        listeners = parse_ss(read_input(args.ss), args.ss)
    elif args.live:
        try:
            listeners = parse_ss(runner(["ss", "-tulnpH"], args.timeout), "live:ss")
        except InputError as exc:
            rs.notes.append(f"live: socket listing unavailable ({exc}); exposure analysis skipped")
    return rs, listeners


def main(argv: Optional[Sequence[str]] = None, runner: Runner = default_runner) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ignore = {c.strip().upper() for item in args.ignore for c in item.split(",") if c.strip()}
    sensitive = args.sensitive_ports if args.sensitive_ports is not None else DEFAULT_SENSITIVE_PORTS
    try:
        rs, listeners = collect(args, runner)
        findings = run_static_checks(rs, sensitive)
        exposures = None
        if listeners is not None:
            exposures = analyse_exposure(rs, listeners)
            findings += exposure_findings(rs, exposures, listeners, sensitive)
    except (InputError, ParseError, SsParseError) as exc:
        if args.json:
            print(json.dumps({"tool": "nftlint", "version": __version__, "error": str(exc), "exit_code": 3}))
        else:
            print(f"nftlint: error: {exc}", file=sys.stderr)
        return EXIT_UNKNOWN
    floor = SEVERITY_RANK[args.min_severity]
    findings = [f for f in findings if SEVERITY_RANK[f.severity] >= floor and f.code not in ignore]
    code = exit_code(findings)
    if args.json:
        print(render_json(rs, findings, exposures, code))
    else:
        print(render_text(rs, findings, exposures, code, verbose=args.verbose))
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
