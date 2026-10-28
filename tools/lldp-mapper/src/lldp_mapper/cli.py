"""Command-line interface."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import stat
import sys
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .ber import BerError
from .discovery import CrawlSettings, discover
from .mibs import WALKS
from .model import SEVERITIES, SEVERITY_RANK, Finding
from .render import EXIT_UNKNOWN, exit_code, render_dot, render_json, render_mermaid, render_text
from .snmp import V3_AUTH, V3_PRIV, FileWalker, NativeWalker, NetSnmpConfig, NetSnmpWalker, V3Credentials, dump_walk
from .topology import build

DESCRIPTION = """\
Discover the layer-2 topology of a network over SNMP (LLDP-MIB and
CISCO-CDP-MIB neighbour tables) and check every link for the problems that
LLDP/CDP make visible: duplex, speed and auto-negotiation mismatches, native
VLAN (PVID) mismatches, one-way adjacencies and miscabled ports. Outputs a
text report, JSON, a Mermaid or Graphviz graph.

lldp-mapper is read-only: it only sends SNMP GetNext/GetBulk requests.
"""

EPILOG = """\
credentials (never on the command line):
  SNMPv1/v2c  community in $SNMP_COMMUNITY (see --community-env) or --community-file
  SNMPv3      --user NAME [--auth-proto SHA-256 --priv-proto AES]; passphrases in
              $SNMP_AUTH_PASS / $SNMP_PRIV_PASS; uses net-snmp's snmpbulkwalk

examples:
  SNMP_COMMUNITY=... lldp-mapper core1.example.net core2.example.net
  lldp-mapper --crawl --scope 10.10.0.0/16 core1 --graph topo.mmd --graph topo.json
  lldp-mapper -s 3 --user nms --auth-proto SHA-256 --priv-proto AES -f switches.txt
  lldp-mapper --from-walks walks/ --format dot | dot -Tsvg > topo.svg

exit codes: 0 OK, 1 warning finding(s), 2 critical finding(s) (duplex mismatch),
            3 unknown: poll failures only, all polls failed, or usage error
"""

ALL_CAPS = ("other", "repeater", "bridge", "wlanAccessPoint", "router", "telephone", "docsisCableDevice", "stationOnly")


class UsageError(Exception):
    pass


def _csv(text: str) -> List[str]:
    return [x.strip() for x in text.split(",") if x.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lldp-mapper", description=DESCRIPTION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("targets", nargs="*", metavar="TARGET", help="device hostname or IP address to poll")
    p.add_argument(
        "-f",
        "--targets-file",
        action="append",
        default=[],
        metavar="FILE",
        help="file with one target per line ('#' comments); repeatable",
    )
    p.add_argument(
        "--from-walks",
        action="append",
        default=[],
        metavar="PATH",
        help="offline mode: analyse saved walks (`snmpbulkwalk -On` output or --save-walks files); "
        "file or directory, repeatable",
    )

    g = p.add_argument_group("SNMP")
    g.add_argument("-s", "--snmp-version", choices=("1", "2c", "3"), default="2c", help="default: 2c")
    g.add_argument(
        "--community-env",
        default="SNMP_COMMUNITY",
        metavar="VAR",
        help="environment variable holding the v1/v2c community (default: SNMP_COMMUNITY)",
    )
    g.add_argument("--community-file", metavar="FILE", help="file whose first line is the community")
    g.add_argument("--user", help="SNMPv3 security name")
    g.add_argument("--auth-proto", choices=V3_AUTH, help="SNMPv3 authentication protocol")
    g.add_argument("--priv-proto", choices=V3_PRIV, help="SNMPv3 privacy protocol (requires --auth-proto)")
    g.add_argument("--auth-pass-env", default="SNMP_AUTH_PASS", metavar="VAR", help="default: SNMP_AUTH_PASS")
    g.add_argument("--priv-pass-env", default="SNMP_PRIV_PASS", metavar="VAR", help="default: SNMP_PRIV_PASS")
    g.add_argument("--context", help="SNMPv3 context name")
    g.add_argument(
        "--backend",
        choices=("auto", "native", "net-snmp"),
        default="auto",
        help="auto: built-in client for v1/v2c, net-snmp for v3 (default)",
    )
    g.add_argument("--port", type=int, default=161)
    g.add_argument("--timeout", type=float, default=2.0, help="per-request timeout in seconds (default: 2)")
    g.add_argument("--retries", type=int, default=2, help="retries per request (default: 2)")
    g.add_argument("--max-repetitions", type=int, default=25, help="GetBulk max-repetitions (default: 25)")
    g.add_argument(
        "--device-timeout",
        type=float,
        default=120.0,
        help="time budget for all walks of one device in seconds (default: 120, 0 = none)",
    )
    g.add_argument("--workers", type=int, default=8, help="devices polled in parallel (default: 8)")

    c = p.add_argument_group("crawling")
    c.add_argument(
        "--crawl",
        action="store_true",
        help="also poll neighbours through their advertised management address (needs --scope)",
    )
    c.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="CIDR",
        help="only crawl into these prefixes; repeatable or comma-separated",
    )
    c.add_argument("--max-depth", type=int, default=3, help="crawl depth from the seeds (default: 3)")
    c.add_argument("--max-devices", type=int, default=256, help="stop after polling this many devices")
    c.add_argument(
        "--crawl-caps",
        default="bridge,router",
        metavar="LIST",
        help="neighbour capabilities worth crawling (default: bridge,router)",
    )

    o = p.add_argument_group("output")
    o.add_argument(
        "--format",
        choices=("text", "json", "mermaid", "dot"),
        default="text",
        help="standard output format (default: text)",
    )
    o.add_argument("--json", action="store_true", help="shortcut for --format json")
    o.add_argument(
        "--graph",
        action="append",
        default=[],
        metavar="FILE",
        help="also write the topology to FILE; format from the extension: .mmd/.mermaid, .dot/.gv, .json; repeatable",
    )
    o.add_argument("--direction", choices=("LR", "TB", "RL", "BT"), default="LR", help="Mermaid layout")
    o.add_argument(
        "--save-walks",
        metavar="DIR",
        help="save the raw walk of every polled device to DIR/<target>.walk (re-usable with --from-walks)",
    )
    o.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="info",
        help="hide findings below this severity (also ignored for the exit code)",
    )
    o.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="CODE",
        help="suppress a finding code (e.g. shared-port); repeatable or comma-separated",
    )
    o.add_argument("--progress", action="store_true", help="report each poll on stderr")
    o.add_argument("-v", "--verbose", action="store_true", help="show link facts with their sources")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


# --------------------------------------------------------------------------- inputs


def read_targets(args: argparse.Namespace) -> List[str]:
    targets = list(args.targets)
    for path in args.targets_file:
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        targets.extend(line.split())
        except OSError as exc:
            raise UsageError(f"{path}: {exc.strerror or exc}") from exc
    for t in targets:
        if not re.match(r"^[A-Za-z0-9._:%-]+$", t):
            raise UsageError(f"invalid target {t!r}")
    return list(dict.fromkeys(targets))


def read_community(args: argparse.Namespace, warn: Callable[[str], None]) -> bytes:
    if args.community_file:
        try:
            st = os.stat(args.community_file)
            with open(args.community_file, "rb") as fh:
                lines = [ln.strip() for ln in fh.read().splitlines() if ln.strip()]
        except OSError as exc:
            raise UsageError(f"{args.community_file}: {exc.strerror or exc}") from exc
        if not lines:
            raise UsageError(f"{args.community_file}: empty")
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            warn(f"{args.community_file} is readable by group/others; chmod 600 it")
        return lines[0]
    value = os.environ.get(args.community_env)
    if not value:
        raise UsageError(f"no SNMP community: set ${args.community_env} or use --community-file")
    return value.encode("utf-8", "surrogateescape")


def read_v3(args: argparse.Namespace) -> V3Credentials:
    if not args.user:
        raise UsageError("SNMPv3 needs --user")
    if args.priv_proto and not args.auth_proto:
        raise UsageError("--priv-proto requires --auth-proto (authPriv)")
    creds = V3Credentials(user=args.user, auth_proto=args.auth_proto, priv_proto=args.priv_proto, context=args.context)
    for proto, env, attr in (
        (args.auth_proto, args.auth_pass_env, "auth_pass"),
        (args.priv_proto, args.priv_pass_env, "priv_pass"),
    ):
        if not proto:
            continue
        value = os.environ.get(env, "")
        if len(value) < 8:
            raise UsageError(f"${env} must hold the {attr.split('_')[0]} passphrase (8 characters minimum)")
        setattr(creds, attr, value)
    return creds


def parse_scope(items: List[str]) -> List[ipaddress._BaseNetwork]:
    out = []
    for item in items:
        for part in _csv(item):
            try:
                out.append(ipaddress.ip_network(part, strict=False))
            except ValueError as exc:
                raise UsageError(f"--scope: {exc}") from exc
    return out


def walk_files(paths: List[str]) -> List[str]:
    files: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                full = os.path.join(path, name)
                if os.path.isfile(full) and not name.startswith("."):
                    files.append(full)
        elif os.path.isfile(path):
            files.append(path)
        else:
            raise UsageError(f"{path}: no such file or directory")
    if not files:
        raise UsageError("--from-walks: no walk file found")
    return files


def graph_format(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    fmt = {".mmd": "mermaid", ".mermaid": "mermaid", ".dot": "dot", ".gv": "dot", ".json": "json"}.get(ext)
    if fmt is None:
        raise UsageError(f"--graph {path}: unknown extension (use .mmd, .dot, .gv or .json)")
    return fmt


def safe_filename(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", target).lstrip(".") or "device"


# --------------------------------------------------------------------------- main


Opener = Callable[[str, Optional[float]], Tuple[Callable, Callable[[], None], Callable[[], int]]]


def make_opener(args: argparse.Namespace, warn: Callable[[str], None]) -> Tuple[Opener, Callable[[], None]]:
    backend = args.backend
    if backend == "auto":
        backend = "net-snmp" if args.snmp_version == "3" else "native"
    if backend == "native" and args.snmp_version == "3":
        raise UsageError("the built-in client does not implement SNMPv3: use --backend net-snmp (default)")
    common = dict(port=args.port, timeout=args.timeout, retries=args.retries, max_repetitions=args.max_repetitions)
    if backend == "native":
        community = read_community(args, warn)

        def open_native(target: str, deadline: Optional[float]):
            w = NativeWalker(target, community, version=args.snmp_version, deadline=deadline, **common)
            return w.walk, w.close, lambda: w.requests

        return open_native, lambda: None
    community = read_community(args, warn) if args.snmp_version != "3" else None
    v3 = read_v3(args) if args.snmp_version == "3" else None
    conf = NetSnmpConfig(args.snmp_version, community, v3)

    def open_netsnmp(target: str, deadline: Optional[float]):
        w = NetSnmpWalker(target, conf, version=args.snmp_version, deadline=deadline, **common)
        return w.walk, w.close, lambda: w.requests

    return open_netsnmp, conf.cleanup


def filter_findings(findings: List[Finding], args: argparse.Namespace) -> List[Finding]:
    ignore = {c.lower() for item in args.ignore for c in _csv(item)}
    floor = SEVERITY_RANK[args.min_severity]
    return [f for f in findings if SEVERITY_RANK[f.severity] >= floor and f.code not in ignore]


def main(argv: Optional[Sequence[str]] = None, opener: Optional[Opener] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.json:
        args.format = "json"

    def warn(msg: str) -> None:
        print(f"lldp-mapper: warning: {msg}", file=sys.stderr)

    def fail(msg: str) -> int:
        if args.format == "json":
            print(json.dumps({"tool": "lldp-mapper", "version": __version__, "error": msg, "exit_code": EXIT_UNKNOWN}))
        else:
            print(f"lldp-mapper: error: {msg}", file=sys.stderr)
        return EXIT_UNKNOWN

    cleanup: Callable[[], None] = lambda: None  # noqa: E731
    try:
        graphs = [(path, graph_format(path)) for path in args.graph]
        for name, val, low in (
            ("--timeout", args.timeout, 0.1),
            ("--workers", args.workers, 1),
            ("--max-repetitions", args.max_repetitions, 1),
            ("--retries", args.retries, 0),
            ("--max-depth", args.max_depth, 0),
            ("--max-devices", args.max_devices, 1),
        ):
            if val < low:
                raise UsageError(f"{name} must be >= {low}")
        if not 0 < args.port < 65536:
            raise UsageError("--port must be between 1 and 65535")
        progress = (lambda m: print(m, file=sys.stderr)) if args.progress else None
        if args.from_walks:
            if args.targets or args.targets_file or args.crawl:
                raise UsageError("--from-walks cannot be combined with targets or --crawl")
            walkers: Dict[str, FileWalker] = {}
            for path in walk_files(args.from_walks):
                try:
                    fw = FileWalker.from_file(path)
                except (OSError, BerError, UnicodeError) as exc:
                    raise UsageError(f"{path}: {exc}") from exc
                walkers[fw.name] = fw

            def open_file(target: str, deadline: Optional[float]):
                fw = walkers[target]
                return fw.walk, fw.close, lambda: fw.requests

            devices, raw = discover(list(walkers), open_file, workers=1, device_timeout=None, progress=progress)
        else:
            targets = read_targets(args)
            if not targets:
                raise UsageError("no target given (pass hostnames/addresses, -f FILE or --from-walks)")
            crawl = CrawlSettings(
                enabled=args.crawl,
                scope=parse_scope(args.scope),
                max_depth=args.max_depth,
                max_devices=args.max_devices,
                capabilities=set(_csv(args.crawl_caps)),
            )
            bad_caps = crawl.capabilities - set(ALL_CAPS)
            if bad_caps:
                raise UsageError(
                    f"--crawl-caps: unknown capability {', '.join(sorted(bad_caps))} "
                    f"(choose from {', '.join(ALL_CAPS)})"
                )
            if args.crawl and not crawl.scope:
                raise UsageError("--crawl needs at least one --scope prefix (crawling never leaves it)")
            if opener is None:
                opener, cleanup = make_opener(args, warn)
            devices, raw = discover(
                targets,
                opener,
                workers=args.workers,
                device_timeout=args.device_timeout or None,
                crawl=crawl,
                progress=progress,
            )
    except UsageError as exc:
        return fail(str(exc))
    except KeyboardInterrupt:
        return fail("interrupted")
    finally:
        cleanup()

    if args.save_walks:
        try:
            os.makedirs(args.save_walks, exist_ok=True)
            for target, data in raw.items():
                if not data:
                    continue
                vbs = [vb for key, _root in WALKS for vb in data.get(key, [])]
                with open(os.path.join(args.save_walks, safe_filename(target) + ".walk"), "w", encoding="utf-8") as fh:
                    fh.write(dump_walk(vbs))
        except OSError as exc:
            warn(f"--save-walks: {exc}")

    topo = build(devices)
    findings = filter_findings(topo.findings, args)
    code = exit_code(topo, findings)
    renderers = {
        "json": lambda: render_json(topo, findings, code),
        "mermaid": lambda: render_mermaid(topo, args.direction),
        "dot": lambda: render_dot(topo),
        "text": lambda: render_text(topo, findings, code, verbose=args.verbose),
    }
    for path, fmt in graphs:
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(renderers[fmt]())
                if fmt == "json":
                    fh.write("\n")
        except OSError as exc:
            warn(f"--graph {path}: {exc.strerror or exc}")
    sys.stdout.write(renderers[args.format]().rstrip("\n") + "\n")
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
