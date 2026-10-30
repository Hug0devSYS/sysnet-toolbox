"""Command-line interface."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
import zlib
from typing import Dict, List, Optional, Sequence, Tuple

from . import __version__
from .diff import Differ, summarize
from .loader import detect, load
from .masking import MODES, Masker
from .model import FAMILIES, VENDORS, Change, Config, ParseError
from .render import Result, junos_commands, render_summary, render_text, to_dict

EXIT_SAME, EXIT_DIFF, EXIT_ERROR = 0, 1, 2
MAX_BYTES = 64 * 1024 * 1024

DESCRIPTION = """\
Semantic diff of network device configurations. Statements are compared
hierarchically (a line belongs to its interface / router / policy context),
order is ignored where the device ignores it and checked where it matters
(ACL entries, firewall policies, policy chains), single-valued commands are
reported as modifications, and secrets are masked before anything is printed.

Supported: Cisco IOS / IOS-XE / NX-OS / IOS-XR, Arista EOS (indentation
based), Junos (brace or 'display set' format, interchangeably) and FortiOS.
"""

EPILOG = """\
examples:
  netcfg-diff r1-2026-10-01.cfg r1-2026-10-21.cfg
  netcfg-diff --section '^interface ' --brief old.cfg new.cfg
  netcfg-diff --json fw-a.conf fw-b.conf | jq '.changes[] | select(.op=="move")'
  netcfg-diff --format set junos-before.conf junos-after.set > change.set
  netcfg-diff backups/2026-10-20/ backups/2026-10-21/ --format summary
  netcfg-diff r1.cfg backups/2026-10-20/          (compares with backups/2026-10-20/r1.cfg)
  git difftool -y -x 'netcfg-diff' HEAD~1 -- r1.cfg

exit codes: 0 no semantic difference, 1 differences found, 2 error
            (same convention as diff(1))
"""


class InputError(Exception):
    pass


def read_input(path: str) -> str:
    try:
        if path == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rb") as fh:  # type: ignore[operator]
                data = fh.read(MAX_BYTES + 1)
    except (OSError, EOFError, zlib.error) as exc:
        detail = exc.strerror if isinstance(exc, OSError) and exc.strerror else exc
        if isinstance(exc, zlib.error):
            detail = f"corrupt gzip data ({exc})"
        raise InputError(f"{path}: {detail}") from exc
    if len(data) > MAX_BYTES:
        raise InputError(f"{path}: larger than {MAX_BYTES // (1024 * 1024)} MiB")
    if b"\x00" in data[:8192]:
        raise InputError(f"{path}: looks like a binary file")
    return decode(data)


def decode(data: bytes) -> str:
    """Decode a configuration: UTF-8 (with or without BOM), else Windows-1252.

    Older devices and TFTP backups often store descriptions and banners in a
    legacy 8-bit encoding; decoding them as UTF-8 with replacement characters
    would make every accented line look modified once the device is
    upgraded. Bytes undefined in Windows-1252 fall back to Latin-1.
    """
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("cp1252")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netcfg-diff",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "left", help="old configuration file or directory ('-' for stdin; FILE DIR compares with DIR/FILE)"
    )
    p.add_argument("right", help="new configuration file or directory ('-' for stdin)")
    p.add_argument(
        "--vendor",
        choices=("auto", *VENDORS),
        default="auto",
        help="configuration dialect (default: auto-detected per file)",
    )
    p.add_argument(
        "--format",
        choices=("text", "json", "set", "summary"),
        default="text",
        help="output format; 'set' prints Junos set/delete/insert commands (Junos only)",
    )
    p.add_argument("--json", action="store_const", const="json", dest="format", help="same as --format json")
    p.add_argument("--brief", action="store_true", help="collapse added/removed blocks to their first line")
    p.add_argument(
        "--section",
        action="append",
        default=[],
        metavar="REGEX",
        help="only report changes whose context path matches REGEX (repeatable)",
    )
    p.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="REGEX",
        help="drop statements matching REGEX, with their sub-statements, before comparing (repeatable)",
    )
    p.add_argument(
        "--ignore-file", metavar="FILE", help="file with one --ignore REGEX per line ('#' comments)"
    )
    p.add_argument(
        "--keep-volatile",
        action="store_true",
        help="keep statements ignored by default (ntp clock-period, timestamps, prompts)",
    )
    p.add_argument("--ignore-order", action="store_true", help="never report order changes")
    p.add_argument(
        "--secrets",
        choices=MODES,
        default="mask",
        help="mask: HMAC fingerprints, changes visible (default); presence: ignore secret values; "
        "show: print secrets in clear",
    )
    p.add_argument(
        "--color", choices=("auto", "always", "never"), default="auto", help="colorize text output"
    )
    p.add_argument("-q", "--quiet", action="store_true", help="print nothing, only set the exit code")
    p.add_argument("--version", action="version", version=f"netcfg-diff {__version__}")
    return p


def compile_patterns(exprs: Sequence[str], what: str) -> List[re.Pattern]:
    out = []
    for e in exprs:
        try:
            out.append(re.compile(e))
        except re.error as exc:
            raise InputError(f"{what}: invalid regular expression {e!r}: {exc}") from exc
    return out


def resolve_vendors(vendor: str, ltext: str, rtext: str, lname: str, rname: str) -> Tuple[str, str]:
    if vendor != "auto":
        return vendor, vendor
    lv = detect(ltext) if ltext.strip() else None
    rv = detect(rtext) if rtext.strip() else None
    lv, rv = lv or rv or "ios", rv or lv or "ios"
    if FAMILIES[lv] != FAMILIES[rv]:
        raise InputError(
            f"cannot compare {lname} (detected {lv}) with {rname} (detected {rv}); "
            "use --vendor to force a dialect"
        )
    return lv, rv


def compare(
    ltext: str,
    rtext: str,
    lname: str,
    rname: str,
    args: argparse.Namespace,
    ignore: Sequence[re.Pattern],
    sections: Sequence[re.Pattern],
    masker: Masker,
) -> Result:
    lv, rv = resolve_vendors(args.vendor, ltext, rtext, lname, rname)
    try:
        left = load(ltext, lv, masker, ignore, args.keep_volatile)
    except ParseError as exc:
        raise InputError(f"{lname}: {exc}") from exc
    try:
        right = load(rtext, rv, masker, ignore, args.keep_volatile)
    except ParseError as exc:
        raise InputError(f"{rname}: {exc}") from exc
    changes = diff_configs(left, right, args.ignore_order)
    if sections:
        changes = [c for c in changes if _in_section(c, sections)]
    return Result(lname, rname, left, right, changes)


def diff_configs(left: Config, right: Config, ignore_order: bool = False) -> List[Change]:
    differ = Differ(pair_leaves=left.family == "junos", ignore_order=ignore_order)
    return differ.diff(left.root, right.root)


def _in_section(change: Change, sections: Sequence[re.Pattern]) -> bool:
    full = " ".join((*change.path, change.node.text))
    return any(p.search(full) for p in sections)


def list_files(root: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for f in sorted(filenames):
            if f.startswith("."):
                continue
            full = os.path.join(dirpath, f)
            out[os.path.relpath(full, root)] = full
    return out


def use_color(mode: str, stream) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def emit(res: Result, fmt: str, color: bool, brief: bool, out, header: Optional[str] = None) -> None:
    if fmt == "text":
        out.write(render_text(res, color, brief))
    elif fmt == "summary":
        out.write(render_summary(res))
    elif fmt == "set":
        if header:
            out.write(f"# {header}\n")
        for cmd in junos_commands(res.changes):
            out.write(cmd + "\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        return _main(argv)
    except BrokenPipeError:  # e.g. piped into head(1)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130


def _main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    out, err = sys.stdout, sys.stderr
    try:
        ignore_exprs = list(args.ignore)
        if args.ignore_file:
            for line in read_input(args.ignore_file).splitlines():
                if line.strip() and not line.lstrip().startswith("#"):
                    ignore_exprs.append(line.strip())
        ignore = compile_patterns(ignore_exprs, "--ignore")
        sections = compile_patterns(args.section, "--section")
        if args.left == "-" and args.right == "-":
            raise InputError("only one side can be read from stdin")
        masker = Masker(args.secrets)
        color = use_color(args.color, out)
        ldir, rdir = os.path.isdir(args.left), os.path.isdir(args.right)
        if ldir and rdir:
            return run_dirs(args, ignore, sections, masker, color)
        if ldir != rdir:
            # diff(1) convention: "FILE DIR" compares FILE with DIR/basename(FILE).
            file_arg = args.right if ldir else args.left
            if file_arg == "-":
                raise InputError("stdin cannot be compared with a directory")
            target = os.path.join(args.left if ldir else args.right, os.path.basename(file_arg))
            if not os.path.isfile(target):
                raise InputError(f"{target}: no such file to compare with {file_arg}")
            if ldir:
                args.left = target
            else:
                args.right = target
        res = compare(
            read_input(args.left),
            read_input(args.right),
            args.left,
            args.right,
            args,
            ignore,
            sections,
            masker,
        )
        if args.format == "set" and res.family != "junos":
            raise InputError("--format set is only available for Junos configurations")
    except InputError as exc:
        print(f"netcfg-diff: {exc}", file=err)
        return EXIT_ERROR
    if not args.quiet:
        if args.format == "json":
            json.dump({"tool": "netcfg-diff", "version": __version__, **to_dict(res)}, out, indent=2)
            out.write("\n")
        else:
            emit(res, args.format, color, args.brief, out)
    return EXIT_DIFF if res.changes else EXIT_SAME


def run_dirs(args, ignore, sections, masker: Masker, color: bool) -> int:
    out, err = sys.stdout, sys.stderr
    lfiles, rfiles = list_files(args.left), list_files(args.right)
    only_left = sorted(set(lfiles) - set(rfiles))
    only_right = sorted(set(rfiles) - set(lfiles))
    pairs, errors = [], []
    differ = False
    for rel in sorted(set(lfiles) & set(rfiles)):
        try:
            res = compare(
                read_input(lfiles[rel]),
                read_input(rfiles[rel]),
                lfiles[rel],
                rfiles[rel],
                args,
                ignore,
                sections,
                masker,
            )
            if args.format == "set" and res.family != "junos":
                raise InputError(f"{rel}: --format set is only available for Junos configurations")
        except InputError as exc:
            errors.append(str(exc))
            print(f"netcfg-diff: {exc}", file=err)
            continue
        pairs.append(res)
        if res.changes:
            differ = True
            if not args.quiet and args.format != "json":
                emit(res, args.format, color, args.brief, out, header=rel)
                if args.format != "set":
                    out.write("\n")
    if not args.quiet:
        if args.format == "json":
            doc = {
                "tool": "netcfg-diff",
                "version": __version__,
                "pairs": [to_dict(r) for r in pairs],
                "only_left": only_left,
                "only_right": only_right,
                "errors": errors,
                "summary": {
                    "compared": len(pairs),
                    "different": sum(1 for r in pairs if r.changes),
                    "only_left": len(only_left),
                    "only_right": len(only_right),
                    "errors": len(errors),
                    "changes": sum(summarize(r.changes)["total"] for r in pairs),
                },
            }
            json.dump(doc, out, indent=2)
            out.write("\n")
        else:
            prefix = "# " if args.format == "set" else ""
            for rel in only_left:
                out.write(f"{prefix}Only in {args.left}: {rel}\n")
            for rel in only_right:
                out.write(f"{prefix}Only in {args.right}: {rel}\n")
            n_diff = sum(1 for r in pairs if r.changes)
            out.write(
                f"{prefix}{len(pairs)} file(s) compared, {n_diff} with differences, "
                f"{len(only_left) + len(only_right)} unpaired, {len(errors)} error(s)\n"
            )
    if errors:
        return EXIT_ERROR
    return EXIT_DIFF if differ or only_left or only_right else EXIT_SAME


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
