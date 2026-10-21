"""Output formats: annotated text, Junos commands, summary table and JSON."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .diff import summarize
from .model import Change, Config, Node, compress_ints, display

COLORS = {"+": "32", "-": "31", ">": "36", "~": "33", "h": "1"}


@dataclass
class Result:
    left_name: str
    right_name: str
    left: Config
    right: Config
    changes: List[Change] = field(default_factory=list)

    @property
    def family(self) -> str:
        return self.left.family


def section_of(change: Change, family: str) -> str:
    """Coarse grouping key: top-level context (Cisco), config/edit (FortiOS), 2 tokens (Junos)."""
    if family == "junos":
        return display(" ".join((*change.path, change.node.text)[:2]), 80)
    if not change.path:
        if family == "cisco" and not change.node.children:
            return "(global)"
        return display(change.node.text, 80)
    return display(" ".join(change.path[: 1 if family == "cisco" else 2]), 80)


def _fmt_values(vals: Sequence[Any]) -> str:
    if vals and all(isinstance(v, int) for v in vals):
        return compress_ints(vals)
    return ", ".join(str(v) for v in vals)


def annotation(change: Change) -> str:
    d = change.detail
    if change.op == "modify" and ("added" in d or "removed" in d):
        parts = []
        if d.get("added"):
            parts.append(f"added: {_fmt_values(d['added'])}")
        if d.get("removed"):
            parts.append(f"removed: {_fmt_values(d['removed'])}")
        return "; ".join(parts)
    if change.op == "move":
        return f"moved from position {d['from']} to {d['to']}"
    if change.op == "add" and "position" in d and not d.get("tail"):
        return f"inserted at position {d['position']}"
    if change.op in ("activate", "deactivate"):
        return f"{change.op}d"
    return ""


class _Out:
    def __init__(self, color: bool):
        self.color = color
        self.lines: List[str] = []

    def emit(self, sign: str, text: str, note: str = "") -> None:
        line = f"{sign}{text}" + (f"  # {note}" if note else "")
        if self.color and sign.strip() in COLORS:
            line = f"\033[{COLORS[sign.strip()]}m{line}\033[0m"
        self.lines.append(line)

    def header(self, text: str) -> None:
        self.lines.append(f"\033[1m{text}\033[0m" if self.color else text)


# ---------------------------------------------------------------- Junos helpers


def _j(*parts: str) -> str:
    return " ".join(p for p in parts if p)


def junos_insert(change: Change) -> Optional[str]:
    """'insert' command placing an element of an ordered list (terms, policies, chains)."""
    d, path, node = change.detail, change.path, change.node
    if not path:
        return None
    keyword = path[-1] if node.children else ""
    base = " ".join(path)
    if "after" in d:
        return _j("insert", base, node.text, "after", keyword, d["after"])
    if "before" in d:
        return _j("insert", base, node.text, "before", keyword, d["before"])
    return None


def _inactive_paths(node: Node, prefix: Tuple[str, ...]) -> Iterable[Tuple[str, ...]]:
    here = prefix + (node.text,)
    if node.inactive:
        yield here
    for c in node.children:
        yield from _inactive_paths(c, here)


def junos_commands(changes: Sequence[Change]) -> List[str]:
    """Junos CLI commands turning the left configuration into the right one."""
    deletes: List[str] = []
    sets: List[str] = []
    inserts: List[str] = []
    acts: List[str] = []
    for ch in changes:
        if ch.op == "add":
            assert ch.after is not None
            sets.extend("set " + " ".join(ch.path + leaf) for leaf in ch.after.leaf_paths())
            acts.extend("deactivate " + " ".join(p) for p in _inactive_paths(ch.after, ch.path))
            if "position" in ch.detail and not ch.detail.get("tail"):
                cmd = junos_insert(ch)
                if cmd:
                    inserts.append(cmd)
        elif ch.op == "remove":
            assert ch.before is not None
            deletes.append("delete " + " ".join(ch.path + (ch.before.text,)))
        elif ch.op == "modify":
            assert ch.after is not None
            deletes.append("delete " + " ".join(ch.path))
            sets.append("set " + " ".join(ch.path + (ch.after.text,)))
        elif ch.op == "move":
            cmd = junos_insert(ch)
            if cmd:
                inserts.append(cmd)
        else:
            acts.append(f"{ch.op} " + " ".join(ch.path + (ch.node.text,)))
    return deletes + sets + inserts + acts


# ---------------------------------------------------------------- text output


def _subtree(out: _Out, sign: str, node: Node, depth: int, note: str = "", brief: bool = False) -> None:
    ind = "  " * depth
    if brief and node.children:
        out.emit(sign, ind + display(node.text), _join(note, f"{node.size() - 1} sub-statement(s)"))
        return
    out.emit(sign, ind + display(node.text), note)
    for c in node.children:
        _subtree(out, sign, c, depth + 1)


def _join(*notes: str) -> str:
    return "; ".join(n for n in notes if n)


def _junos_text(out: _Out, changes: Sequence[Change], brief: bool) -> None:
    for ch in changes:
        note = annotation(ch)
        if ch.op == "add":
            assert ch.after is not None
            leaves = list(ch.after.leaf_paths(ch.path))
            if brief and len(leaves) > 1:
                out.emit(
                    "+ ",
                    "set " + display(" ".join(ch.path + (ch.after.text,))),
                    _join(note, f"{len(leaves)} statements"),
                )
            else:
                for i, leaf in enumerate(leaves):
                    out.emit("+ ", "set " + display(" ".join(leaf)), note if i == 0 else "")
            for p in _inactive_paths(ch.after, ch.path):
                out.emit("~ ", "deactivate " + display(" ".join(p)))
        elif ch.op == "remove":
            assert ch.before is not None
            leaves = list(ch.before.leaf_paths(ch.path))
            if brief and len(leaves) > 1:
                out.emit(
                    "- ",
                    "delete " + display(" ".join(ch.path + (ch.before.text,))),
                    f"{len(leaves)} statements",
                )
            else:
                for leaf in leaves:
                    out.emit("- ", "set " + display(" ".join(leaf)))
        elif ch.op == "modify":
            assert ch.before is not None and ch.after is not None
            out.emit("- ", "set " + display(" ".join(ch.path + (ch.before.text,))))
            out.emit("+ ", "set " + display(" ".join(ch.path + (ch.after.text,))))
        elif ch.op == "move":
            out.emit("> ", display(junos_insert(ch) or " ".join(ch.path + (ch.node.text,))), note)
        else:
            out.emit("~ ", f"{ch.op} " + display(" ".join(ch.path + (ch.node.text,))))


def _tree_text(out: _Out, changes: Sequence[Change], brief: bool) -> None:
    printed: Tuple[str, ...] = ()
    for ch in changes:
        path = ch.path
        common = 0
        while common < min(len(printed), len(path)) and printed[common] == path[common]:
            common += 1
        for d in range(common, len(path)):
            out.emit("  ", "  " * d + display(path[d]))
        printed = path
        depth = len(path)
        note = annotation(ch)
        ind = "  " * depth
        if ch.op == "add":
            assert ch.after is not None
            _subtree(out, "+ ", ch.after, depth, note, brief)
        elif ch.op == "remove":
            assert ch.before is not None
            _subtree(out, "- ", ch.before, depth, note, brief)
        elif ch.op == "modify":
            assert ch.before is not None and ch.after is not None
            out.emit("- ", ind + display(ch.before.text))
            out.emit("+ ", ind + display(ch.after.text), note)
        elif ch.op == "move":
            out.emit("> ", ind + display(ch.node.text), note)
        else:
            out.emit("~ ", ind + display(ch.node.text), note)


def summary_line(changes: Sequence[Change]) -> str:
    s = summarize(changes)
    if not s["total"]:
        return "No semantic differences."
    parts = [
        f"{s[k]} {k}" for k in ("added", "removed", "modified", "moved", "activated", "deactivated") if s[k]
    ]
    return f"{s['total']} change(s): " + ", ".join(parts)


def render_text(res: Result, color: bool = False, brief: bool = False) -> str:
    out = _Out(color)
    out.header(f"--- {res.left_name} ({res.left.vendor})")
    out.header(f"+++ {res.right_name} ({res.right.vendor})")
    if res.family == "junos":
        _junos_text(out, res.changes, brief)
    else:
        _tree_text(out, res.changes, brief)
    out.lines.append(summary_line(res.changes))
    return "\n".join(out.lines) + "\n"


def render_summary(res: Result) -> str:
    rows: Dict[str, Dict[str, int]] = {}
    sym = {"add": "+", "remove": "-", "modify": "~", "move": ">", "activate": "~", "deactivate": "~"}
    for ch in res.changes:
        row = rows.setdefault(section_of(ch, res.family), {"+": 0, "-": 0, "~": 0, ">": 0})
        row[sym[ch.op]] += 1
    lines = [f"{res.left_name} -> {res.right_name} ({res.left.vendor})"]
    if rows:
        width = max(len(k) for k in rows)
        lines.append(f"  {'section':<{width}}  {'+':>5} {'-':>5} {'~':>5} {'>':>5}")
        for name, r in rows.items():
            lines.append(f"  {name:<{width}}  {r['+']:>5} {r['-']:>5} {r['~']:>5} {r['>']:>5}")
    lines.append(summary_line(res.changes))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- JSON


def _lines(node: Node) -> List[str]:
    return ["  " * d + display(n.text, 4096) for d, n in node.walk()]


def change_to_dict(ch: Change, family: str) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "op": ch.op,
        "section": section_of(ch, family),
        "path": list(ch.path),
        "statement": ch.node.text,
        "before": ch.before.text if ch.before is not None else None,
        "after": ch.after.text if ch.after is not None else None,
    }
    if ch.op in ("add", "remove"):
        d["lines"] = _lines(ch.node)
    detail = {k: v for k, v in ch.detail.items() if v != []}
    for k in ("added", "removed"):
        if k in detail and detail[k] and all(isinstance(v, int) for v in detail[k]):
            detail[k + "_ranges"] = compress_ints(detail[k])
    if detail:
        d["detail"] = detail
    if family == "junos":
        d["commands"] = junos_commands([ch])
    return d


def to_dict(res: Result) -> Dict[str, Any]:
    return {
        "left": {"name": res.left_name, "vendor": res.left.vendor, **_meta(res.left)},
        "right": {"name": res.right_name, "vendor": res.right.vendor, **_meta(res.right)},
        "identical": not res.changes,
        "summary": summarize(res.changes),
        "changes": [change_to_dict(c, res.family) for c in res.changes],
    }


def _meta(cfg: Config) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if "version" in cfg.meta:
        out["version"] = cfg.meta["version"]
    if "format" in cfg.meta:
        out["format"] = cfg.meta["format"]
    out["ignored_statements"] = int(cfg.meta.get("removed", "0"))
    return out
