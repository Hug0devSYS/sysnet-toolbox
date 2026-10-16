"""Text and JSON rendering."""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from . import __version__
from .exposure import STATUS_ORDER, Exposure
from .model import FAMILY_NAMES, SEVERITIES, SEVERITY_RANK, Finding, Ruleset

EXIT_NAMES = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}


def exit_code(findings: List[Finding]) -> int:
    worst = max((SEVERITY_RANK[f.severity] for f in findings), default=0)
    if worst >= SEVERITY_RANK["high"]:
        return 2
    if worst >= SEVERITY_RANK["medium"]:
        return 1
    return 0


def summary(findings: List[Finding]) -> Dict[str, int]:
    out = {s: 0 for s in reversed(SEVERITIES)}
    for f in findings:
        out[f.severity] += 1
    return out


def sort_findings(findings: List[Finding]) -> List[Finding]:
    def key(f: Finding):
        chain = f.rule.chain if f.rule is not None else f.chain
        loc = chain.key() if chain is not None else ("", "", "", "")
        idx = f.rule.index if f.rule is not None else 0
        return (-SEVERITY_RANK[f.severity], loc, idx, f.code)

    return sorted(findings, key=key)


def render_json(rs: Ruleset, findings: List[Finding], exposures: Optional[List[Exposure]], code: int) -> str:
    doc: Dict[str, object] = {
        "tool": "nftlint",
        "version": __version__,
        "sources": rs.sources,
        "summary": summary(findings),
        "status": EXIT_NAMES[code],
        "exit_code": code,
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    if exposures is not None:
        doc["exposure"] = [e.to_dict() for e in exposures]
    return json.dumps(doc, indent=2, sort_keys=False)


def _table(rows: List[List[str]]) -> List[str]:
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return ["  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]


def render_text(
    rs: Ruleset,
    findings: List[Finding],
    exposures: Optional[List[Exposure]],
    code: int,
    verbose: bool = False,
) -> str:
    out: List[str] = []
    for s in rs.sources:
        out.append(
            f"nftlint {__version__}: {s['path']} ({s['format']}, {s['tables']} table(s), "
            f"{s['chains']} chain(s), {s['rules']} rule(s))"
        )
    out.append("")
    if not findings:
        out.append("No findings.")
    for f in sort_findings(findings):
        out.append(f"[{f.severity.upper():<6}] {f.code} {f.title}  {f.location()}")
        if f.rule is not None:
            out.append(f"         rule: {f.rule.text}")
        out.append(f"         {f.message}")
        out.append("")
    if exposures is not None:
        out.append("Exposure of listening sockets (first packet, ct state new, non-loopback):")
        rows = [["PROTO", "ADDRESS", "PORT", "PROCESS", "STATUS", "DETAIL"]]
        for e in sorted(exposures, key=lambda e: (-STATUS_ORDER.index(e.status), e.listener.port)):
            lst = e.listener
            detail = _exposure_detail(e, verbose)
            rows.append([lst.proto, lst.raw_address, str(lst.port), lst.process or "-", e.status, detail])
        out.extend("  " + line for line in _table(rows))
        out.append("")
    counts = summary(findings)
    out.append(
        "Summary: "
        + ", ".join(f"{n} {s}" for s, n in counts.items())
        + f" -> {EXIT_NAMES[code]} (exit {code})"
    )
    return "\n".join(out)


def _exposure_detail(e: Exposure, verbose: bool) -> str:
    if not e.results:
        return "loopback only"
    parts = []
    for r in e.results:
        fam = FAMILY_NAMES[r.family]
        if r.status == "restricted":
            parts.append(f"{fam}: from {r.sources()}")
        elif r.status == "open":
            parts.append(f"{fam}: any source" + (" (default policy)" if r.via_policy_only else ""))
        elif r.status == "conditional":
            parts.append(f"{fam}: depends on conditions nftlint cannot evaluate")
        elif r.status == "unfiltered":
            parts.append(f"{fam}: no input filtering")
        elif r.status == "unknown":
            parts.append(f"{fam}: ruleset not analysed")
        else:
            parts.append(f"{fam}: dropped")
        if verbose:
            locs = [f"accepted by {x.location()}" for x in r.accept_rules[:3]]
            locs += [f"maybe accepted by {x.location()}" for x in r.maybe_rules[:3]]
            if locs:
                parts[-1] += " [" + "; ".join(locs) + "]"
        if r.caveats:
            parts[-1] += f" ({len({c.location() for c in r.caveats})} unevaluated drop condition(s))"
    return "; ".join(parts)
