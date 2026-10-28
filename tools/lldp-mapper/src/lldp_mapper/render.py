"""Output formats: text report, JSON, Mermaid and Graphviz DOT."""

from __future__ import annotations

import datetime as _dt
import json
from typing import Dict, List

from . import __version__
from .model import SEVERITY_RANK, Finding, Link
from .topology import Topology

EXIT_OK, EXIT_WARNING, EXIT_CRITICAL, EXIT_UNKNOWN = 0, 1, 2, 3
STATUS = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN"}


def exit_code(topo: Topology, findings: List[Finding]) -> int:
    polled = [d for d in topo.devices]
    if polled and all(not d.ok for d in polled):
        return EXIT_UNKNOWN
    sev = {f.severity for f in findings}
    if "critical" in sev:
        return EXIT_CRITICAL
    if "warning" in sev:
        return EXIT_WARNING
    if "unknown" in sev:
        return EXIT_UNKNOWN
    return EXIT_OK


def _counts(findings: List[Finding]) -> Dict[str, int]:
    out = {s: 0 for s in ("critical", "warning", "unknown", "info")}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def _link_status(topo: Topology, link: Link) -> str:
    if link.findings:
        return ",".join(dict.fromkeys(link.findings))
    if link.bidirectional:
        return "ok"
    other = link.b if link.a.node in link.seen_from else link.a
    return "ok (peer not polled)" if not topo.nodes[other.node].polled else "seen from one side"


def _subtitle(node) -> str:
    sub = node.target if node.polled else (node.mgmt_addrs[0] if node.mgmt_addrs else "")
    return "" if sub == node.name else sub


# --------------------------------------------------------------------------- JSON


def render_json(topo: Topology, findings: List[Finding], code: int) -> str:
    devices = []
    for d in topo.devices:
        devices.append(
            {
                "target": d.target,
                "name": d.name,
                "ok": d.ok,
                "error": d.error,
                "sys_object_id": d.sys_object_id or None,
                "chassis_id": d.chassis_id or None,
                "lldp": d.lldp_supported,
                "cdp": d.cdp_supported,
                "neighbors": len(d.neighbors),
                "warnings": d.warnings,
                "depth": d.depth,
                "requests": d.requests,
                "duration_s": round(d.duration_s, 3),
            }
        )
    nodes = [
        {
            "id": n.id,
            "name": n.name,
            "polled": n.polled,
            "target": n.target or None,
            "chassis_id": n.chassis_id or None,
            "mgmt_addrs": n.mgmt_addrs,
            "platform": n.platform or None,
            "capabilities": n.caps,
            "error": n.error,
        }
        for n in topo.nodes.values()
    ]
    links = [
        {
            "a": {"node": lk.a.node, "port": lk.a.port, "facts": lk.a.facts.as_dict()},
            "b": {"node": lk.b.node, "port": lk.b.port, "facts": lk.b.facts.as_dict()},
            "protocols": lk.protocols,
            "seen_from": lk.seen_from,
            "bidirectional": lk.bidirectional,
            "findings": list(dict.fromkeys(lk.findings)),
        }
        for lk in topo.links
    ]
    doc = {
        "tool": "lldp-mapper",
        "version": __version__,
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "devices_polled": sum(1 for d in topo.devices if d.ok),
            "devices_failed": sum(1 for d in topo.devices if not d.ok),
            "nodes": len(topo.nodes),
            "links": len(topo.links),
            "findings": _counts(findings),
            "status": STATUS[code],
            "exit_code": code,
        },
        "devices": devices,
        "nodes": nodes,
        "links": links,
        "findings": [f.as_dict() for f in findings],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- text


def _table(rows: List[List[str]], indent: str = "  ") -> List[str]:
    if not rows:
        return []
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return [indent + "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]


def render_text(topo: Topology, findings: List[Finding], code: int, verbose: bool = False) -> str:
    ok = [d for d in topo.devices if d.ok]
    failed = [d for d in topo.devices if not d.ok]
    out = [
        f"lldp-mapper {__version__}: {len(ok)} device(s) polled"
        + (f", {len(failed)} unreachable" if failed else "")
        + f", {len(topo.nodes)} node(s), {len(topo.links)} link(s)",
        "",
    ]
    out.append("Devices")
    rows = []
    for d in topo.devices:
        if d.ok:
            protos = "+".join(p for p, on in (("LLDP", d.lldp_supported), ("CDP", d.cdp_supported)) if on) or "-"
            rows.append([d.name, d.target, f"{len(d.neighbors)} neighbour(s)", protos, f"{d.duration_s:.1f}s"])
        else:
            rows.append([d.name, d.target, "UNREACHABLE", "", (d.error or "")[:90]])
    out += _table(rows)
    names = {nid: n.name for nid, n in topo.nodes.items()}
    out += ["", "Links"]
    rows = []
    for lk in topo.links:
        rows.append(
            [
                names[lk.a.node],
                lk.a.port,
                "<->",
                names[lk.b.node],
                lk.b.port,
                "+".join(p.upper() for p in lk.protocols),
                _link_status(topo, lk),
            ]
        )
    out += _table(rows) or ["  (none)"]
    if verbose:
        out += ["", "Link facts"]
        for lk in topo.links:
            for ep in (lk.a, lk.b):
                facts = ep.facts.as_dict()
                if not facts:
                    continue
                parts = []
                for k, v in facts.items():
                    val = v.get("value", v.get("enabled"))
                    parts.append(f"{k}={val} [{v['source']}]")
                out.append(f"  {names[ep.node]} {ep.port}: " + "; ".join(parts))
    external = [n for n in topo.nodes.values() if not n.polled]
    if external and verbose:
        out += ["", "Neighbours not polled"]
        out += _table(
            [[n.name, ",".join(n.mgmt_addrs) or "-", ",".join(n.caps) or "-", n.platform[:60]] for n in external]
        )
    out += ["", "Findings"]
    if not findings:
        out.append("  none")
    for f in sorted(findings, key=lambda x: (-SEVERITY_RANK[x.severity], x.code, x.message)):
        out.append(f"  {f.severity.upper():8} {f.code}: {f.message}")
        if verbose and f.detail and "a_source" in f.detail:
            out.append(f"           sources: {f.detail['a_source']} | {f.detail['b_source']}")
    c = _counts(findings)
    out += [
        "",
        f"{STATUS[code]}: {c['critical']} critical, {c['warning']} warning, {c['unknown']} unknown, "
        f"{c['info']} info (exit {code})",
    ]
    return "\n".join(out)


# --------------------------------------------------------------------------- graphs


def _mm(text: str) -> str:
    return (
        text.replace("&", "#amp;")
        .replace('"', "#quot;")
        .replace("<", "#lt;")
        .replace(">", "#gt;")
        .replace("|", "#124;")
    )


def render_mermaid(topo: Topology, direction: str = "LR") -> str:
    out = [f"graph {direction}"]
    for n in topo.nodes.values():
        label = _mm(n.name)
        sub = _subtitle(n)
        if sub:
            label += "<br/><small>" + _mm(sub) + "</small>"
        nid = "n_" + n.id
        if n.polled:
            out.append(f'  {nid}["{label}"]')
        else:
            out.append(f'  {nid}(["{label}"])')
    styles = []
    for i, lk in enumerate(topo.links):
        label = _mm(f"{lk.a.port} — {lk.b.port}")
        arrow = "---" if lk.bidirectional else "-.-"
        out.append(f'  n_{lk.a.node} {arrow}|"{label}"| n_{lk.b.node}')
        if lk.findings:
            styles.append(f"  linkStyle {i} stroke:#d62728,stroke-width:3px")
    out += styles
    out.append("  classDef failed fill:#fde2e1,stroke:#d62728,color:#7a1712")
    failed = [f"n_{n.id}" for n in topo.nodes.values() if n.error]
    if failed:
        out.append(f"  class {','.join(failed)} failed")
    return "\n".join(out) + "\n"


def _dq(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def render_dot(topo: Topology) -> str:
    out = [
        "graph topology {",
        "  graph [rankdir=LR, overlap=false, splines=true];",
        '  node [shape=box, style="rounded", fontname="Helvetica"];',
        '  edge [fontname="Helvetica", fontsize=9];',
    ]
    for n in topo.nodes.values():
        sub = _subtitle(n)
        label = n.name + (f"\n{sub}" if sub else "")
        attrs = [f"label={_dq(label)}"]
        if not n.polled:
            attrs.append("shape=ellipse")
        if n.error:
            attrs += ['color="#d62728"', f"tooltip={_dq(n.error)}"]
        out.append(f"  {_dq(n.id)} [{', '.join(attrs)}];")
    for lk in topo.links:
        attrs = [f"taillabel={_dq(lk.a.port)}", f"headlabel={_dq(lk.b.port)}"]
        if not lk.bidirectional:
            attrs.append("style=dashed")
        if lk.findings:
            attrs += ['color="#d62728"', "penwidth=2.5", f"tooltip={_dq(', '.join(dict.fromkeys(lk.findings)))}"]
        out.append(f"  {_dq(lk.a.node)} -- {_dq(lk.b.node)} [{', '.join(attrs)}];")
    out.append("}")
    return "\n".join(out) + "\n"
