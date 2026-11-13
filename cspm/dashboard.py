"""KPI dashboard.

Two outputs from the same data:

* dashboard/data/*.csv   one file per table, ready to load into Power BI
* dashboard/index.html   a self-contained page that needs no server or licence

The page shows each business unit's risk against its goal line, the risk trend,
headline KPIs, and tables of tickets, vulnerabilities, drift and the approved
exceptions (the read-only GRC view).
"""
from __future__ import annotations

import csv
from html import escape
from pathlib import Path
from typing import Any, Dict, List

from . import evaluation
from .store import from_iso

TABLES = ["risk_history", "tickets", "ticket_history", "vulnerabilities", "config_issues",
          "patch_jobs", "exceptions", "assessment_findings", "notifications"]


# -- CSV export for Power BI ------------------------------------------------
def export_csv(ctx) -> Path:
    out = ctx.root / "dashboard" / "data"
    out.mkdir(parents=True, exist_ok=True)
    for table in TABLES:
        rows = ctx.store.q(f"SELECT * FROM {table}")
        cols = [c["name"] for c in ctx.store.q(f"PRAGMA table_info({table})")]
        with open(out / f"{table}.csv", "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=cols)
            writer.writeheader()
            writer.writerows(rows)
    with open(out / "business_units.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["bu", "name", "head", "goal_line", "window_weekday", "window_start_hour", "window_hours"])
        for u in ctx.business_units:
            w = u["downtime_window"]
            writer.writerow([u["id"], u["name"], u["head"], u["goal_line"], w["weekday"], w["start_hour"], w["duration_hours"]])
    m = evaluation.metrics(ctx)
    with open(out / "kpis.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["area", "metric", "value"])
        for area in ("assessment", "drift", "vulnerabilities", "patching"):
            for key, value in m[area].items():
                if isinstance(value, (int, float)) or value is None:
                    writer.writerow([area, key, "" if value is None else value])
    return out


# -- HTML page ----------------------------------------------------------------
CSS = """
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;
--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--series:#2a78d6;--good:#0ca30c;--critical:#d03b3b;--warning:#fab219}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;
--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--series:#3987e5}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;
--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--series:#3987e5}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1120px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 2px}h2{font-size:15px;margin:0 0 12px}
.sub{color:var(--ink2);margin:0 0 20px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:16px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.tile .v{font-size:26px;font-weight:600}.tile .l{color:var(--ink2);font-size:12px}
.panels{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}
.panel h3{font-size:13px;margin:0 0 4px;font-weight:600}
svg{display:block;width:100%;height:auto;overflow:visible}
svg text{font:11px system-ui,-apple-system,"Segoe UI",sans-serif;fill:var(--muted)}
svg text.val{fill:var(--ink);font-weight:600}svg text.name{fill:var(--ink);font-size:12px}svg text.sec{fill:var(--ink2)}
.bar{fill:var(--series)}.line{fill:none;stroke:var(--series);stroke-width:2;stroke-linejoin:round}
.dot{fill:var(--series);stroke:var(--surface);stroke-width:2}.hit{fill:transparent}
.gridl{stroke:var(--grid);stroke-width:1}.axisl{stroke:var(--axis);stroke-width:1}
.goal{stroke:var(--ink);stroke-width:2}.goald{stroke:var(--ink2);stroke-width:1.5;stroke-dasharray:4 3}
.legend{display:flex;gap:16px;color:var(--ink2);font-size:12px;margin:0 0 8px;flex-wrap:wrap}
.legend i{display:inline-block;vertical-align:middle;margin-right:6px}
.tablewrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--grid);white-space:nowrap}
th{color:var(--ink2);font-weight:600}td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td.wrap{white-space:normal;min-width:220px}
.st{font-weight:600}.st.bad::before{content:"\\25B2 ";color:var(--critical)}.st.ok::before{content:"\\2713 ";color:var(--good)}
.st.wait::before{content:"\\25CF ";color:var(--warning)}
#tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--surface);padding:6px 9px;border-radius:6px;
font-size:12px;white-space:pre-line;display:none;z-index:9;max-width:260px}
.empty{color:var(--muted)}
:root{--before:#86b6ef}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--before:#184f95}}
:root[data-theme="dark"]{--before:#184f95}
.bar.before{fill:var(--before)}
.how{margin:0;padding-left:18px;color:var(--ink2)}.how li{margin-bottom:6px}.how b{color:var(--ink)}
.card .sub{margin:-6px 0 12px}
"""

JS = """
const tip=document.getElementById('tip');
document.addEventListener('mousemove',e=>{const t=e.target.closest('[data-tip]');
if(!t){tip.style.display='none';return}
tip.textContent=t.getAttribute('data-tip');tip.style.display='block';
const w=tip.offsetWidth,x=e.clientX+14+w>innerWidth?e.clientX-w-10:e.clientX+14;
tip.style.left=x+'px';tip.style.top=(e.clientY+14)+'px'});
"""


def _fmt(value: float) -> str:
    return f"{value:.1f}".rstrip("0").rstrip(".")


def _nice_max(value: float) -> float:
    for step in (10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000):
        if value <= step * 4:
            return step * (int(value / step) + 1)
    return value * 1.1


def _hbar(cls: str, x: float, y: float, w: float, h: float) -> str:
    if w >= 4:
        return f'<path class="{cls}" d="M{x},{y} h{w - 4:.1f} a4,4 0 0 1 4,4 v{h - 8} a4,4 0 0 1 -4,4 h-{w - 4:.1f} z"/>'
    return f'<rect class="{cls}" x="{x}" y="{y}" width="{max(w, 0):.1f}" height="{h}"/>'


def _bar_chart(latest: List[Dict[str, Any]], first: Dict[str, Dict[str, Any]]) -> str:
    """Risk per business unit at the first assessment and now, with its goal line."""
    W, row_h, left, right, bh = 720, 64, 170, 200, 18
    plot = W - left - right
    top = max(max(r["score"], r["goal_line"], first[r["bu"]]["score"]) for r in latest) or 1
    scale = plot / _nice_max(top)
    H = row_h * len(latest) + 8
    out = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Risk score before and now against the goal line for each business unit">']
    out.append(f'<line class="axisl" x1="{left}" y1="0" x2="{left}" y2="{H - 4}"/>')
    for i, r in enumerate(latest):
        f = first[r["bu"]]
        y = i * row_h + 12
        wb, wn = f["score"] * scale, r["score"] * scale
        gx = left + r["goal_line"] * scale
        above = r["score"] > r["goal_line"]
        tip = (f"{r['bu_name']} (goal line {_fmt(r['goal_line'])})\n"
               f"Before: risk {_fmt(f['score'])}, {f['open_vulns']} vulnerabilities, {f['open_config']} config issues\n"
               f"Now: risk {_fmt(r['score'])}, {r['open_vulns']} vulnerabilities, {r['open_config']} config issues")
        out.append(f'<g data-tip="{escape(tip)}">')
        out.append(f'<rect class="hit" x="0" y="{y - 10}" width="{W}" height="{row_h}"/>')
        out.append(f'<text class="name" x="{left - 10}" y="{y + bh + 5}" text-anchor="end">{escape(r["bu_name"])}</text>')
        out.append(_hbar("bar before", left, y, wb, bh))
        out.append(_hbar("bar", left, y + bh + 2, wn, bh))
        out.append(f'<line class="goal" x1="{gx:.1f}" y1="{y - 5}" x2="{gx:.1f}" y2="{y + 2 * bh + 7}"/>')
        out.append(f'<text class="val" x="{max(left + wb, gx) + 8:.1f}" y="{y + 13}">{_fmt(f["score"])}'
                   f'<tspan class="sec" font-weight="400"> before</tspan></text>')
        out.append(f'<text class="val" x="{max(left + wn, gx) + 8:.1f}" y="{y + bh + 15}">{_fmt(r["score"])}'
                   f'<tspan class="sec" font-weight="400"> now  '
                   f'{"&#9650; above goal" if above else "&#10003; within goal"} ({_fmt(r["goal_line"])})</tspan></text>')
        out.append("</g>")
    out.append("</svg>")
    return "".join(out)


def _trend_panel(unit: Dict[str, Any], hist: List[Dict[str, Any]], t0: float, t1: float, ymax: float) -> str:
    W, H, l, r, t, b = 300, 170, 30, 14, 12, 22
    pw, ph = W - l - r, H - t - b
    span = max(t1 - t0, 1.0)

    def X(ts: float) -> float:
        return l + (ts - t0) / span * pw

    def Y(v: float) -> float:
        return t + ph - v / ymax * ph

    out = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Risk trend for {escape(unit["name"])}">']
    for tick in (0, ymax / 2, ymax):
        out.append(f'<line class="{"axisl" if tick == 0 else "gridl"}" x1="{l}" y1="{Y(tick):.1f}" x2="{W - r}" y2="{Y(tick):.1f}"/>')
        out.append(f'<text x="{l - 6}" y="{Y(tick) + 4:.1f}" text-anchor="end">{_fmt(tick)}</text>')
    gy = Y(unit["goal_line"])
    out.append(f'<line class="goald" x1="{l}" y1="{gy:.1f}" x2="{W - r}" y2="{gy:.1f}"/>')
    out.append(f'<text class="sec" x="{W - r}" y="{gy - 5:.1f}" text-anchor="end">goal {_fmt(unit["goal_line"])}</text>')
    pts = [(X(from_iso(h["at"]).timestamp()), Y(h["score"]), h) for h in hist]
    if len(pts) > 1:
        out.append('<polyline class="line" points="' + " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts) + '"/>')
    for x, y, h in pts:
        tip = f"{h['at'][:16].replace('T', ' ')} UTC\nRisk {_fmt(h['score'])}" + (f"\n{h['label']}" if h["label"] else "")
        out.append(f'<g data-tip="{escape(tip)}"><circle class="hit" cx="{x:.1f}" cy="{y:.1f}" r="11"/>'
                   f'<circle class="dot" cx="{x:.1f}" cy="{y:.1f}" r="4"/></g>')
    if pts:
        x, y, h = pts[-1]
        out.append(f'<text class="val" x="{x:.1f}" y="{y - 9:.1f}" text-anchor="end">{_fmt(h["score"])}</text>')
        out.append(f'<text x="{l}" y="{H - 5}">{hist[0]["at"][5:10]}</text>')
        out.append(f'<text x="{W - r}" y="{H - 5}" text-anchor="end">{hist[-1]["at"][5:10]}</text>')
    out.append("</svg>")
    return "".join(out)


def _table(headers: List[str], rows: List[List[Any]], numeric: List[int] = (), wrap: List[int] = ()) -> str:
    if not rows:
        return '<p class="empty">Nothing to show.</p>'
    head = "".join(f'<th class="{"num" if i in numeric else ""}">{escape(h)}</th>' for i, h in enumerate(headers))
    body = []
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            cls = "num" if i in numeric else ("wrap" if i in wrap else "")
            text = cell if isinstance(cell, str) and cell.startswith("<span") else escape("" if cell is None else str(cell))
            cells.append(f'<td class="{cls}">{text}</td>')
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f'<div class="tablewrap"><table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


def _status(text: str, kind: str) -> str:
    return f'<span class="st {kind}">{escape(text)}</span>'


def build_html(ctx) -> Path:
    store = ctx.store
    now = store.now()
    m = evaluation.metrics(ctx)
    names = {u["id"]: u["name"] for u in ctx.business_units}

    latest = []
    for unit in ctx.business_units:
        row = store.one("SELECT * FROM risk_history WHERE bu = ? ORDER BY id DESC LIMIT 1", (unit["id"],))
        if row:
            latest.append(row)
    history = store.q("SELECT * FROM risk_history ORDER BY id")

    def show(value: Any, suffix: str = "") -> str:
        return "n/a" if value is None else f"{_fmt(value) if isinstance(value, float) else value}{suffix}"

    v, p, d, a = m["vulnerabilities"], m["patching"], m["drift"], m["assessment"]
    first = {}
    for h in history:
        first.setdefault(h["bu"], h)
    befores = list(first.values())
    arrow = " → "
    tiles = [
        (f"{sum(1 for r in befores if r['score'] > r['goal_line'])}{arrow}{sum(1 for r in latest if r['score'] > r['goal_line'])}",
         "business units above goal line, before and now"),
        (f"{_fmt(sum(r['score'] for r in befores))}{arrow}{_fmt(sum(r['score'] for r in latest))}",
         "total risk score, before and now"),
        (f"{sum(r['open_vulns'] for r in befores)}{arrow}{v['open']}", "open vulnerabilities, before and now"),
        (f"{sum(r['open_config'] for r in befores)}{arrow}{sum(r['open_config'] for r in latest)}",
         "configuration issues, before and now"),
        (show(v["open_past_deadline"]), "open past deadline"),
        (show(v["fixed_within_deadline_pct"], "%"), "fixed within deadline"),
        (show(p["patch_success_rate_pct"], "%"), "patch success rate"),
        (show(p["rollback_rate_pct"], "%"), "rollback rate"),
        (show(d["mean_time_to_detect_min"], " min"), "mean time to detect drift"),
        (show(d["mean_time_to_remediate_min_auto"], " min"), "mean time to auto-remediate drift"),
    ]
    if "detection_rate_pct" in a:
        tiles.append((show(a["detection_rate_pct"], "%"), "planted issues detected"))

    parts: List[str] = []
    parts.append(f"<h1>{escape(ctx.company['company'])}: security posture</h1>")
    parts.append(f'<p class="sub">Risk per business unit against the goal line set by leadership. '
                 f'Data as of {now:%d %b %Y %H:%M} UTC, provider {escape(ctx.provider.name)}.</p>')
    parts.append('<div class="tiles">' + "".join(
        f'<div class="tile"><div class="v">{escape(val)}</div><div class="l">{escape(label)}</div></div>'
        for val, label in tiles) + "</div>")

    parts.append(
        '<div class="card"><h2>How to read this page</h2><ul class="how">'
        '<li><b>Risk score</b>: one number per business unit. Every unpatched vulnerability and every broken security '
        'setting adds to it; serious, internet-facing and overdue items add more. Lower is better.</li>'
        '<li><b>Goal line</b>: the most risk leadership accepts for that unit. Above the line, the unit head is alerted.</li>'
        '<li><b>Before</b> is the first assessment, when nothing had been fixed. <b>Now</b> is the latest measurement. '
        'If "now" is 0, everything found has been fixed.</li></ul></div>')

    if latest:
        parts.append('<div class="card"><h2>Risk score before and now, against the goal line</h2>'
                     '<div class="legend"><span><i style="width:14px;height:10px;border-radius:2px;background:var(--before)"></i>Before (first assessment)</span>'
                     '<span><i style="width:14px;height:10px;border-radius:2px;background:var(--series)"></i>Now</span>'
                     '<span><i style="width:2px;height:14px;background:var(--ink)"></i>Goal line</span></div>'
                     + _bar_chart(latest, first) + "</div>")
        stages = []
        for h in history:
            if not stages or stages[-1]["at"] != h["at"]:
                stages.append({"at": h["at"], "label": h["label"], "scores": {}})
            stages[-1]["scores"][h["bu"]] = h
        stage_rows = []
        for s in stages:
            cells = [s["at"][:16].replace("T", " "), s["label"] or "Risk check"]
            for unit in ctx.business_units:
                h = s["scores"].get(unit["id"])
                cells.append("" if h is None else _status(_fmt(h["score"]), "bad" if h["score"] > h["goal_line"] else "ok"))
            stage_rows.append(cells)
        parts.append('<div class="card"><h2>What happened, step by step</h2>'
                     '<p class="sub">Risk score of each business unit after each stage. &#9650; means above its goal line, &#10003; means within it.</p>'
                     + _table(["When (UTC)", "Stage"] + [u["name"] for u in ctx.business_units], stage_rows,
                              numeric=list(range(2, 2 + len(ctx.business_units)))) + "</div>")
        t0 = from_iso(history[0]["at"]).timestamp()
        t1 = from_iso(history[-1]["at"]).timestamp()
        ymax = _nice_max(max(max(h["score"] for h in history), max(u["goal_line"] for u in ctx.business_units)))
        panels = []
        for unit in ctx.business_units:
            hist = [h for h in history if h["bu"] == unit["id"]]
            panels.append(f'<div class="panel"><h3>{escape(unit["name"])}</h3>{_trend_panel(unit, hist, t0, t1, ymax)}</div>')
        parts.append('<div class="card"><h2>Risk over time, before and after remediation</h2>'
                     '<div class="legend"><span><i style="width:14px;height:2px;background:var(--series)"></i>Risk score</span>'
                     '<span><i style="width:14px;border-top:2px dashed var(--ink2)"></i>Goal line</span>'
                     '<span>All panels share one scale</span></div>'
                     f'<div class="panels">{"".join(panels)}</div></div>')
        rows = []
        for r in latest:
            first = next(h for h in history if h["bu"] == r["bu"])
            ok = r["score"] <= r["goal_line"]
            rows.append([r["bu_name"], _fmt(first["score"]), _fmt(r["score"]), _fmt(r["goal_line"]),
                         r["open_vulns"], r["overdue_vulns"], r["open_config"],
                         _status("Within goal" if ok else "Above goal", "ok" if ok else "bad")])
        parts.append('<div class="card"><h2>Business unit summary</h2>' + _table(
            ["Business unit", "Initial risk", "Current risk", "Goal line", "Open vulnerabilities", "Past deadline",
             "Config issues", "Status"], rows, numeric=[1, 2, 3, 4, 5, 6]) + "</div>")
    else:
        parts.append('<div class="card"><p class="empty">No risk has been computed yet. Run <code>python -m cspm risk</code>.</p></div>')

    tickets = store.q("SELECT * FROM tickets WHERE status != 'closed' ORDER BY due_at")
    parts.append(f'<div class="card"><h2>Open tickets ({len(tickets)})</h2>' + _table(
        ["Ticket", "Title", "Business unit", "Assignee", "Severity", "Due", "Status"],
        [[t["id"], t["title"], names.get(t["bu"], t["bu"]), t["assignee"], t["severity"], (t["due_at"] or "")[:10],
          _status(t["status"].replace("_", " ") + (", overdue" if t["due_at"] and from_iso(t["due_at"]) < now else ""),
                  "bad" if t["due_at"] and from_iso(t["due_at"]) < now else "wait")] for t in tickets], wrap=[1]) + "</div>")

    vulns = store.q("SELECT * FROM vulnerabilities ORDER BY status DESC, cvss DESC")
    parts.append(f'<div class="card"><h2>Vulnerabilities ({len(vulns)})</h2>' + _table(
        ["CVE", "Server", "Business unit", "Severity", "CVSS", "Found", "Deadline", "Fixed", "Status"],
        [[x["cve"], x["server_name"], names.get(x["bu"], x["bu"]), x["severity"], x["cvss"], x["first_seen"][:10],
          x["due_at"][:10], (x["fixed_at"] or "")[:10],
          _status("fixed", "ok") if x["status"] == "fixed" else
          _status("open, overdue" if from_iso(x["due_at"]) < now else "open", "bad" if from_iso(x["due_at"]) < now else "wait")]
         for x in vulns], numeric=[4]) + "</div>")

    issues = store.q("SELECT * FROM config_issues WHERE kind = 'drift' ORDER BY id DESC")
    parts.append(f'<div class="card"><h2>Configuration drift ({len(issues)})</h2>' + _table(
        ["Control", "Resource", "Business unit", "Changed by", "Changed at", "Detected at", "Handling", "Status"],
        [[i["control_id"], i["resource_name"], names.get(i["bu"], i["bu"]), i["actor"] or "unknown",
          (i["changed_at"] or "")[:16].replace("T", " "), i["detected_at"][:16].replace("T", " "), i["remediation_mode"],
          _status(i["status"].replace("_", " "), "ok" if i["status"] == "remediated" else "wait")] for i in issues]) + "</div>")

    exc = store.q("SELECT * FROM exceptions ORDER BY id")
    parts.append(f'<div class="card"><h2>Approved exceptions, GRC view ({len(exc)})</h2>' + _table(
        ["Control", "Resource", "Business unit", "Reason", "Approved by", "Approved", "Expires"],
        [[e["control_id"], e["resource_name"], names.get(e["bu"], e["bu"]), e["reason"], e["approved_by"],
          e["approved_at"][:10], e["expires_at"][:10]] for e in exc], wrap=[3]) + "</div>")

    jobs = store.q("SELECT * FROM patch_jobs ORDER BY id DESC")
    parts.append(f'<div class="card"><h2>Patch jobs ({len(jobs)})</h2>' + _table(
        ["Job", "Server", "Mode", "Started", "Tickets closed", "Result", "Steps"],
        [[j["id"], j["server_name"], j["mode"], j["started_at"][:16].replace("T", " "), j["fixed_count"],
          _status(j["status"].replace("_", " "), "ok" if j["status"] == "success" else "bad"), j["detail"]]
         for j in jobs], numeric=[4], wrap=[6]) + "</div>")

    html = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>CSPM dashboard</title><style>{CSS}</style></head><body><main>"
            + "".join(parts) + f'</main><div id="tip"></div><script>{JS}</script></body></html>')
    out = ctx.root / "dashboard" / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out


def build(ctx) -> Path:
    export_csv(ctx)
    return build_html(ctx)
