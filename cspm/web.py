"""Web console.

    python3 -m cspm web            ->  http://localhost:8770

A small standard-library HTTP server in front of the same engine the CLI uses.
GET /api/state returns everything the console shows; POST /api/action runs one
engine operation (scan, approve, patch, ...). The page itself is static and
lives in cspm/webui/.

On the mock provider the console also drives the simulation: it can change a
setting as a named user, move the clock, and play the full scenario.
"""
from __future__ import annotations

import json
import os
import threading
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple

from . import assessment, demo, drift, evaluation, itsm, patch, risk, scheduler, vuln
from .checks import evaluate
from .context import ROOT, Context
from .store import from_iso, to_iso

UI_DIR = Path(__file__).resolve().parent / "webui"
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}
LOCK = threading.Lock()
SEV_ORDER = {"zero-day": 0, "critical": 1, "high": 2, "medium": 3, "low": 4}


def _state_dir() -> Path:
    return Path(os.environ.get("CSPM_STATE") or ROOT / "state")


def _reset_files() -> None:
    for name in ("cspm.db", "mock_env.json", "outbox.log"):
        path = _state_dir() / name
        if path.exists():
            path.unlink()


def _snapshot(ctx) -> Dict[str, Any]:
    """Live on the mock provider; cached on AWS, where a snapshot is many API calls."""
    if ctx.provider.name == "mock":
        return ctx.provider.snapshot()
    cached = ctx.store.get_meta("last_snapshot")
    if not cached:                      # first load on a live account: read it once, then reuse
        _refresh_snapshot(ctx)
        cached = ctx.store.get_meta("last_snapshot")
    return json.loads(cached)


def _refresh_snapshot(ctx) -> None:
    if ctx.provider.name != "mock":
        ctx.store.set_meta("last_snapshot", json.dumps(ctx.provider.snapshot()))


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
def build_state(ctx) -> Dict[str, Any]:
    store = ctx.store
    now = store.now()
    mock = ctx.provider.name == "mock"
    snap = _snapshot(ctx)
    names = {u["id"]: u["name"] for u in ctx.business_units}

    vulns = store.q("SELECT * FROM vulnerabilities ORDER BY status DESC, cvss DESC")
    for v in vulns:
        v["risk"] = round(risk.vuln_risk(ctx, v, now), 1) if v["status"] == "open" else 0
        v["overdue"] = v["status"] == "open" and from_iso(v["due_at"]) < now
    issues = store.q("SELECT * FROM config_issues ORDER BY id DESC")
    tickets = store.q("SELECT * FROM tickets ORDER BY id DESC")
    hist = defaultdict(list)
    for h in store.q("SELECT * FROM ticket_history ORDER BY id"):
        hist[h["ticket_id"]].append({"at": h["at"], "status": h["status"], "note": h["note"]})
    for t in tickets:
        t["history"] = hist[t["id"]]
        t["overdue"] = t["status"] != "closed" and bool(t["due_at"]) and from_iso(t["due_at"]) < now
    jobs = store.q("SELECT * FROM patch_jobs ORDER BY id DESC")

    # Business units: live risk, history, window, queue
    live = {r["bu"]: r for r in risk.compute(ctx, record=False, alert=False)}
    history = store.q("SELECT at, label, bu, score FROM risk_history ORDER BY id")
    plan = {p["bu"]: p for p in scheduler.plan(ctx)}
    bus = []
    for u in ctx.business_units:
        p, r = plan[u["id"]], live[u["id"]]
        bus.append({
            "id": u["id"], "name": u["name"], "head": u["head"], "goal_line": u["goal_line"],
            "window": u["downtime_window"], "next_start": to_iso(p["start"]), "next_end": to_iso(p["end"]),
            "window_open": p["open"], "held": p["held"]["reason"] if p["held"] else None,
            "score": r["score"], "vuln_score": r["vuln_score"], "config_score": r["config_score"],
            "open_vulns": r["open_vulns"], "overdue_vulns": r["overdue_vulns"], "open_config": r["open_config"],
            "history": [{"at": h["at"], "label": h["label"], "score": h["score"]} for h in history if h["bu"] == u["id"]],
            "queue": [{"server": q["server_name"], "tickets": q["tickets"], "risk": round(q["risk"], 1)} for q in p["queue"]],
        })

    # Servers
    servers = []
    for inst in snap.get("instances", []):
        mine = [v for v in vulns if v["instance_id"] == inst["id"] and v["status"] == "open"]
        last = next((j for j in jobs if j["instance_id"] == inst["id"]), None)
        servers.append({
            "id": inst["id"], "name": inst["name"], "bu": inst["bu"], "bu_name": names.get(inst["bu"], inst["bu"]),
            "owner": inst.get("owner", ""), "criticality": inst.get("criticality", ""),
            "internet_facing": bool(inst.get("internet_facing")), "services": inst.get("services", []),
            "open_vulns": len(mine), "risk": round(sum(v["risk"] for v in mine), 1),
            "worst": min((v["severity"] for v in mine), key=lambda s: SEV_ORDER[s]) if mine else None,
            "last_job": {"status": last["status"], "at": last["finished_at"]} if last else None,
        })

    # MBSS controls with current compliance
    counts: Dict[str, Counter] = defaultdict(Counter)
    for c in store.q("SELECT control_id, status FROM compliance"):
        counts[c["control_id"]][c["status"]] += 1
    controls = [{
        "id": c["id"], "cis_ref": c["cis_ref"], "title": c["title"], "domain": c["domain"],
        "severity": c["severity"], "accepted": c.get("accepted", True),
        "exclusion_reason": c.get("exclusion_reason", ""), "mode": c["remediation"]["mode"],
        "recommendation": c["recommendation"], "counts": dict(counts[c["id"]]),
    } for c in ctx.all_controls()]

    # Assessment (latest run)
    run_id = int(store.get_meta("assessment_runs", "0"))
    findings = store.q("SELECT * FROM assessment_findings WHERE run_id = ? ORDER BY id", (run_id,))
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["control_id"]))
    by_domain: List[Dict[str, Any]] = []
    assessed_vulns: List[Dict[str, Any]] = []
    report = ROOT / "reports" / "assessment_report.json"
    if run_id and report.exists():
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
            if findings and data.get("at") == findings[0]["created_at"]:
                by_domain = [{"domain": d, "checks": s.get("checks", 0), "passed": s.get("passed", 0),
                              "controls": s.get("controls", 0)} for d, s in data["stats"].items()]
                by_domain.sort(key=lambda d: assessment.DOMAINS.index(d["domain"]) if d["domain"] in assessment.DOMAINS else 9)
                assessed_vulns = data.get("vulnerabilities", [])
        except (ValueError, KeyError):
            pass

    # Things the simulation can break: compliant resources of auto/approval controls
    targets = []
    if mock and store.get_meta("baseline_applied_at"):
        for c in ctx.mbss_controls():
            ok = [{"id": r["resource_id"], "name": r["resource_name"]} for r in evaluate(c, snap) if r["compliant"]]
            if ok:
                targets.append({"id": c["id"], "title": c["title"], "mode": c["remediation"]["mode"], "resources": ok})

    return {
        "company": ctx.company["company"], "provider": ctx.provider.name, "simulated": bool(store.get_meta("sim_now")),
        "now": to_iso(now), "mbss": {"name": ctx.mbss["name"], "source": ctx.mbss["source"], "signed_off_by": ctx.mbss["signed_off_by"]},
        "lifecycle": {
            "assessed": run_id > 0, "baseline": bool(store.get_meta("baseline_applied_at")),
            "vulns_scanned": bool(vulns), "patched": bool(jobs),
            "drift_seen": any(i["kind"] == "drift" for i in issues),
        },
        "inventory": {"servers": len(snap.get("instances", [])), "buckets": len(snap.get("s3_buckets", [])),
                      "users": len(snap.get("iam_users", [])), "security_groups": len(snap.get("security_groups", [])),
                      "vpcs": len(snap.get("vpcs", [])), "trails": len(snap.get("trails", []))},
        "bus": bus, "servers": servers, "controls": controls,
        "assessment": {"run_id": run_id, "at": findings[0]["created_at"] if findings else None,
                       "findings": findings, "by_domain": by_domain, "vulnerabilities": assessed_vulns},
        "issues": issues, "exceptions": store.q("SELECT * FROM exceptions ORDER BY id DESC"),
        "tickets": tickets, "vulns": vulns, "jobs": jobs,
        "notifications": store.q("SELECT * FROM notifications ORDER BY id DESC LIMIT 200"),
        "feed": _feed(ctx, issues, vulns, jobs)[:60],
        "metrics": evaluation.metrics(ctx),
        "sla_days": ctx.settings["sla_days"], "risk_settings": ctx.settings["risk"],
        "drift_targets": targets,
        "actors": [u["name"] for u in snap.get("iam_users", [])] if mock else [],
    }


def _feed(ctx, issues, vulns, jobs) -> List[Dict[str, Any]]:
    """Activity timeline assembled from what the engine recorded."""
    out: List[Dict[str, Any]] = []
    store = ctx.store
    for r in store.q("SELECT run_id, created_at, COUNT(*) AS n FROM assessment_findings GROUP BY run_id"):
        out.append({"at": r["created_at"], "kind": "assessment", "text": f"Assessment run {r['run_id']} found {r['n']} configuration gaps"})
    base = [i for i in issues if i["kind"] == "baseline_gap"]
    if base:
        auto = sum(1 for i in base if i["remediation_mode"] == "auto")
        out.append({"at": min(i["detected_at"] for i in base), "kind": "baseline",
                    "text": f"MBSS implemented: {auto} settings fixed automatically, {len(base) - auto} sent for approval"})
    for i in issues:
        if i["kind"] == "drift":
            out.append({"at": i["detected_at"], "kind": "drift",
                        "text": f"Drift on {i['resource_name']} ({i['control_id']}), changed by {i['actor'] or 'an unknown user'}"})
            if i["remediated_at"]:
                how = "automatically" if i["remediation_mode"] == "auto" else "after approval"
                out.append({"at": i["remediated_at"], "kind": "fix", "text": f"{i['control_id']} restored on {i['resource_name']} {how}"})
        elif i["remediated_at"] and i["remediation_mode"] == "approval":
            out.append({"at": i["remediated_at"], "kind": "fix", "text": f"{i['control_id']} fixed on {i['resource_name']} after approval"})
    seen: Dict[Tuple[str, str], int] = Counter((v["first_seen"], v["server_name"]) for v in vulns)
    for (at, server), n in seen.items():
        out.append({"at": at, "kind": "vuln", "text": f"{n} vulnerabilit{'y' if n == 1 else 'ies'} found on {server}; tickets raised"})
    for j in jobs:
        if j["finished_at"]:
            text = (f"{j['server_name']} patched ({j['mode']}): {j['fixed_count']} tickets closed" if j["status"] == "success"
                    else f"Patching {j['server_name']} failed its health check; rolled back, tickets reopened")
            out.append({"at": j["finished_at"], "kind": "patch" if j["status"] == "success" else "rollback", "text": text})
    for e in store.q("SELECT * FROM exceptions"):
        out.append({"at": e["approved_at"], "kind": "exception",
                    "text": f"{e['approved_by']} accepted the risk for {e['control_id']} on {e['resource_name']}"})
    for n in store.q("SELECT at, subject FROM notifications WHERE subject LIKE '%goal line%'"):
        out.append({"at": n["at"], "kind": "alert", "text": n["subject"]})
    out.sort(key=lambda e: e["at"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
def run_action(name: str, p: Dict[str, Any]) -> str:
    if name in ("reset", "demo"):
        _reset_files()
    ctx = Context(quiet=True)
    try:
        mock = ctx.provider.name == "mock"
        store = ctx.store
        label = ""
        if name == "reset":
            if mock:
                store.set_now(datetime.now(timezone.utc).replace(second=0, microsecond=0))
            return "Everything was reset. The company is back to its original state."
        if name == "demo":
            if not mock:
                raise RuntimeError("The scripted scenario only runs in simulation")
            demo.run(ctx)
            return "Played the full two-week scenario (5 to 19 January 2026)."

        if name == "assess":
            _refresh_snapshot(ctx)
            a = assessment.run(ctx)
            msg, label = f"Assessment complete: {len(a['findings'])} configuration gaps, {len(a['vulnerabilities'])} server vulnerabilities.", "Assessment"
        elif name == "baseline":
            b = drift.baseline_apply(ctx)
            _refresh_snapshot(ctx)
            msg, label = (f"MBSS implemented: {len(b['auto_fixed'])} settings fixed automatically, "
                          f"{len(b['tickets'])} sensitive settings sent for approval."), "MBSS implemented"
        elif name == "vuln_scan":
            v = vuln.scan(ctx)
            msg, label = f"Scan complete: {v['new']} new tickets, {v['fixed']} confirmed fixed.", "Vulnerability scan"
        elif name == "drift_scan":
            s = drift.scan(ctx)
            _refresh_snapshot(ctx)
            msg, label = (f"Drift scan: {len(s['new'])} changes found, {len(s['auto_fixed'])} restored automatically, "
                          f"{len(s['tickets'])} waiting for approval."), "Drift scan"
        elif name == "inject_drift":
            if not mock:
                raise RuntimeError("In live mode, make the change in the AWS console instead")
            ev = ctx.provider.violate(ctx.control(p["control"]), p["resource"], p.get("actor") or "dev-priya")
            store.advance(minutes=4)   # a few minutes pass before the next scan notices
            return f"{ev['user']} called {ev['event_name']} on {p['resource']}. Run a drift scan to see it caught."
        elif name == "decide":
            msg, label = drift.decide(ctx, p["ticket"], p["decision"], reason=p.get("reason", "")), "Approval decision"
        elif name == "patch_now":
            job = patch.patch_server(ctx, p["server"], mode="self-service")
            msg = ("Nothing to patch on this server." if job is None else
                   f"{job['server_name']}: {job['status'].replace('_', ' ')}. {job['detail']}")
            label = "Self-service patch"
        elif name == "hold":
            scheduler.hold(ctx, p["bu"], p.get("reason") or "Business declined downtime")
            msg = f"{ctx.bu(p['bu'])['name']}: downtime is on hold. Scheduled patching will skip this unit."
        elif name == "release":
            scheduler.release(ctx, ctx.bu(p["bu"])["id"])
            msg = f"{ctx.bu(p['bu'])['name']}: downtime released."
        elif name == "advance":
            if not mock:
                raise RuntimeError("The clock can only be moved in simulation")
            store.advance(hours=float(p.get("hours", 0)), days=float(p.get("days", 0)))
            msg, label = f"Clock moved to {store.now():%a %d %b %Y %H:%M} UTC.", "Time passed"
        elif name == "next_window":
            unit = ctx.bu(p["bu"])
            if mock:
                start, _ = scheduler.window_for(unit, store.now())
                if start > store.now():
                    store.set_now(start)
            entry = scheduler.run(ctx, only_bu=unit["id"], force=not mock)[0]
            done = "; ".join(f"{j['server_name']} {j['status'].replace('_', ' ')}" for j in entry["jobs"])
            msg, label = f"{unit['name']}: {entry['status']}" + (f". {done}" if done else ""), f"{unit['name']} window"
        elif name == "run_windows":
            results = scheduler.run(ctx)
            ran = [f"{e['name']}: " + ", ".join(f"{j['server_name']} {j['status'].replace('_', ' ')}" for j in e["jobs"])
                   for e in results if e["jobs"]]
            msg, label = ("; ".join(ran) or "No downtime window with work to do is open right now."), "Scheduled patching"
        else:
            raise ValueError(f"unknown action {name!r}")

        if label:
            risk.compute(ctx, label=label)
        return msg
    finally:
        ctx.close()


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # keep the terminal quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: Any) -> None:
        self._send(code, json.dumps(payload).encode("utf-8"), "application/json")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/state":
            with LOCK:
                ctx = Context(quiet=True)
                try:
                    self._json(200, build_state(ctx))
                except Exception as exc:
                    self._json(500, {"error": str(exc)})
                finally:
                    ctx.close()
            return
        name = "index.html" if path == "/" else path.lstrip("/")
        file = (UI_DIR / name).resolve()
        if UI_DIR.resolve() not in file.parents or not file.is_file():
            self._send(404, b"not found", "text/plain")
            return
        self._send(200, file.read_bytes(), MIME.get(file.suffix, "application/octet-stream"))

    def do_POST(self):
        if self.path != "/api/action":
            self._send(404, b"not found", "text/plain")
            return
        # Only accept requests made by the console itself, from this machine.
        origin = self.headers.get("Origin", "")
        if origin and not origin.startswith(("http://localhost", "http://127.0.0.1")):
            self._json(403, {"ok": False, "message": "forbidden"})
            return
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            with LOCK:
                message = run_action(body.get("action", ""), body.get("params") or {})
            self._json(200, {"ok": True, "message": message})
        except Exception as exc:
            text = exc.args[0] if exc.args else str(exc)
            self._json(200, {"ok": False, "message": str(text)})


def serve(port: int = 8770) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"CSPM console: http://localhost:{port}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
