"""Command line interface:  python -m cspm <command>"""
from __future__ import annotations

import argparse
import os
import time
from pathlib import Path
from typing import List, Optional

from . import assessment, dashboard, demo, drift, evaluation, itsm, patch, risk, scheduler, vuln
from .context import ROOT, Context
from .store import from_iso


def _state_dir() -> Path:
    return Path(os.environ.get("CSPM_STATE") or ROOT / "state")


def _reset_state() -> None:
    for name in ("cspm.db", "mock_env.json", "outbox.log"):
        path = _state_dir() / name
        if path.exists():
            path.unlink()


def _table(rows: List[List[str]], headers: List[str]) -> None:
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)] if rows else [len(h) for h in headers]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)))
    for row in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(row, widths)))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cspm", description="Cloud Security Posture Management for mid-range firms")
    p.add_argument("--provider", choices=["mock", "aws", "recorded"],
                   help="mock = simulation, aws = live account, recorded = read-only view of a past live run")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="reset all state (and the simulated company, on the mock provider)")
    sp.add_argument("--start", help="start a simulated clock at this UTC time, e.g. 2026-01-05T09:00:00Z")

    sub.add_parser("demo", help="run the full two-week scenario on the simulated company")
    sp = sub.add_parser("web", help="start the web console at http://localhost:8770")
    sp.add_argument("--port", type=int, default=8770)
    sp.add_argument("--state", help="state folder to use (keeps live AWS data apart from the simulation)")
    sub.add_parser("assess", help="one-time assessment across the five security domains")

    sp = sub.add_parser("baseline", help="implement the MBSS on all resources")
    sp.add_argument("action", choices=["apply"])

    sp = sub.add_parser("drift", help="drift detection, attribution and remediation")
    dsub = sp.add_subparsers(dest="action", required=True)
    dsub.add_parser("scan")
    dsub.add_parser("list")
    w = dsub.add_parser("watch", help="scan when the cloud reports a change, and at least every --interval seconds")
    w.add_argument("--interval", type=int, default=300)
    d = dsub.add_parser("decide", help="approve the restore of a sensitive setting, or accept the risk")
    d.add_argument("ticket")
    d.add_argument("decision", choices=["restore", "accept"])
    d.add_argument("--reason", default="")
    d.add_argument("--by", default="")

    sp = sub.add_parser("vuln", help="vulnerability intake")
    sp.add_argument("action", choices=["scan", "list", "rescore"])

    sp = sub.add_parser("tickets", help="list ITSM tickets")
    sp.add_argument("--all", action="store_true", help="include closed tickets")
    sp.add_argument("--bu")
    sp = sub.add_parser("ticket", help="show one ticket with its history")
    sp.add_argument("id")

    sp = sub.add_parser("patch", help="patching")
    psub = sp.add_subparsers(dest="action", required=True)
    n = psub.add_parser("now", help="self-service: patch one server immediately")
    n.add_argument("--server", required=True, help="server name or instance id")
    s = psub.add_parser("schedule", help="patch every business unit whose downtime window is open now")
    s.add_argument("--bu")
    s.add_argument("--force", action="store_true", help="open an agreed out-of-schedule window now")
    psub.add_parser("plan", help="show the next window and patch queue of each business unit")

    sp = sub.add_parser("window", help="put a business unit's downtime on hold, or release it")
    sp.add_argument("action", choices=["hold", "release"])
    sp.add_argument("--bu", required=True)
    sp.add_argument("--reason", default="Business declined downtime")

    sp = sub.add_parser("risk", help="compute risk per business unit and alert units above their goal line")
    sp.add_argument("--label", default="")

    sub.add_parser("dashboard", help="write dashboard/index.html and the CSV files for Power BI")
    sub.add_parser("evaluate", help="write reports/evaluation.md")

    sp = sub.add_parser("nvd", help="NVD cache")
    sp.add_argument("action", choices=["refresh"])

    sp = sub.add_parser("simulate", help="mock provider only: change a controlled setting as a named user")
    sp.add_argument("what", choices=["drift"])
    sp.add_argument("--control", required=True)
    sp.add_argument("--resource", required=True)
    sp.add_argument("--actor", default="dev-priya")

    sp = sub.add_parser("clock", help="simulated clock")
    csub = sp.add_subparsers(dest="action", required=True)
    csub.add_parser("show")
    csub.add_parser("clear", help="go back to real time")
    c = csub.add_parser("set")
    c.add_argument("when", help="UTC time, e.g. 2026-01-05T09:00:00Z")
    c = csub.add_parser("advance")
    c.add_argument("--days", type=float, default=0)
    c.add_argument("--hours", type=float, default=0)
    c.add_argument("--minutes", type=float, default=0)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "web":
        if args.provider:
            os.environ["CSPM_PROVIDER"] = args.provider
        if args.state:
            os.environ["CSPM_STATE"] = args.state
        from . import web
        web.serve(args.port)
        return 0
    if args.cmd in ("init", "demo"):
        _reset_state()
    ctx = Context(provider_name=args.provider)
    try:
        return _dispatch(ctx, args) or 0
    except (KeyError, RuntimeError, ValueError) as exc:
        print(f"error: {exc.args[0] if exc.args else exc}")
        return 1
    finally:
        ctx.close()


def _dispatch(ctx: Context, args: argparse.Namespace) -> int:
    store = ctx.store

    if args.cmd == "init":
        if args.start:
            store.set_now(from_iso(args.start))
        print(f"State reset in {ctx.state_dir}. Provider: {ctx.provider.name}. Clock: {store.now_iso()}")

    elif args.cmd == "demo":
        demo.run(ctx)

    elif args.cmd == "assess":
        a = assessment.run(ctx)
        print(f"{len(a['findings'])} configuration gaps, {len(a['vulnerabilities'])} server vulnerabilities")
        _table([[f["severity"], f["control_id"], f["resource_name"], f["detail"]] for f in a["findings"]],
               ["SEVERITY", "CONTROL", "RESOURCE", "GAP"])
        print(f"\nReport: {a['report']}")

    elif args.cmd == "baseline":
        b = drift.baseline_apply(ctx)
        print(f"{b['checked']} checks: {b['compliant']} compliant, {len(b['auto_fixed'])} fixed automatically, "
              f"{len(b['tickets'])} ticketed for approval ({', '.join(b['tickets']) or 'none'})")
        for issue_id, why in b["failed"]:
            print(f"  ! issue {issue_id} not fixed: {why}")

    elif args.cmd == "drift":
        if args.action == "scan":
            _print_drift(ctx, drift.scan(ctx))
        elif args.action == "list":
            _table([[d["id"], d["kind"], d["control_id"], d["resource_name"], d["actor"] or "-", d["changed_at"] or "-",
                     d["detected_at"], d["status"], d["ticket_id"] or "-"] for d in drift.issues(ctx)],
                   ["ID", "KIND", "CONTROL", "RESOURCE", "CHANGED BY", "CHANGED AT", "DETECTED AT", "STATUS", "TICKET"])
        elif args.action == "decide":
            print(drift.decide(ctx, args.ticket, args.decision, by=args.by, reason=args.reason))
        elif args.action == "watch":
            print(f"Watching for drift (full scan at least every {args.interval}s). Ctrl-C to stop.")
            last = 0.0
            try:
                while True:
                    events = ctx.provider.poll_drift_events()
                    if events or time.time() - last >= args.interval:
                        if events:
                            print(f"{store.now_iso()} {len(events)} change event(s) received")
                        _print_drift(ctx, drift.scan(ctx))
                        risk.compute(ctx, label="drift watch")
                        last = time.time()
                    else:
                        time.sleep(5)
            except KeyboardInterrupt:
                print("stopped")

    elif args.cmd == "vuln":
        if args.action == "rescore":
            print(f"{vuln.rescore(ctx)} open vulnerabilities rescored from the NVD cache")
        if args.action == "scan":
            v = vuln.scan(ctx)
            print(f"{v['reported']} reported by the scanner: {v['new']} new ticket(s), {v['fixed']} confirmed fixed")
        rows = store.q("SELECT * FROM vulnerabilities ORDER BY status DESC, cvss DESC")
        _table([[r["cve"], r["server_name"], r["severity"], r["cvss"], r["due_at"][:10], r["status"], r["ticket_id"]]
                for r in rows], ["CVE", "SERVER", "SEVERITY", "CVSS", "DEADLINE", "STATUS", "TICKET"])

    elif args.cmd == "tickets":
        rows = itsm.list_tickets(ctx, status=None if args.all else "active", bu=args.bu)
        _table([[t["id"], t["type"], t["status"], t["severity"], (t["due_at"] or "")[:10], t["assignee"], t["title"]]
                for t in rows], ["ID", "TYPE", "STATUS", "SEVERITY", "DUE", "ASSIGNEE", "TITLE"])

    elif args.cmd == "ticket":
        t = itsm.get(ctx, args.id)
        if not t:
            raise KeyError(f"no such ticket {args.id}")
        for key in ("id", "type", "title", "bu", "assignee", "severity", "status", "created_at", "due_at", "closed_at"):
            print(f"{key:<11} {t[key]}")
        print(f"\n{t['description']}\n")
        _table([[h["at"], h["status"], h["note"]] for h in itsm.history(ctx, args.id)], ["AT", "STATUS", "NOTE"])

    elif args.cmd == "patch":
        if args.action == "now":
            job = patch.patch_server(ctx, args.server, mode="self-service")
            print("Nothing to patch: no open vulnerability tickets for this server." if job is None
                  else f"{job['server_name']}: {job['status'].replace('_', ' ')}. {job['detail']}")
        elif args.action == "schedule":
            for e in scheduler.run(ctx, only_bu=args.bu, force=args.force):
                print(f"{e['name']}: {e['status']}")
                for job in e["jobs"]:
                    print(f"  {job['server_name']}: {job['status'].replace('_', ' ')}. {job['detail']}")
                for name in e["skipped"]:
                    print(f"  {name}: does not fit in the time left; stays queued for the next window")
        elif args.action == "plan":
            for e in scheduler.plan(ctx):
                state = "OPEN NOW" if e["open"] else f"opens {e['start']:%a %d %b %H:%M} UTC"
                hold = f"  [on hold: {e['held']['reason']}]" if e["held"] else ""
                print(f"{e['name']}: {state}{hold}")
                for s in e["queue"]:
                    print(f"  {s['server_name']:<18} {s['tickets']} ticket(s), risk {s['risk']:.1f}")

    elif args.cmd == "window":
        unit = ctx.bu(args.bu)
        if args.action == "hold":
            scheduler.hold(ctx, unit["id"], args.reason)
            print(f"{unit['name']}: downtime on hold ({args.reason}). Its risk will keep rising until released.")
        else:
            scheduler.release(ctx, unit["id"])
            print(f"{unit['name']}: downtime released.")

    elif args.cmd == "risk":
        rows = risk.compute(ctx, label=args.label)
        _table([[r["bu_name"], r["score"], r["goal_line"], "ABOVE" if r["score"] > r["goal_line"] else "ok",
                 r["vuln_score"], r["config_score"], r["open_vulns"], r["overdue_vulns"], r["open_config"]] for r in rows],
               ["BUSINESS UNIT", "RISK", "GOAL", "STATE", "VULN", "CONFIG", "OPEN VULNS", "OVERDUE", "CONFIG ISSUES"])

    elif args.cmd == "dashboard":
        print(f"Dashboard: {dashboard.build(ctx)}\nPower BI data: {ctx.root / 'dashboard' / 'data'}")

    elif args.cmd == "evaluate":
        path = evaluation.write_report(ctx)
        print(path.read_text(encoding="utf-8"))

    elif args.cmd == "nvd":
        cves = {r["cve"] for r in store.q("SELECT DISTINCT cve FROM vulnerabilities")}
        cves |= {v["cve"] for v in ctx.provider.list_vulnerabilities()}
        print(f"Fetching {len(cves)} CVE record(s) from NVD (about 7 seconds each)...")
        for cve, result in vuln.nvd_for(ctx).refresh(cves).items():
            print(f"  {cve}: {result}")

    elif args.cmd == "simulate":
        if ctx.provider.name != "mock":
            raise RuntimeError("simulate only works on the mock provider; on AWS, make the change in the console")
        event = ctx.provider.violate(ctx.control(args.control), args.resource, args.actor)
        print(f"{event['time']} {args.actor} called {event['event_name']} on {args.resource} (breaks {args.control})")

    elif args.cmd == "clock":
        if args.action == "set":
            store.set_now(from_iso(args.when))
        elif args.action == "advance":
            store.advance(days=args.days, hours=args.hours, minutes=args.minutes)
        elif args.action == "clear":
            store.set_now(None)
        print(f"{store.now():%a %Y-%m-%d %H:%M:%S} UTC" + (" (simulated)" if store.get_meta("sim_now") else " (real time)"))

    return 0


def _print_drift(ctx: Context, s: dict) -> None:
    print(f"{ctx.store.now_iso()} {s['checked']} checks: {len(s['new'])} drift event(s), {len(s['auto_fixed'])} restored "
          f"automatically, {len(s['tickets'])} ticketed for approval, {len(s['self_healed'])} found fixed")
    if s["new"]:
        marks = ",".join("?" * len(s["new"]))
        for d in ctx.store.q(f"SELECT * FROM config_issues WHERE id IN ({marks})", s["new"]):
            print(f"  {d['control_id']:<6} {d['resource_name']:<24} changed by {d['actor'] or 'unknown'} "
                  f"at {d['changed_at'] or 'unknown'} -> {d['status']}" + (f" ({d['ticket_id']})" if d["ticket_id"] else ""))
    for issue_id, why in s["failed"]:
        print(f"  ! issue {issue_id} not fixed: {why}")
