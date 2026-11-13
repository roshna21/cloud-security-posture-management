"""End-to-end scenario on the simulated company.

Two simulated weeks that exercise every part of the system and produce the
numbers for the evaluation: assessment, MBSS implementation, approvals, a
self-service patch, injected drift, a business unit that refuses downtime, a
failed patch with rollback, and the retries.
"""
from __future__ import annotations

from typing import Any, Dict, List

from . import assessment, dashboard, drift, evaluation, itsm, patch, risk, scheduler, vuln
from .store import from_iso


def _goto(ctx, when: str) -> None:
    ctx.store.set_now(from_iso(when))
    ctx.say(f"\n=== {ctx.store.now():%a %d %b %Y %H:%M} UTC ===")


def _risk(ctx, label: str) -> List[Dict[str, Any]]:
    rows = risk.compute(ctx, label=label)
    ctx.say(f"  Risk ({label}):")
    for r in rows:
        flag = "ABOVE goal" if r["score"] > r["goal_line"] else "within goal"
        ctx.say(f"    {r['bu_name']:<22} {r['score']:>6}  goal {r['goal_line']:>3}  {flag}")
    return rows


def _windows(ctx) -> None:
    for entry in scheduler.run(ctx):
        if entry["status"].startswith("window closed") or entry["status"].endswith("nothing to patch"):
            continue
        ctx.say(f"  {entry['name']}: {entry['status']}")
        for job in entry["jobs"]:
            ctx.say(f"    {job['server_name']}: {job['status'].replace('_', ' ')} ({job['detail']})")


def run(ctx) -> Dict[str, Any]:
    if ctx.provider.name != "mock":
        raise RuntimeError("the demo scenario only runs on the mock provider")

    _goto(ctx, "2026-01-05T09:00:00Z")
    ctx.say("1. Initial assessment")
    a = assessment.run(ctx)
    ctx.say(f"  {len(a['findings'])} configuration gaps and {len(a['vulnerabilities'])} server vulnerabilities -> {a['report']}")
    v = vuln.scan(ctx)
    ctx.say(f"  Vulnerability scan: {v['new']} tickets raised, owners notified")
    _risk(ctx, "Initial assessment")

    _goto(ctx, "2026-01-05T09:30:00Z")
    ctx.say("2. Implement the MBSS on all resources")
    b = drift.baseline_apply(ctx)
    ctx.say(f"  {b['checked']} checks, {len(b['new'])} gaps: {len(b['auto_fixed'])} fixed automatically, "
            f"{len(b['tickets'])} sensitive settings ticketed for approval")

    _goto(ctx, "2026-01-05T10:30:00Z")
    ctx.say("3. Business unit heads act on the approval tickets")
    for t in itsm.list_tickets(ctx, status="active"):
        if t["type"] != "config_approval":
            continue
        issue = ctx.store.one("SELECT * FROM config_issues WHERE id = ?", (t["ref_id"],))
        if issue["control_id"] == "DP.5":
            msg = drift.decide(ctx, t["id"], "accept",
                               reason="Re-encrypting the volume needs a rebuild; planned with the storefront migration")
        else:
            msg = drift.decide(ctx, t["id"], "restore")
        ctx.say(f"  {issue['control_id']:<6} {issue['resource_name']:<22} {msg}")
    _risk(ctx, "MBSS implemented")

    _goto(ctx, "2026-01-06T14:00:00Z")
    ctx.say("4. Online Store owner patches the zero-day through self-service")
    job = patch.patch_server(ctx, "store-web-01", mode="self-service")
    ctx.say(f"  store-web-01: {job['status']} ({job['detail']})")
    _risk(ctx, "Self-service patch")

    _goto(ctx, "2026-01-07T11:00:00Z")
    ctx.say("5. Configuration drift: five changes made outside the process")
    changes = [("NET.1", "sg-web-0001", "dev-priya"), ("DP.1", "stride-finance-reports", "ops-admin"),
               ("LOG.2", "stride-trail", "ops-admin"), ("SRV.1", "i-0a1b2c3d4e5f60002", "dev-priya"),
               ("NET.4", "sg-db-0002", "dev-priya")]
    for control_id, resource_id, actor in changes:
        ctx.provider.violate(ctx.control(control_id), resource_id, actor)
        ctx.say(f"  {ctx.store.now():%H:%M} {actor} broke {control_id} on {resource_id}")
        ctx.store.advance(minutes=1)
    ctx.store.advance(minutes=1)
    s = drift.scan(ctx)
    ctx.say(f"  {ctx.store.now():%H:%M} drift scan: {len(s['new'])} drift events, {len(s['auto_fixed'])} restored "
            f"automatically, {len(s['tickets'])} waiting for approval")
    for d in drift.issues(ctx, kind="drift"):
        ctx.say(f"    {d['control_id']:<6} {d['resource_name']:<22} changed by {d['actor']} at {d['changed_at'][11:16]} -> {d['status']}")
    _goto(ctx, "2026-01-07T11:45:00Z")
    for ticket_id in s["tickets"]:
        ctx.say(f"  {drift.decide(ctx, ticket_id, 'restore')}")
    _risk(ctx, "Drift handled")

    _goto(ctx, "2026-01-08T10:00:00Z")
    ctx.say("6. Finance and HR declines downtime this week")
    scheduler.hold(ctx, "finance-hr", "Quarter-end payroll run; no downtime this week")

    _goto(ctx, "2026-01-09T21:00:00Z")
    ctx.say("7. Downtime windows, week 1")
    _windows(ctx)
    _goto(ctx, "2026-01-10T20:00:00Z")
    _windows(ctx)
    _goto(ctx, "2026-01-11T01:00:00Z")
    _windows(ctx)
    _risk(ctx, "After week 1 windows")

    _goto(ctx, "2026-01-13T09:00:00Z")
    ctx.say("8. Finance and HR critical tickets are now past their 7-day deadline")
    _risk(ctx, "Finance past deadline")

    _goto(ctx, "2026-01-14T10:00:00Z")
    ctx.say("9. The Finance and HR head agrees to downtime")
    scheduler.release(ctx, "finance-hr")

    _goto(ctx, "2026-01-16T21:00:00Z")
    ctx.say("10. Downtime windows, week 2")
    _windows(ctx)
    _goto(ctx, "2026-01-17T20:00:00Z")
    _windows(ctx)

    _goto(ctx, "2026-01-19T09:00:00Z")
    ctx.say("11. Final scans")
    v = vuln.scan(ctx)
    s = drift.scan(ctx)
    ctx.say(f"  Vulnerability scan: {v['reported']} reported. Drift scan: {len(s['new'])} new drift events.")
    _risk(ctx, "Final")

    page = dashboard.build(ctx)
    report = evaluation.write_report(ctx)
    ctx.say(f"\nDashboard:  {page}\nEvaluation: {report}")
    ctx.say(f"Notifications sent: {ctx.store.one('SELECT COUNT(*) AS n FROM notifications')['n']} "
            f"(see {ctx.state_dir / 'outbox.log'})")
    return evaluation.metrics(ctx)
