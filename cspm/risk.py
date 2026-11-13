"""Business-unit risk scoring and goal-line alerts.

The project brief leaves the scoring model to a separate research document, so
the model here is a documented, configurable default (config/settings.json):

    vulnerability risk = CVSS x exposure x criticality x exploited x overdue
    config issue risk  = severity points x overdue
    overdue            = 1 + min(days past deadline / max(SLA days, floor), cap)

    business-unit risk = sum over its open vulnerabilities and unresolved config issues

A unit whose risk is above the goal line set by leadership gets an alert to its
head. Approved exceptions do not add risk; they are shown on the dashboard.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from .store import from_iso, to_iso

UNRESOLVED = ("open", "pending_approval")


def overdue_factor(ctx, due_at: str, sla_days: int, now: datetime) -> float:
    cfg = ctx.settings["risk"]
    days_over = max(0.0, (now - from_iso(due_at)).total_seconds() / 86400.0)
    return 1.0 + min(days_over / max(sla_days, cfg["overdue_floor_days"]), cfg["overdue_cap"])


def vuln_risk(ctx, v: Dict[str, Any], now: datetime) -> float:
    cfg = ctx.settings["risk"]
    exposure = cfg["exposure_factor"]["internet" if v["internet_facing"] else "internal"]
    criticality = cfg["criticality_factor"].get(v["criticality"], 1.0)
    exploited = cfg["exploited_factor"] if v["exploited"] else 1.0
    overdue = overdue_factor(ctx, v["due_at"], ctx.settings["sla_days"][v["severity"]], now)
    return v["cvss"] * exposure * criticality * exploited * overdue


def config_risk(ctx, issue: Dict[str, Any], now: datetime) -> float:
    points = ctx.settings["risk"]["config_severity_points"].get(issue["severity"], 2)
    return points * overdue_factor(ctx, issue["due_at"], ctx.settings["sla_days"].get(issue["severity"], 90), now)


def compute(ctx, label: str = "", record: bool = True, alert: bool = True) -> List[Dict[str, Any]]:
    now = ctx.store.now()
    vulns = ctx.store.q("SELECT * FROM vulnerabilities WHERE status = 'open'")
    if ctx.store.get_meta("baseline_applied_at"):
        issues = ctx.store.q("SELECT * FROM config_issues WHERE status IN ('open', 'pending_approval')")
    else:
        # Before the MBSS is implemented, the gaps found by the latest assessment are the config risk.
        run_id = ctx.store.get_meta("assessment_runs", "0")
        issues = [dict(f, due_at=to_iso(now), status="found in assessment") for f in ctx.store.q(
            "SELECT * FROM assessment_findings WHERE run_id = ? AND in_mbss = 1", (run_id,))]
    rows: List[Dict[str, Any]] = []
    for unit in ctx.business_units:
        mine_v = [v for v in vulns if v["bu"] == unit["id"]]
        mine_c = [c for c in issues if c["bu"] == unit["id"]]
        vuln_score = sum(vuln_risk(ctx, v, now) for v in mine_v)
        config_score = sum(config_risk(ctx, c, now) for c in mine_c)
        row = {
            "at": to_iso(now), "label": label, "bu": unit["id"], "bu_name": unit["name"],
            "score": round(vuln_score + config_score, 1), "goal_line": unit["goal_line"],
            "vuln_score": round(vuln_score, 1), "config_score": round(config_score, 1),
            "open_vulns": len(mine_v),
            "overdue_vulns": sum(1 for v in mine_v if from_iso(v["due_at"]) < now),
            "open_config": len(mine_c),
        }
        rows.append(row)
        if record:
            ctx.store.insert("risk_history", row)
        if alert:
            _alert(ctx, unit, row, mine_v, mine_c, now)
    return rows


def _alert(ctx, unit: Dict[str, Any], row: Dict[str, Any], vulns: List[Dict[str, Any]],
           issues: List[Dict[str, Any]], now: datetime) -> None:
    state_key, last_key = f"alert_state:{unit['id']}", f"alert_last:{unit['id']}"
    was_above = ctx.store.get_meta(state_key) == "above"
    last = ctx.store.get_meta(last_key)
    above = row["score"] > unit["goal_line"]

    if above:
        reminder_due = last is None or (now - from_iso(last)).days >= ctx.settings["risk"]["alert_reminder_days"]
        if was_above and not reminder_due:
            return
        top = sorted(vulns, key=lambda v: -vuln_risk(ctx, v, now))[:5]
        lines = [f"  {v['cve']:<16} on {v['server_name']:<16} {v['severity']:<9} due {v['due_at'][:10]}"
                 f"{'  OVERDUE' if from_iso(v['due_at']) < now else ''}" for v in top]
        lines += [f"  {c['control_id']:<16} on {c['resource_name']:<16} config issue ({c['status']})" for c in issues[:5]]
        window = unit["downtime_window"]
        held = ctx.store.one("SELECT * FROM holds WHERE bu = ?", (unit["id"],))
        hold_note = ("\nDowntime for this unit is currently on hold, so scheduled patching is not running.\n"
                     if held else "")
        ctx.notify(
            unit["head_email"],
            f"{'Reminder: ' if was_above else ''}{unit['name']} risk is {row['score']} against a goal line of {unit['goal_line']}",
            f"Hello {unit['head']},\n\nYour business unit's security risk is above the goal line set by leadership.\n"
            f"  Risk score: {row['score']} (goal line {unit['goal_line']})\n"
            f"  Open vulnerabilities: {row['open_vulns']} ({row['overdue_vulns']} past deadline)\n"
            f"  Unresolved configuration issues: {row['open_config']}\n\nLargest contributors:\n"
            + "\n".join(lines) + "\n" + hold_note +
            f"\nAgreeing to downtime is how this comes down: the next window is {window['weekday']} "
            f"{window['start_hour']:02d}:00 UTC, or the server owner can patch now through self-service.",
        )
        ctx.store.set_meta(state_key, "above")
        ctx.store.set_meta(last_key, to_iso(now))
    elif was_above:
        ctx.notify(unit["head_email"],
                   f"{unit['name']} risk is back under the goal line ({row['score']} of {unit['goal_line']})",
                   f"Hello {unit['head']},\n\nYour business unit's risk score is now {row['score']}, "
                   f"under the goal line of {unit['goal_line']}. No action is needed.")
        ctx.store.set_meta(state_key, "below")
