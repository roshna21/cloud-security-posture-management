"""Security configuration and drift management (the MBSS cycle).

    1. take the CIS baseline      config/mbss.json lists the CIS controls
    2. firm sign-off              accepted=true marks the firm's MBSS subset
    3. implement                  baseline_apply() brings every resource to the MBSS
    4. detect drift               scan() compares the live setting with the MBSS and
                                  asks the audit trail who changed it and when
    5. remediate                  safe settings are restored at once; sensitive ones
                                  raise a ticket and wait for decide()
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

from . import itsm
from .checks import evaluate
from .providers import NotAutomatable
from .store import to_iso

UNRESOLVED = ("open", "pending_approval")


# -- small helpers ---------------------------------------------------------
def _set_compliance(ctx, control_id: str, resource_id: str, status: str) -> None:
    ctx.store.x(
        "INSERT INTO compliance (control_id, resource_id, status, updated_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(control_id, resource_id) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at",
        (control_id, resource_id, status, ctx.store.now_iso()))


def _compliance(ctx, control_id: str, resource_id: str) -> Optional[str]:
    row = ctx.store.one("SELECT status FROM compliance WHERE control_id = ? AND resource_id = ?",
                        (control_id, resource_id))
    return row["status"] if row else None


def _unresolved(ctx, control_id: str, resource_id: str) -> Optional[Dict[str, Any]]:
    return ctx.store.one(
        "SELECT * FROM config_issues WHERE control_id = ? AND resource_id = ? "
        "AND status IN ('open', 'pending_approval')", (control_id, resource_id))


def _active_exception(ctx, control_id: str, resource_id: str) -> Optional[Dict[str, Any]]:
    return ctx.store.one(
        "SELECT * FROM exceptions WHERE control_id = ? AND resource_id = ? AND expires_at > ?",
        (control_id, resource_id, ctx.store.now_iso()))


def _open_issue(ctx, kind: str, control: Dict[str, Any], result: Dict[str, Any],
                change: Optional[Dict[str, Any]]) -> int:
    now = ctx.store.now()
    due = now + timedelta(days=ctx.settings["sla_days"].get(control["severity"], 90))
    change = change or {}
    return ctx.store.insert("config_issues", {
        "kind": kind, "control_id": control["id"], "resource_type": result["resource_type"],
        "resource_id": result["resource_id"], "resource_name": result["resource_name"],
        "bu": result["bu"], "severity": control["severity"], "detail": result["detail"],
        "actor": change.get("user"), "changed_at": change.get("time"),
        "event_name": change.get("event_name"), "source_ip": change.get("source_ip"),
        "detected_at": to_iso(now), "due_at": to_iso(due),
        "remediation_mode": control["remediation"]["mode"], "status": "open",
    })


def _raise_approval(ctx, issue_id: int, control: Dict[str, Any], result: Dict[str, Any], kind: str) -> str:
    unit = ctx.bu(result["bu"])
    issue = ctx.store.one("SELECT * FROM config_issues WHERE id = ?", (issue_id,))
    who = f" Changed by {issue['actor']} at {issue['changed_at']}." if issue["actor"] else ""
    label = "Drift" if kind == "drift" else "Baseline gap"
    ticket_id = itsm.create(
        ctx, "config_approval",
        title=f"{label}: {control['id']} on {result['resource_name']} needs approval",
        description=(f"{control['title']} ({control['cis_ref']}). {result['detail']}.{who}\n"
                     f"Recommended fix: {control['recommendation']}\n"
                     f"Approve the restore:  python -m cspm drift decide {{ticket}} restore\n"
                     f"Or accept the risk:   python -m cspm drift decide {{ticket}} accept --reason \"...\""),
        bu=result["bu"], assignee=unit["head"], assignee_email=unit["head_email"],
        severity=control["severity"], resource_id=result["resource_id"], ref_id=issue_id,
        due_at=issue["due_at"])
    described = itsm.get(ctx, ticket_id)["description"].replace("{ticket}", ticket_id)
    ctx.store.update("tickets", ticket_id, {"description": described})
    ctx.store.update("config_issues", issue_id, {"status": "pending_approval", "ticket_id": ticket_id})
    ctx.notify(unit["head_email"], f"Approval needed: {control['id']} on {result['resource_name']} ({ticket_id})",
               f"Hello {unit['head']},\n\n{control['title']}.\n{result['detail']}.{who}\n\n"
               f"This setting is sensitive, so it was not changed automatically. Ticket {ticket_id} is waiting "
               f"for you to approve the restore or accept the risk as an exception.")
    return ticket_id


def _verify(ctx, pairs: List[Tuple[Dict[str, Any], str]]) -> Dict[Tuple[str, str], bool]:
    """Re-read the environment once and confirm each (control, resource) is now compliant."""
    if not pairs:
        return {}
    snapshot = ctx.provider.snapshot()
    out: Dict[Tuple[str, str], bool] = {}
    for control, resource_id in pairs:
        ok = any(r["resource_id"] == resource_id and r["compliant"] for r in evaluate(control, snapshot))
        out[(control["id"], resource_id)] = ok
    return out


def _close_issue(ctx, issue_id: int, note: str) -> None:
    issue = ctx.store.one("SELECT * FROM config_issues WHERE id = ?", (issue_id,))
    ctx.store.update("config_issues", issue_id, {"status": "remediated", "remediated_at": ctx.store.now_iso()})
    _set_compliance(ctx, issue["control_id"], issue["resource_id"], "compliant")
    if issue["ticket_id"] and itsm.get(ctx, issue["ticket_id"])["status"] != "closed":
        itsm.set_status(ctx, issue["ticket_id"], "closed", note)


# -- the cycle -------------------------------------------------------------
def _process(ctx, kind: str) -> Dict[str, Any]:
    """Shared engine for baseline_apply (kind=baseline_gap) and scan (kind=drift)."""
    snapshot = ctx.provider.snapshot()
    summary: Dict[str, Any] = {"checked": 0, "compliant": 0, "new": [], "auto_fixed": [],
                               "tickets": [], "self_healed": [], "failed": []}
    to_verify: List[Tuple[Dict[str, Any], str]] = []
    pending: Dict[Tuple[str, str], int] = {}

    for control in ctx.mbss_controls():
        for result in evaluate(control, snapshot):
            summary["checked"] += 1
            key = (control["id"], result["resource_id"])
            existing = _unresolved(ctx, *key)

            if result["compliant"]:
                summary["compliant"] += 1
                if existing:  # someone fixed it outside the system
                    _close_issue(ctx, existing["id"], "Setting found compliant on rescan")
                    summary["self_healed"].append(existing["id"])
                else:
                    _set_compliance(ctx, *key, "compliant")
                continue

            if existing:
                continue
            if _active_exception(ctx, *key):
                _set_compliance(ctx, *key, "exception")
                continue

            change = None
            if kind == "drift":
                change = ctx.provider.lookup_change(result["resource_id"], control.get("cloudtrail_events"))
            issue_id = _open_issue(ctx, kind, control, result, change)
            _set_compliance(ctx, *key, "noncompliant")
            summary["new"].append(issue_id)

            if control["remediation"]["mode"] == "auto":
                try:
                    ctx.provider.remediate(control, result["resource_id"])
                    to_verify.append((control, result["resource_id"]))
                    pending[key] = issue_id
                except Exception as exc:
                    summary["failed"].append((issue_id, str(exc)))
            else:
                summary["tickets"].append(_raise_approval(ctx, issue_id, control, result, kind))

    for key, ok in _verify(ctx, to_verify).items():
        issue_id = pending[key]
        if ok:
            _close_issue(ctx, issue_id, "Restored automatically")
            summary["auto_fixed"].append(issue_id)
        else:
            summary["failed"].append((issue_id, "setting is still non-compliant after remediation"))

    if kind == "drift" and (summary["auto_fixed"] or summary["failed"]):
        rows = ctx.store.q(
            f"SELECT * FROM config_issues WHERE id IN ({','.join('?' * len(summary['new']))})", summary["new"])
        lines = [f"  {r['control_id']:<6} {r['resource_name']:<24} by {r['actor'] or 'unknown':<14} "
                 f"at {r['changed_at'] or 'unknown'} -> {r['status']}" for r in rows]
        ctx.notify(ctx.company["security_team_email"], f"Drift detected on {len(rows)} setting(s)",
                   "Configuration drift from the MBSS:\n" + "\n".join(lines))
    return summary


def baseline_apply(ctx) -> Dict[str, Any]:
    """Step 3: implement the MBSS on every resource."""
    summary = _process(ctx, "baseline_gap")
    ctx.store.set_meta("baseline_applied_at", ctx.store.now_iso())
    return summary


def scan(ctx) -> Dict[str, Any]:
    """Steps 4 and 5: detect drift, attribute it, and remediate or raise a ticket."""
    if not ctx.store.get_meta("baseline_applied_at"):
        raise RuntimeError("the MBSS has not been applied yet; run `baseline apply` first")
    return _process(ctx, "drift")


def decide(ctx, ticket_id: str, action: str, by: str = "", reason: str = "") -> str:
    """The approver's decision on a sensitive setting: restore it, or accept the risk."""
    ticket = itsm.get(ctx, ticket_id)
    if ticket is None or ticket["type"] != "config_approval":
        raise KeyError(f"{ticket_id} is not a configuration approval ticket")
    if ticket["status"] == "closed":
        return f"{ticket_id} is already closed"
    issue = ctx.store.one("SELECT * FROM config_issues WHERE id = ?", (ticket["ref_id"],))
    control = ctx.control(issue["control_id"])
    by = by or ticket["assignee"]

    if action == "accept":
        days = ctx.settings["exceptions"]["default_expiry_days"]
        now = ctx.store.now()
        ctx.store.insert("exceptions", {
            "control_id": issue["control_id"], "resource_id": issue["resource_id"],
            "resource_name": issue["resource_name"], "bu": issue["bu"],
            "reason": reason or "Risk accepted by the business", "approved_by": by,
            "approved_at": to_iso(now), "expires_at": to_iso(now + timedelta(days=days)),
        })
        ctx.store.update("config_issues", issue["id"], {"status": "exception"})
        _set_compliance(ctx, issue["control_id"], issue["resource_id"], "exception")
        itsm.set_status(ctx, ticket_id, "closed", f"Risk accepted by {by} for {days} days: {reason}")
        return f"{ticket_id}: exception recorded until {to_iso(now + timedelta(days=days))[:10]}"

    if action == "restore":
        try:
            what = ctx.provider.remediate(control, issue["resource_id"])
        except NotAutomatable as exc:
            itsm.set_status(ctx, ticket_id, "in_progress",
                            f"Approved by {by}, but this fix needs a person: {exc}. "
                            "The ticket closes when a scan finds the setting compliant.")
            return f"{ticket_id}: approved; manual action required ({exc})"
        if _verify(ctx, [(control, issue["resource_id"])])[(control["id"], issue["resource_id"])]:
            _close_issue(ctx, issue["id"], f"Restore approved by {by}; {what or 'setting restored'}")
            return f"{ticket_id}: restored and closed"
        itsm.set_status(ctx, ticket_id, "reopened", "Remediation ran but the setting is still non-compliant")
        return f"{ticket_id}: remediation did not take effect"

    raise ValueError("action must be 'restore' or 'accept'")


def issues(ctx, kind: Optional[str] = None, unresolved_only: bool = False) -> List[Dict[str, Any]]:
    sql, params = "SELECT * FROM config_issues WHERE 1=1", []
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    if unresolved_only:
        sql += " AND status IN ('open', 'pending_approval')"
    return ctx.store.q(sql + " ORDER BY id", params)
