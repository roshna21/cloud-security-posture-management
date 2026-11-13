"""Vulnerability intake: detect, score, set a deadline, raise a ticket, notify.

    scanner finding -> NVD enrichment -> severity -> deadline -> ticket -> owner email
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any, Dict, List, Optional

from . import itsm
from .nvd import Nvd
from .store import to_iso


def severity_of(cvss: float, exploited: bool) -> str:
    if exploited:
        return "zero-day"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def nvd_for(ctx) -> Nvd:
    return Nvd(ctx.root / "data" / "nvd_cache.json", ctx.settings["nvd"]["api_url"])


def scan(ctx) -> Dict[str, Any]:
    """Pull scanner findings and open a ticket for every new vulnerability."""
    now = ctx.store.now()
    nvd = nvd_for(ctx)
    instances = {i["id"]: i for i in ctx.provider.snapshot()["instances"]}
    findings = ctx.provider.list_vulnerabilities()
    known = {(r["instance_id"], r["cve"]) for r in
             ctx.store.q("SELECT instance_id, cve FROM vulnerabilities WHERE status = 'open'")}
    exploited_list = set(ctx.settings.get("actively_exploited_cves", []))
    new_by_server: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for f in findings:
        if (f["instance_id"], f["cve"]) in known:
            continue
        inst = instances.get(f["instance_id"], {})
        record = nvd.lookup(f["cve"]) or {}
        cvss = record.get("cvss")
        if cvss is None:
            cvss = f.get("cvss") or 0.0
        exploited = f["cve"] in exploited_list
        severity = severity_of(cvss, exploited)
        due = now + timedelta(days=ctx.settings["sla_days"][severity])
        bu = inst.get("bu") or "platform"
        owner = inst.get("owner") or ctx.bu(bu)["head"]
        owner_email = inst.get("owner_email") or ctx.bu(bu)["head_email"]
        server = inst.get("name", f["instance_id"])
        row = {
            "instance_id": f["instance_id"], "server_name": server, "bu": bu,
            "owner": owner, "owner_email": owner_email,
            "criticality": inst.get("criticality", "medium"),
            "internet_facing": 1 if inst.get("internet_facing") else 0,
            "cve": f["cve"], "package": f.get("package", ""),
            "installed_version": f.get("installed_version", ""),
            "fixed_version": f.get("fixed_version", ""),
            "cvss": cvss, "severity": severity, "exploited": 1 if exploited else 0,
            "description": record.get("description") or f.get("description", ""),
            "first_seen": to_iso(now), "due_at": to_iso(due), "status": "open",
        }
        vuln_id = ctx.store.insert("vulnerabilities", row)
        ticket_id = itsm.create(
            ctx, "vulnerability",
            title=f"{f['cve']} on {server} ({severity}, CVSS {cvss})",
            description=(f"{row['description']}\nPackage {row['package']} {row['installed_version']} "
                         f"-> fixed in {row['fixed_version'] or 'no fix published yet'}."),
            bu=bu, assignee=owner, assignee_email=owner_email, severity=severity,
            resource_id=f["instance_id"], ref_id=vuln_id, due_at=row["due_at"],
        )
        ctx.store.update("vulnerabilities", vuln_id, {"ticket_id": ticket_id})
        row.update(id=vuln_id, ticket_id=ticket_id)
        new_by_server[f["instance_id"]].append(row)

    # One email per server, not one per CVE.
    for rows in new_by_server.values():
        rows.sort(key=lambda r: -r["cvss"])
        first = rows[0]
        window = ctx.bu(first["bu"])["downtime_window"]
        lines = [f"  {r['ticket_id']}  {r['cve']:<16} {r['severity']:<9} CVSS {r['cvss']:<4}  due {r['due_at'][:10]}" for r in rows]
        urgent = "URGENT: " if any(r["severity"] == "zero-day" for r in rows) else ""
        ctx.notify(
            first["owner_email"],
            f"{urgent}{len(rows)} new vulnerability ticket(s) for {first['server_name']}",
            f"Hello {first['owner']},\n\nThe following vulnerabilities were found on {first['server_name']}:\n"
            + "\n".join(lines)
            + "\n\nYou can patch now (self-service):\n"
            f"  python -m cspm patch now --server {first['server_name']}\n"
            f"or leave it to the next agreed downtime window ({window['weekday']} "
            f"{window['start_hour']:02d}:00 UTC, {window['duration_hours']}h). "
            "A snapshot is taken before patching and the server is rolled back if health checks fail.",
        )

    fixed = reconcile(ctx, findings)
    return {
        "reported": len(findings),
        "new": sum(len(v) for v in new_by_server.values()),
        "fixed": len(fixed),
        "new_rows": [r for rows in new_by_server.values() for r in rows],
    }


def reconcile(ctx, findings: List[Dict[str, Any]], instance_id: Optional[str] = None,
              note: str = "Scanner no longer reports this vulnerability") -> List[Dict[str, Any]]:
    """Mark open vulnerabilities the scanner no longer reports as fixed and close their tickets."""
    reported = {(f["instance_id"], f["cve"]) for f in findings}
    sql, params = "SELECT * FROM vulnerabilities WHERE status = 'open'", []
    if instance_id:
        sql += " AND instance_id = ?"
        params.append(instance_id)
    fixed = []
    for row in ctx.store.q(sql, params):
        if (row["instance_id"], row["cve"]) in reported:
            continue
        ctx.store.update("vulnerabilities", row["id"], {"status": "fixed", "fixed_at": ctx.store.now_iso()})
        if row["ticket_id"]:
            itsm.set_status(ctx, row["ticket_id"], "closed", note)
        fixed.append(row)
    return fixed


def open_vulns(ctx, instance_id: Optional[str] = None, bu: Optional[str] = None) -> List[Dict[str, Any]]:
    sql, params = "SELECT * FROM vulnerabilities WHERE status = 'open'", []
    if instance_id:
        sql += " AND instance_id = ?"
        params.append(instance_id)
    if bu:
        sql += " AND bu = ?"
        params.append(bu)
    return ctx.store.q(sql + " ORDER BY cvss DESC", params)


def rescore(ctx) -> int:
    """Re-apply NVD scores to open vulnerabilities after the cache was refreshed.

    Severity, deadline (counted from first detection) and the ticket follow the new score.
    """
    nvd = nvd_for(ctx)
    exploited_list = set(ctx.settings.get("actively_exploited_cves", []))
    changed = 0
    for row in open_vulns(ctx):
        record = nvd.lookup(row["cve"]) or {}
        if record.get("cvss") is None or record["cvss"] == row["cvss"]:
            continue
        cvss = record["cvss"]
        severity = severity_of(cvss, row["cve"] in exploited_list)
        from .store import from_iso
        due = to_iso(from_iso(row["first_seen"]) + timedelta(days=ctx.settings["sla_days"][severity]))
        ctx.store.update("vulnerabilities", row["id"], {
            "cvss": cvss, "severity": severity, "due_at": due,
            "description": record.get("description") or row["description"]})
        if row["ticket_id"]:
            ctx.store.update("tickets", row["ticket_id"], {
                "severity": severity, "due_at": due,
                "title": f"{row['cve']} on {row['server_name']} ({severity}, CVSS {cvss})"})
            itsm.set_status(ctx, row["ticket_id"], itsm.get(ctx, row["ticket_id"])["status"],
                            f"Rescored from NVD: CVSS {row['cvss']} -> {cvss}, severity {severity}")
        changed += 1
    return changed
