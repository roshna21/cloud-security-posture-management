"""One-time initial assessment across the five security domains.

Every CIS control in the catalogue is checked (including those the firm later
leaves out of its MBSS), plus the vulnerability state of each server. The
result is stored and written as a report listing each gap with its severity,
the affected resource and the recommended fix.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List

from .checks import evaluate
from .vuln import nvd_for, severity_of

SEVERITY_ORDER = {"zero-day": 0, "critical": 1, "high": 2, "medium": 3, "low": 4}
DOMAINS = ["Identity and access", "Data protection", "Network", "Logging and monitoring", "Server security"]


def run(ctx, write_report: bool = True) -> Dict[str, Any]:
    store = ctx.store
    run_id = int(store.get_meta("assessment_runs", "0")) + 1
    store.set_meta("assessment_runs", str(run_id))
    snapshot = ctx.provider.snapshot()
    now = store.now_iso()

    findings: List[Dict[str, Any]] = []
    stats: Dict[str, Counter] = defaultdict(Counter)
    for control in ctx.all_controls():
        stats[control["domain"]]["controls"] += 1
        for result in evaluate(control, snapshot):
            stats[control["domain"]]["checks"] += 1
            if result["compliant"]:
                stats[control["domain"]]["passed"] += 1
                continue
            finding = {
                "run_id": run_id, "control_id": control["id"], "cis_ref": control["cis_ref"],
                "domain": control["domain"], "title": control["title"], "severity": control["severity"],
                "in_mbss": 1 if control.get("accepted", True) else 0,
                "resource_type": result["resource_type"], "resource_id": result["resource_id"],
                "resource_name": result["resource_name"], "bu": result["bu"],
                "detail": result["detail"], "recommendation": control["recommendation"],
                "source": "cspm-check", "created_at": now,
            }
            store.insert("assessment_findings", finding)
            findings.append(finding)

    # On AWS, add what Security Hub's CIS standard reports that our own checks do not cover.
    extra = getattr(ctx.provider, "security_hub_findings", None)
    if extra:
        seen = {(f["cis_ref"], f["resource_id"]) for f in findings}
        for f in extra():
            if (f["cis_ref"], f["resource_id"]) in seen:
                continue
            f.update(run_id=run_id, in_mbss=0, source="security-hub", created_at=now)
            store.insert("assessment_findings", f)
            findings.append(f)
            stats[f["domain"]]["checks"] += 1

    # Server vulnerabilities, scored the same way the vulnerability module will score them.
    nvd = nvd_for(ctx)
    names = {i["id"]: i["name"] for i in snapshot["instances"]}
    exploited = set(ctx.settings.get("actively_exploited_cves", []))
    vulns = []
    for v in ctx.provider.list_vulnerabilities():
        record = nvd.lookup(v["cve"]) or {}
        cvss = record.get("cvss") or v.get("cvss") or 0.0
        vulns.append(dict(v, cvss=cvss, severity=severity_of(cvss, v["cve"] in exploited),
                          server=names.get(v["instance_id"], v["instance_id"])))
    vulns.sort(key=lambda v: (SEVERITY_ORDER[v["severity"]], -v["cvss"]))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["control_id"]))
    result = {"run_id": run_id, "at": now, "findings": findings, "stats": stats, "vulnerabilities": vulns}
    if write_report:
        result["report"] = str(_write_report(ctx, result))
    return result


def _write_report(ctx, result: Dict[str, Any]) -> Path:
    out_dir = ctx.root / "reports"
    out_dir.mkdir(exist_ok=True)
    findings, vulns, stats = result["findings"], result["vulnerabilities"], result["stats"]
    sev = Counter(f["severity"] for f in findings)
    vsev = Counter(v["severity"] for v in vulns)
    L: List[str] = []
    L.append(f"# Cloud Security Assessment Report: {ctx.company['company']}")
    L.append("")
    L.append(f"Assessment run {result['run_id']} at {result['at']}, provider `{ctx.provider.name}`. "
             f"Baseline: {ctx.mbss['source']}.")
    L.append("")
    L.append("## Summary")
    L.append("")
    L.append(f"- **{len(findings)} configuration gaps** across {len(DOMAINS)} security domains: "
             + ", ".join(f"{sev[s]} {s}" for s in ("critical", "high", "medium", "low") if sev[s]) + ".")
    L.append(f"- **{len(vulns)} server vulnerabilities**: "
             + (", ".join(f"{vsev[s]} {s}" for s in SEVERITY_ORDER if vsev[s]) or "none") + ".")
    L.append("")
    L.append("| Domain | Controls checked | Resource checks | Passed | Gaps |")
    L.append("|---|---:|---:|---:|---:|")
    for d in DOMAINS:
        s = stats.get(d, Counter())
        L.append(f"| {d} | {s['controls']} | {s['checks']} | {s['passed']} | {s['checks'] - s['passed']} |")
    L.append("")
    for d in DOMAINS:
        rows = [f for f in findings if f["domain"] == d]
        if not rows:
            continue
        L.append(f"## {d}")
        L.append("")
        L.append("| Severity | Control | Resource | Business unit | Gap | Recommended fix |")
        L.append("|---|---|---|---|---|---|")
        for f in rows:
            note = "" if f["in_mbss"] else " *(not adopted in MBSS)*"
            L.append(f"| {f['severity']} | {f['control_id']} {f['title']} ({f['cis_ref']}){note} | "
                     f"{f['resource_name']} | {ctx.bu(f['bu'])['name']} | {f['detail']} | {f['recommendation']} |")
        L.append("")
    L.append("## Server vulnerabilities")
    L.append("")
    if vulns:
        L.append("| Severity | CVE | CVSS | Server | Package | Installed | Fixed in | Deadline once ticketed |")
        L.append("|---|---|---:|---|---|---|---|---|")
        for v in vulns:
            days = ctx.settings["sla_days"][v["severity"]]
            L.append(f"| {v['severity']} | {v['cve']} | {v['cvss']} | {v['server']} | {v.get('package', '')} | "
                     f"{v.get('installed_version', '')} | {v.get('fixed_version', '')} | "
                     f"{'immediate' if days == 0 else str(days) + ' days'} |")
    else:
        L.append("No vulnerabilities were reported by the scanner.")
    L.append("")
    path = out_dir / "assessment_report.md"
    path.write_text("\n".join(L), encoding="utf-8")
    serialisable = dict(result, stats={k: dict(v) for k, v in stats.items()})
    (out_dir / "assessment_report.json").write_text(json.dumps(serialisable, indent=2), encoding="utf-8")
    return path
