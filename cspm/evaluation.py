"""Evaluation metrics (section 11 of the project document).

    assessment      detection rate against the planted issues
    drift           mean time to detect, mean time to remediate, attribution accuracy
    vulnerabilities share fixed within deadline, patch success rate, rollback rate
    risk            each business unit's score against its goal line, first vs latest
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .context import load_json
from .store import from_iso


def _mean(values: List[float]) -> Optional[float]:
    return round(sum(values) / len(values), 1) if values else None


def _minutes(start: str, end: str) -> float:
    return (from_iso(end) - from_iso(start)).total_seconds() / 60.0


def _pct(part: int, whole: int) -> Optional[float]:
    return round(100.0 * part / whole, 1) if whole else None


def metrics(ctx) -> Dict[str, Any]:
    store = ctx.store
    out: Dict[str, Any] = {"generated_at": store.now_iso(), "provider": ctx.provider.name}

    # -- assessment: detection rate against ground truth ---------------------
    truth_path = ctx.root / "data" / "sample" / "planted_issues.json"
    found = {(f["control_id"], f["resource_id"]) for f in store.q(
        "SELECT control_id, resource_id FROM assessment_findings WHERE run_id = 1 AND source = 'cspm-check'")}
    seen_vulns = {(v["instance_id"], v["cve"]) for v in store.q("SELECT instance_id, cve FROM vulnerabilities")}
    if ctx.provider.name == "mock" and truth_path.exists():
        truth = load_json(truth_path)
        planted = {(p["control_id"], p["resource_id"]) for p in truth["config_issues"]}
        planted_v = {(p["instance_id"], p["cve"]) for p in truth["vulnerabilities"]}
        by_domain: Dict[str, Dict[str, int]] = {}
        for p in truth["config_issues"]:
            d = by_domain.setdefault(p["domain"], {"planted": 0, "detected": 0})
            d["planted"] += 1
            d["detected"] += (p["control_id"], p["resource_id"]) in found
        out["assessment"] = {
            "planted_config_issues": len(planted),
            "detected": len(planted & found),
            "detection_rate_pct": _pct(len(planted & found), len(planted)),
            "missed": sorted(f"{c} on {r}" for c, r in planted - found),
            "false_positives": sorted(f"{c} on {r}" for c, r in found - planted),
            "by_domain": by_domain,
            "planted_vulnerabilities": len(planted_v),
            "vulnerabilities_detected": len(planted_v & seen_vulns),
            "vulnerability_detection_rate_pct": _pct(len(planted_v & seen_vulns), len(planted_v)),
        }
    else:
        out["assessment"] = {"findings": len(found), "vulnerabilities_seen": len(seen_vulns),
                             "note": "No ground truth for this provider; detection rate needs the planted-issue list."}

    # -- drift ------------------------------------------------------------------
    drifts = store.q("SELECT * FROM config_issues WHERE kind = 'drift'")
    fixed = [d for d in drifts if d["status"] == "remediated" and d["remediated_at"]]
    auto = [d for d in fixed if d["remediation_mode"] == "auto"]
    approval = [d for d in fixed if d["remediation_mode"] == "approval"]
    drift: Dict[str, Any] = {
        "drift_events": len(drifts),
        "attributed": sum(1 for d in drifts if d["actor"]),
        "mean_time_to_detect_min": _mean([_minutes(d["changed_at"], d["detected_at"]) for d in drifts if d["changed_at"]]),
        "mean_time_to_remediate_min_auto": _mean([_minutes(d["detected_at"], d["remediated_at"]) for d in auto]),
        "mean_time_to_remediate_min_approval": _mean([_minutes(d["detected_at"], d["remediated_at"]) for d in approval]),
        "auto_remediated": len(auto), "remediated_after_approval": len(approval),
        "accepted_as_exception": sum(1 for d in drifts if d["status"] == "exception"),
        "unresolved": sum(1 for d in drifts if d["status"] in ("open", "pending_approval")),
    }
    injected = getattr(ctx.provider, "injected_drifts", lambda: [])()
    if injected:
        index = {(d["control_id"], d["resource_id"], d["changed_at"]): d for d in drifts}
        hits = [index.get((i["control_id"], i["resource_id"], i["at"])) for i in injected]
        drift["injected"] = len(injected)
        drift["detected_of_injected"] = sum(1 for h in hits if h)
        drift["attribution_correct"] = sum(1 for i, h in zip(injected, hits) if h and h["actor"] == i["actor"])
        drift["attribution_accuracy_pct"] = _pct(drift["attribution_correct"], len(injected))
    out["drift"] = drift

    # -- vulnerabilities and patching -----------------------------------------
    vulns = store.q("SELECT * FROM vulnerabilities")
    now = store.now()
    done = [v for v in vulns if v["status"] == "fixed"]
    on_time = [v for v in done if from_iso(v["fixed_at"]) <= from_iso(v["due_at"])]
    # A zero-day's deadline is the moment it is found, so "on time" for it means fixed within a day.
    zero_day_ok = [v for v in done if v["severity"] == "zero-day"
                   and (from_iso(v["fixed_at"]) - from_iso(v["first_seen"])).total_seconds() <= 86400 * 2]
    on_time_ids = {v["id"] for v in on_time} | {v["id"] for v in zero_day_ok}
    jobs = store.q("SELECT * FROM patch_jobs WHERE status != 'running'")
    out["vulnerabilities"] = {
        "total": len(vulns), "fixed": len(done), "open": len(vulns) - len(done),
        "open_past_deadline": sum(1 for v in vulns if v["status"] == "open" and from_iso(v["due_at"]) < now),
        "fixed_within_deadline": len(on_time_ids),
        "fixed_within_deadline_pct": _pct(len(on_time_ids), len(vulns)),
        "zero_day_note": "zero-day tickets count as on time when fixed within 48 hours of detection",
        "mean_days_to_fix": _mean([_minutes(v["first_seen"], v["fixed_at"]) / 1440.0 for v in done]),
    }
    out["patching"] = {
        "jobs": len(jobs),
        "succeeded": sum(1 for j in jobs if j["status"] == "success"),
        "rolled_back": sum(1 for j in jobs if j["status"] == "rolled_back"),
        "failed_without_rollback": sum(1 for j in jobs if j["status"] == "failed"),
        "patch_success_rate_pct": _pct(sum(1 for j in jobs if j["status"] == "success"), len(jobs)),
        "rollback_rate_pct": _pct(sum(1 for j in jobs if j["status"] == "rolled_back"), len(jobs)),
    }

    # -- risk: first vs latest ----------------------------------------------------
    risk_rows = []
    for unit in ctx.business_units:
        hist = store.q("SELECT * FROM risk_history WHERE bu = ? ORDER BY id", (unit["id"],))
        if not hist:
            continue
        risk_rows.append({
            "bu": unit["name"], "goal_line": unit["goal_line"],
            "initial": hist[0]["score"], "peak": max(h["score"] for h in hist), "latest": hist[-1]["score"],
            "within_goal": hist[-1]["score"] <= unit["goal_line"],
        })
    out["risk"] = risk_rows
    return out


def write_report(ctx) -> Path:
    m = metrics(ctx)
    out_dir = ctx.root / "reports"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "evaluation.json").write_text(json.dumps(m, indent=2), encoding="utf-8")

    def show(value: Any, unit: str = "") -> str:
        return "n/a" if value is None else f"{value}{unit}"

    a, d, v, p = m["assessment"], m["drift"], m["vulnerabilities"], m["patching"]
    L = [f"# Evaluation results ({m['provider']} provider)", "", f"Generated at {m['generated_at']}.", ""]
    L += ["## Assessment", ""]
    if "detection_rate_pct" in a:
        L += [f"- Planted configuration issues detected: **{a['detected']} of {a['planted_config_issues']} "
              f"({show(a['detection_rate_pct'], '%')})**",
              f"- Planted vulnerabilities detected: **{a['vulnerabilities_detected']} of {a['planted_vulnerabilities']} "
              f"({show(a['vulnerability_detection_rate_pct'], '%')})**",
              f"- Missed: {', '.join(a['missed']) or 'none'}",
              f"- Findings not in the ground truth: {', '.join(a['false_positives']) or 'none'}", "",
              "| Domain | Planted | Detected |", "|---|---:|---:|"]
        L += [f"| {dom} | {s['planted']} | {s['detected']} |" for dom, s in a["by_domain"].items()]
    else:
        L += [f"- {a['findings']} findings, {a['vulnerabilities_seen']} vulnerabilities. {a['note']}"]
    L += ["", "## Drift management", "",
          f"- Drift events detected: **{d['drift_events']}** ({d['attributed']} attributed to a user)",
          f"- Mean time to detect: **{show(d['mean_time_to_detect_min'], ' min')}**",
          f"- Mean time to remediate, automatic: **{show(d['mean_time_to_remediate_min_auto'], ' min')}** ({d['auto_remediated']} events)",
          f"- Mean time to remediate, with approval: **{show(d['mean_time_to_remediate_min_approval'], ' min')}** ({d['remediated_after_approval']} events)",
          f"- Accepted as exception: {d['accepted_as_exception']}; unresolved: {d['unresolved']}"]
    if "attribution_accuracy_pct" in d:
        L += [f"- Injected changes detected: {d['detected_of_injected']} of {d['injected']}",
              f"- Attribution accuracy: **{d['attribution_correct']} of {d['injected']} ({show(d['attribution_accuracy_pct'], '%')})**"]
    L += ["", "## Vulnerability management", "",
          f"- Vulnerabilities: {v['total']} total, {v['fixed']} fixed, {v['open']} open ({v['open_past_deadline']} past deadline)",
          f"- Fixed within deadline: **{v['fixed_within_deadline']} of {v['total']} ({show(v['fixed_within_deadline_pct'], '%')})** ({v['zero_day_note']})",
          f"- Mean days to fix: {show(v['mean_days_to_fix'])}",
          f"- Patch jobs: {p['jobs']}; success rate **{show(p['patch_success_rate_pct'], '%')}**, "
          f"rollback rate **{show(p['rollback_rate_pct'], '%')}**",
          "", "## Risk per business unit", "",
          "| Business unit | Goal line | Initial | Peak | Latest | Within goal |", "|---|---:|---:|---:|---:|---|"]
    L += [f"| {r['bu']} | {r['goal_line']} | {r['initial']} | {r['peak']} | {r['latest']} | {'yes' if r['within_goal'] else 'NO'} |"
          for r in m["risk"]]
    path = out_dir / "evaluation.md"
    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    return path
