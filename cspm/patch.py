"""Patch orchestrator.

    snapshot -> stop services -> install patches -> start services -> health checks
        pass: close the tickets
        fail: restore the snapshot and reopen the tickets
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from . import itsm, vuln


def find_instance(ctx, server: str) -> Optional[Dict[str, Any]]:
    for inst in ctx.provider.snapshot()["instances"]:
        if server in (inst["id"], inst["name"]):
            return inst
    return None


def patch_server(ctx, server: str, mode: str = "self-service") -> Optional[Dict[str, Any]]:
    """Patch one server end to end. Returns the patch job, or None if there was nothing to do."""
    inst = find_instance(ctx, server)
    if inst is None:
        raise KeyError(f"no such server {server!r}")
    todo = vuln.open_vulns(ctx, instance_id=inst["id"])
    if not todo:
        return None

    store = ctx.store
    services = inst.get("services", [])
    job_id = store.insert("patch_jobs", {
        "instance_id": inst["id"], "server_name": inst["name"], "bu": inst["bu"],
        "mode": mode, "started_at": store.now_iso(), "status": "running",
    })
    for v in todo:
        itsm.set_status(ctx, v["ticket_id"], "in_progress", f"Patch job {job_id} started ({mode})")

    snapshot_id, ok, steps, reason = None, False, [], ""
    try:
        snapshot_id = ctx.provider.create_snapshot(inst["id"])
        steps.append(f"snapshot {snapshot_id}")
        ctx.provider.stop_services(inst["id"], services)
        steps.append(f"stopped {', '.join(services) or 'no services'}")
        steps.append(ctx.provider.install_patches(inst["id"]))
        ctx.provider.start_services(inst["id"], services)
        ok, health = ctx.provider.health_check(inst["id"], services)
        steps.append(f"health check: {health}")
        reason = health
    except Exception as exc:
        steps.append(f"error: {exc}")
        reason = str(exc)

    # In a simulation, patching takes time too.
    if store.get_meta("sim_now"):
        store.advance(minutes=ctx.settings["patching"]["minutes_per_server"])

    if ok:
        fixed = vuln.reconcile(ctx, ctx.provider.list_vulnerabilities(), inst["id"],
                               note=f"Patched by job {job_id}; post-patch health checks passed")
        fixed_ids = {f["id"] for f in fixed}
        for v in todo:
            if v["id"] not in fixed_ids:
                itsm.set_status(ctx, v["ticket_id"], "open", "Patch run completed but the scanner still reports this CVE "
                                "(no fix published yet, or the scanner has not rescanned); the next vulnerability scan will close it if fixed")
        status = "success"
        ctx.notify(inst["owner_email"], f"{inst['name']} patched: {len(fixed)} vulnerability ticket(s) closed",
                   f"Hello {inst['owner']},\n\n{inst['name']} was patched ({mode}). Steps: " + "; ".join(steps) + ".")
    else:
        fixed = []
        if snapshot_id:
            try:
                ctx.provider.restore_snapshot(inst["id"], snapshot_id)
                steps.append(f"restored from {snapshot_id}")
                status = "rolled_back"
            except Exception as exc:
                steps.append(f"ROLLBACK FAILED: {exc}")
                status = "failed"
        else:
            status = "failed"
        for v in todo:
            itsm.set_status(ctx, v["ticket_id"], "reopened", f"Patch job {job_id} {status.replace('_', ' ')}: {reason}")
        ctx.notify(inst["owner_email"], f"Patching {inst['name']} did not succeed ({status.replace('_', ' ')})",
                   f"Hello {inst['owner']},\n\nPatching {inst['name']} failed its post-patch checks. Steps: "
                   + "; ".join(steps) + f".\n{len(todo)} ticket(s) were reopened and will be retried in the next window.")
        ctx.notify(ctx.company["security_team_email"], f"Patch job {job_id} on {inst['name']}: {status}", "; ".join(steps))

    store.update("patch_jobs", job_id, {
        "finished_at": store.now_iso(), "snapshot_id": snapshot_id, "status": status,
        "detail": "; ".join(steps), "fixed_count": len(fixed),
    })
    return store.one("SELECT * FROM patch_jobs WHERE id = ?", (job_id,))
