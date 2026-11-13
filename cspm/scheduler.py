"""Scheduled patching in each business unit's agreed weekly downtime window.

The brief leaves the scheduling logic to a separate research document, so this
is a documented default: when a unit's window is open, its servers with open
tickets are patched one after another, highest risk first, for as many servers
as fit in the time left. A unit can put its downtime on hold (the business
declining downtime); its risk then keeps rising until it releases the hold.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from . import patch, risk, vuln

WEEKDAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]


def window_for(unit: Dict[str, Any], now: datetime) -> Tuple[datetime, datetime]:
    """The window that is open at `now`, or else the next one to open."""
    w = unit["downtime_window"]
    days_back = (now.weekday() - WEEKDAYS.index(w["weekday"])) % 7
    start = (now - timedelta(days=days_back)).replace(hour=w["start_hour"], minute=0, second=0, microsecond=0)
    length = timedelta(hours=w["duration_hours"])
    if start > now:                       # today is the day, but the window has not opened yet
        pass
    elif now >= start + length:           # this week's window is over
        start += timedelta(days=7)
    return start, start + length


def is_open(unit: Dict[str, Any], now: datetime) -> bool:
    start, end = window_for(unit, now)
    return start <= now < end


def hold(ctx, bu: str, reason: str) -> None:
    ctx.store.x("INSERT INTO holds (bu, reason, at) VALUES (?, ?, ?) "
                "ON CONFLICT(bu) DO UPDATE SET reason = excluded.reason, at = excluded.at",
                (ctx.bu(bu)["id"], reason, ctx.store.now_iso()))


def release(ctx, bu: str) -> None:
    ctx.store.x("DELETE FROM holds WHERE bu = ?", (bu,))


def held(ctx, bu: str) -> Optional[Dict[str, Any]]:
    return ctx.store.one("SELECT * FROM holds WHERE bu = ?", (bu,))


def queue(ctx, bu: str) -> List[Dict[str, Any]]:
    """Servers of a unit that have open tickets, highest risk first."""
    now = ctx.store.now()
    per_server: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"risk": 0.0, "tickets": 0})
    for v in vuln.open_vulns(ctx, bu=bu):
        entry = per_server[v["instance_id"]]
        entry.update(instance_id=v["instance_id"], server_name=v["server_name"])
        entry["risk"] += risk.vuln_risk(ctx, v, now)
        entry["tickets"] += 1
    return sorted(per_server.values(), key=lambda e: -e["risk"])


def plan(ctx) -> List[Dict[str, Any]]:
    now = ctx.store.now()
    out = []
    for unit in ctx.business_units:
        start, end = window_for(unit, now)
        out.append({"bu": unit["id"], "name": unit["name"], "start": start, "end": end,
                    "open": start <= now < end, "held": held(ctx, unit["id"]),
                    "queue": queue(ctx, unit["id"])})
    return out


def run(ctx, only_bu: Optional[str] = None, force: bool = False) -> List[Dict[str, Any]]:
    """Patch every unit whose window is open right now. Returns what happened per unit.

    force=True opens a window of the agreed length starting now, for a unit that has
    agreed to an out-of-schedule window (and for showing the flow on a live account,
    where the clock cannot be moved).
    """
    results = []
    per_server = timedelta(minutes=ctx.settings["patching"]["minutes_per_server"])
    for unit in ctx.business_units:
        if only_bu and unit["id"] != only_bu:
            continue
        now = ctx.store.now()
        start, end = window_for(unit, now)
        if force:
            start, end = now, now + timedelta(hours=unit["downtime_window"]["duration_hours"])
        servers = queue(ctx, unit["id"])
        entry: Dict[str, Any] = {"bu": unit["id"], "name": unit["name"], "jobs": [], "skipped": []}
        if not (start <= now < end):
            entry["status"] = f"window closed (next opens {start:%a %d %b %H:%M} UTC)"
        elif not servers:
            entry["status"] = "window open, nothing to patch"
        elif held(ctx, unit["id"]):
            h = held(ctx, unit["id"])
            entry["status"] = f"window open but downtime is on hold: {h['reason']}"
            ctx.notify(ctx.company["security_team_email"],
                       f"{unit['name']} downtime window skipped (on hold)",
                       f"{len(servers)} server(s) with open tickets were not patched. Reason given: {h['reason']}")
        else:
            entry["status"] = "window open"
            for server in servers:
                if ctx.store.now() + per_server > end:
                    entry["skipped"].append(server["server_name"])
                    continue
                entry["jobs"].append(patch.patch_server(ctx, server["instance_id"], mode="scheduled"))
        results.append(entry)
    return results
