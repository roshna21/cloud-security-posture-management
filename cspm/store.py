"""SQLite persistence and the system clock.

Everything the engine remembers lives here: assessment findings, the compliance
state of every control, config issues (baseline gaps and drift), vulnerabilities,
ITSM tickets, patch jobs, risk history, exceptions and sent notifications.

The clock is part of the store so that a simulation can move time forward
(`cspm clock ...`). When no simulated time is set, real UTC time is used.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ISO = "%Y-%m-%dT%H:%M:%SZ"


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(ISO)


def from_iso(text: str) -> datetime:
    return datetime.strptime(text, ISO).replace(tzinfo=timezone.utc)


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS assessment_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER, control_id TEXT, cis_ref TEXT, domain TEXT, title TEXT,
    severity TEXT, in_mbss INTEGER, resource_type TEXT, resource_id TEXT,
    resource_name TEXT, bu TEXT, detail TEXT, recommendation TEXT,
    source TEXT, created_at TEXT
);

CREATE TABLE IF NOT EXISTS compliance (
    control_id TEXT, resource_id TEXT, status TEXT, updated_at TEXT,
    PRIMARY KEY (control_id, resource_id)
);

CREATE TABLE IF NOT EXISTS config_issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT,               -- baseline_gap | drift
    control_id TEXT, resource_type TEXT, resource_id TEXT, resource_name TEXT,
    bu TEXT, severity TEXT, detail TEXT,
    actor TEXT, changed_at TEXT, event_name TEXT, source_ip TEXT,
    detected_at TEXT, due_at TEXT,
    remediation_mode TEXT,   -- auto | approval
    status TEXT,             -- open | pending_approval | remediated | exception
    remediated_at TEXT, ticket_id TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT, server_name TEXT, bu TEXT, owner TEXT, owner_email TEXT,
    criticality TEXT, internet_facing INTEGER,
    cve TEXT, package TEXT, installed_version TEXT, fixed_version TEXT,
    cvss REAL, severity TEXT, exploited INTEGER, description TEXT,
    first_seen TEXT, due_at TEXT,
    status TEXT,             -- open | fixed
    fixed_at TEXT, ticket_id TEXT
);

CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    type TEXT,               -- vulnerability | config_approval
    title TEXT, description TEXT, bu TEXT,
    assignee TEXT, assignee_email TEXT, severity TEXT,
    resource_id TEXT, ref_id INTEGER,
    status TEXT,             -- open | in_progress | reopened | closed
    created_at TEXT, due_at TEXT, updated_at TEXT, closed_at TEXT,
    reopen_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ticket_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT, at TEXT, status TEXT, note TEXT
);

CREATE TABLE IF NOT EXISTS patch_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT, server_name TEXT, bu TEXT,
    mode TEXT,               -- self-service | scheduled
    started_at TEXT, finished_at TEXT, snapshot_id TEXT,
    status TEXT,             -- success | rolled_back | failed
    detail TEXT, fixed_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS risk_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT, label TEXT, bu TEXT, bu_name TEXT,
    score REAL, goal_line REAL, vuln_score REAL, config_score REAL,
    open_vulns INTEGER, overdue_vulns INTEGER, open_config INTEGER
);

CREATE TABLE IF NOT EXISTS exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id TEXT, resource_id TEXT, resource_name TEXT, bu TEXT,
    reason TEXT, approved_by TEXT, approved_at TEXT, expires_at TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT, recipient TEXT, subject TEXT, body TEXT
);

CREATE TABLE IF NOT EXISTS holds (bu TEXT PRIMARY KEY, reason TEXT, at TEXT);
"""


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- generic helpers -------------------------------------------------
    def q(self, sql: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(sql, tuple(params)).fetchall()]

    def one(self, sql: str, params: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
        rows = self.q(sql, params)
        return rows[0] if rows else None

    def x(self, sql: str, params: Iterable[Any] = ()) -> int:
        cur = self.conn.execute(sql, tuple(params))
        self.conn.commit()
        return cur.lastrowid

    def insert(self, table: str, row: Dict[str, Any]) -> int:
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        return self.x(f"INSERT INTO {table} ({cols}) VALUES ({marks})", row.values())

    def update(self, table: str, row_id: Any, changes: Dict[str, Any]) -> None:
        sets = ", ".join(f"{k} = ?" for k in changes)
        self.x(f"UPDATE {table} SET {sets} WHERE id = ?", list(changes.values()) + [row_id])

    # -- meta ------------------------------------------------------------
    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.one("SELECT value FROM meta WHERE key = ?", (key,))
        return row["value"] if row else default

    def set_meta(self, key: str, value: Optional[str]) -> None:
        if value is None:
            self.x("DELETE FROM meta WHERE key = ?", (key,))
        else:
            self.x("INSERT INTO meta (key, value) VALUES (?, ?) "
                   "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    # -- clock -----------------------------------------------------------
    def now(self) -> datetime:
        sim = self.get_meta("sim_now")
        if sim:
            return from_iso(sim)
        return datetime.now(timezone.utc).replace(microsecond=0)

    def now_iso(self) -> str:
        return to_iso(self.now())

    def set_now(self, when: Optional[datetime]) -> None:
        self.set_meta("sim_now", to_iso(when) if when else None)

    def advance(self, **delta: float) -> datetime:
        when = self.now() + timedelta(**delta)
        self.set_now(when)
        return when

    def close(self) -> None:
        self.conn.close()
