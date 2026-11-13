"""Simulated ITSM ticketing module.

A small stand-in for a tool such as ServiceNow or Jira Service Management:
tickets with an assignee, a due date, a status and a full status history.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

OPEN_STATUSES = ("open", "in_progress", "reopened")


def create(ctx, type: str, title: str, description: str, bu: str, assignee: str,
           assignee_email: str, severity: str, resource_id: str, ref_id: int,
           due_at: Optional[str] = None) -> str:
    count = ctx.store.one("SELECT COUNT(*) AS n FROM tickets")["n"]
    ticket_id = f"TKT-{count + 1:04d}"
    now = ctx.store.now_iso()
    ctx.store.insert("tickets", {
        "id": ticket_id, "type": type, "title": title, "description": description,
        "bu": bu, "assignee": assignee, "assignee_email": assignee_email,
        "severity": severity, "resource_id": resource_id, "ref_id": ref_id,
        "status": "open", "created_at": now, "due_at": due_at, "updated_at": now,
    })
    ctx.store.insert("ticket_history", {"ticket_id": ticket_id, "at": now, "status": "open", "note": "Ticket raised automatically"})
    return ticket_id


def set_status(ctx, ticket_id: str, status: str, note: str = "") -> None:
    ticket = get(ctx, ticket_id)
    if ticket is None:
        raise KeyError(f"no such ticket {ticket_id}")
    now = ctx.store.now_iso()
    changes: Dict[str, Any] = {"status": status, "updated_at": now}
    if status == "closed":
        changes["closed_at"] = now
    if status == "reopened":
        changes["closed_at"] = None
        changes["reopen_count"] = ticket["reopen_count"] + 1
    ctx.store.update("tickets", ticket_id, changes)
    ctx.store.insert("ticket_history", {"ticket_id": ticket_id, "at": now, "status": status, "note": note})


def get(ctx, ticket_id: str) -> Optional[Dict[str, Any]]:
    return ctx.store.one("SELECT * FROM tickets WHERE id = ?", (ticket_id,))


def list_tickets(ctx, status: Optional[str] = None, bu: Optional[str] = None) -> List[Dict[str, Any]]:
    sql, params = "SELECT * FROM tickets WHERE 1=1", []
    if status == "active":
        sql += " AND status != 'closed'"
    elif status:
        sql += " AND status = ?"
        params.append(status)
    if bu:
        sql += " AND bu = ?"
        params.append(bu)
    return ctx.store.q(sql + " ORDER BY id", params)


def history(ctx, ticket_id: str) -> List[Dict[str, Any]]:
    return ctx.store.q("SELECT * FROM ticket_history WHERE ticket_id = ? ORDER BY id", (ticket_id,))
