"""Read-only view of a past live run.

After the cloud environment has been destroyed, the database in the state folder still
holds everything the engine recorded. This provider lets the console and reports show
that data without credentials. Every action that would touch the cloud is refused.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


class RecordedProvider:
    name = "aws-recorded"

    def __init__(self, store):
        self.store = store

    def snapshot(self) -> Dict[str, Any]:
        cached = self.store.get_meta("last_snapshot")
        return json.loads(cached) if cached else {"account": {"id": "account"}, "instances": []}

    def list_vulnerabilities(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.store.q(
            "SELECT instance_id, cve, package, installed_version, fixed_version, cvss FROM vulnerabilities WHERE status = 'open'")]

    def lookup_change(self, resource_id: str, event_names: Optional[List[str]] = None) -> None:
        return None

    def send_notification(self, recipient: str, subject: str, body: str) -> None:
        return None

    def poll_drift_events(self) -> List[Dict[str, Any]]:
        return []

    ACTIONS = ("remediate", "create_snapshot", "stop_services", "start_services",
               "install_patches", "health_check", "restore_snapshot")

    def __getattr__(self, name: str):
        if name not in self.ACTIONS:
            raise AttributeError(name)

        def refuse(*args, **kwargs):
            raise RuntimeError("This is a recording of a past live run; the cloud environment no longer exists, "
                               "so nothing can be changed. Use the simulation to try actions.")
        return refuse
