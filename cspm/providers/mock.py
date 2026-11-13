"""Simulated company environment.

The state is one JSON file that starts as a copy of data/sample/environment.json
(the sports-goods startup with its planted issues). Every provider call reads
and writes that file, so the CLI can be run step by step like a real cloud.

Beyond the provider interface it offers `violate`, which makes a change to a
controlled setting on behalf of a named user and writes the matching audit
event. That is how drift is injected for the evaluation.
"""
from __future__ import annotations

import copy
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..checks import get_field, items_of, set_field, world_rules
from ..store import to_iso

AUTOMATION_USER = "cspm-automation"


class MockProvider:
    name = "mock"

    def __init__(self, state_path: Path, sample_path: Path, clock: Callable[[], datetime]):
        self.state_path = Path(state_path)
        self.sample_path = Path(sample_path)
        self.clock = clock
        if not self.state_path.exists():
            self.reset()

    # -- state -----------------------------------------------------------
    def reset(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.sample_path, self.state_path)

    def _load(self) -> Dict[str, Any]:
        with open(self.state_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _save(self, state: Dict[str, Any]) -> None:
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)

    def _event(self, state: Dict[str, Any], user: str, event_name: str, resource_id: str) -> Dict[str, Any]:
        event = {
            "time": to_iso(self.clock()), "user": user, "event_name": event_name,
            "resource_id": resource_id,
            "source_ip": "10.0.0.10" if user == AUTOMATION_USER else "203.0.113.24",
        }
        state["cloudtrail"].append(event)
        return event

    @staticmethod
    def _find(state: Dict[str, Any], control: Dict[str, Any], resource_id: str) -> Dict[str, Any]:
        chk = control["check"]
        collection = "security_groups" if chk["type"] == "sg_world_ingress" else chk["collection"]
        for item in items_of(state, collection):
            if item["id"] == resource_id:
                return item
        raise KeyError(f"{resource_id} not found in {collection}")

    # -- provider interface: configuration -------------------------------
    def snapshot(self) -> Dict[str, Any]:
        state = self._load()
        return {k: copy.deepcopy(v) for k, v in state.items()
                if k not in ("_sim", "vulnerabilities", "cloudtrail")}

    def lookup_change(self, resource_id: str, event_names: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        events = [e for e in self._load()["cloudtrail"]
                  if e["resource_id"] == resource_id
                  and (not event_names or e["event_name"] in event_names)]
        return events[-1] if events else None

    def remediate(self, control: Dict[str, Any], resource_id: str) -> str:
        """Put the setting back to its MBSS value."""
        state = self._load()
        item = self._find(state, control, resource_id)
        chk = control["check"]
        if chk["type"] == "sg_world_ingress":
            bad = world_rules(item, chk["ports"])
            item["ingress"] = [r for r in item["ingress"] if r not in bad]
            what = f"revoked {len(bad)} internet ingress rule(s)"
        else:
            target = 0 if chk.get("op") == "le" else chk["value"]
            set_field(item, chk["field"], copy.deepcopy(target))
            what = f"set {chk['field']} to {target!r}"
        self._event(state, AUTOMATION_USER, f"Remediate:{control['id']}", resource_id)
        self._save(state)
        return what

    # -- simulation only --------------------------------------------------
    def violate(self, control: Dict[str, Any], resource_id: str, actor: str) -> Dict[str, Any]:
        """Change a controlled setting away from the MBSS, as `actor`."""
        state = self._load()
        item = self._find(state, control, resource_id)
        chk = control["check"]
        if chk["type"] == "sg_world_ingress":
            port = chk["ports"][0]
            item["ingress"].append({"protocol": "tcp", "from_port": port, "to_port": port, "cidr": "0.0.0.0/0"})
        elif chk.get("op") == "ge":
            set_field(item, chk["field"], max(0, chk["value"] - 6))
        elif chk.get("op") == "le":
            set_field(item, chk["field"], chk["value"] + 100)
        elif isinstance(chk["value"], bool):
            set_field(item, chk["field"], not chk["value"])
        elif chk["value"] == []:
            set_field(item, chk["field"], [{"protocol": "-1", "from_port": 0, "to_port": 65535, "cidr": "10.0.0.0/16"}])
        else:
            raise ValueError(f"cannot simulate drift for control {control['id']}")
        names = control.get("cloudtrail_events") or ["ConfigurationChange"]
        event = self._event(state, actor, names[0], resource_id)
        state["_sim"]["injected_drifts"].append({
            "control_id": control["id"], "resource_id": resource_id, "actor": actor, "at": event["time"],
        })
        self._save(state)
        return event

    def injected_drifts(self) -> List[Dict[str, Any]]:
        return self._load()["_sim"]["injected_drifts"]

    # -- provider interface: vulnerabilities and patching ----------------
    def list_vulnerabilities(self) -> List[Dict[str, Any]]:
        return copy.deepcopy(self._load()["vulnerabilities"])

    def create_snapshot(self, instance_id: str) -> str:
        state = self._load()
        snap_id = f"snap-{len(state['_sim']['snapshots']) + 1:04d}"
        state["_sim"]["snapshots"][snap_id] = {
            "instance_id": instance_id, "taken_at": to_iso(self.clock()),
            "vulnerabilities": [v for v in state["vulnerabilities"] if v["instance_id"] == instance_id],
        }
        self._save(state)
        return snap_id

    def stop_services(self, instance_id: str, services: List[str]) -> None:
        state = self._load()
        state["_sim"]["stopped_services"][instance_id] = list(services)
        self._save(state)

    def start_services(self, instance_id: str, services: List[str]) -> None:
        state = self._load()
        state["_sim"]["stopped_services"].pop(instance_id, None)
        self._save(state)

    def install_patches(self, instance_id: str) -> str:
        state = self._load()
        mine = [v for v in state["vulnerabilities"] if v["instance_id"] == instance_id]
        fixable = [v for v in mine if v.get("fixed_version")]
        state["vulnerabilities"] = [v for v in state["vulnerabilities"] if v not in fixable]
        # An instance listed in patch_fail_once comes back unhealthy the first time.
        if instance_id in state["_sim"]["patch_fail_once"]:
            state["_sim"]["patch_fail_once"].remove(instance_id)
            state["_sim"].setdefault("unhealthy", []).append(instance_id)
        self._save(state)
        return f"installed {len(fixable)} package update(s)"

    def health_check(self, instance_id: str, services: List[str]) -> Tuple[bool, str]:
        state = self._load()
        if instance_id in state["_sim"].get("unhealthy", []):
            failed = services[0] if services else "system"
            return False, f"service {failed} failed to start after patching"
        if instance_id in state["_sim"]["stopped_services"]:
            return False, "services are still stopped"
        return True, f"{len(services)} service(s) active"

    def restore_snapshot(self, instance_id: str, snapshot_id: str) -> None:
        state = self._load()
        snap = state["_sim"]["snapshots"][snapshot_id]
        state["vulnerabilities"] = [v for v in state["vulnerabilities"] if v["instance_id"] != instance_id]
        state["vulnerabilities"].extend(snap["vulnerabilities"])
        if instance_id in state["_sim"].get("unhealthy", []):
            state["_sim"]["unhealthy"].remove(instance_id)
        state["_sim"]["stopped_services"].pop(instance_id, None)
        self._save(state)

    # -- provider interface: messaging -----------------------------------
    def send_notification(self, recipient: str, subject: str, body: str) -> None:
        with open(self.state_path.parent / "outbox.log", "a", encoding="utf-8") as fh:
            fh.write(f"[{to_iso(self.clock())}] To: {recipient}\nSubject: {subject}\n{body}\n\n")

    def poll_drift_events(self) -> List[Dict[str, Any]]:
        return []
