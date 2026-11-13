"""Shared context: configuration, store, provider and notification helper."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .store import Store

ROOT = Path(os.environ.get("CSPM_HOME") or Path(__file__).resolve().parent.parent)


def load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


class Context:
    def __init__(self, state_dir: Optional[Path] = None, provider_name: Optional[str] = None,
                 quiet: bool = False):
        self.root = ROOT
        self.quiet = quiet
        self.settings: Dict[str, Any] = load_json(ROOT / "config" / "settings.json")
        self.company: Dict[str, Any] = load_json(ROOT / "config" / "company.json")
        self.mbss: Dict[str, Any] = load_json(ROOT / "config" / "mbss.json")
        self.state_dir = Path(state_dir or os.environ.get("CSPM_STATE") or ROOT / "state")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.state_dir / "cspm.db")

        name = provider_name or os.environ.get("CSPM_PROVIDER") or self.settings.get("provider", "mock")
        if name != "mock":
            # Real servers carry far more CVEs than the simulated ones, so live goal lines sit higher.
            for unit in self.company["business_units"]:
                unit["goal_line"] = unit.get("goal_line_live", unit["goal_line"])
        if name == "mock":
            from .providers.mock import MockProvider
            self.provider = MockProvider(self.state_dir / "mock_env.json",
                                         ROOT / "data" / "sample" / "environment.json",
                                         clock=self.store.now)
        elif name == "aws":
            from .providers.aws import AwsProvider
            self.provider = AwsProvider(self.settings["aws"])
        elif name == "recorded":
            from .providers.recorded import RecordedProvider
            self.provider = RecordedProvider(self.store)
        else:
            raise ValueError(f"unknown provider {name!r} (use 'mock', 'aws' or 'recorded')")

    # -- configuration lookups ------------------------------------------
    @property
    def business_units(self) -> List[Dict[str, Any]]:
        return self.company["business_units"]

    def bu(self, bu_id: Optional[str]) -> Dict[str, Any]:
        for unit in self.business_units:
            if unit["id"] == bu_id:
                return unit
        return self.bu("platform")

    def all_controls(self) -> List[Dict[str, Any]]:
        return self.mbss["controls"]

    def mbss_controls(self) -> List[Dict[str, Any]]:
        """Only the controls the firm signed off."""
        return [c for c in self.mbss["controls"] if c.get("accepted", True)]

    def control(self, control_id: str) -> Dict[str, Any]:
        for c in self.mbss["controls"]:
            if c["id"] == control_id:
                return c
        raise KeyError(control_id)

    # -- output ----------------------------------------------------------
    def say(self, text: str = "") -> None:
        if not self.quiet:
            print(text)

    def notify(self, recipient: str, subject: str, body: str) -> None:
        """Record a notification and hand it to the provider (SNS on AWS)."""
        self.store.insert("notifications", {
            "at": self.store.now_iso(), "recipient": recipient, "subject": subject, "body": body,
        })
        try:
            self.provider.send_notification(recipient, subject, body)
        except Exception as exc:  # a failed email must never stop remediation
            self.say(f"  ! notification to {recipient} failed: {exc}")

    def close(self) -> None:
        self.store.close()
