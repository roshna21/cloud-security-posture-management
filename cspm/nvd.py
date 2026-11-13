"""National Vulnerability Database lookups, with an offline cache.

Scanner findings are enriched with the NVD CVSS base score and description.
The cache (data/nvd_cache.json) lets the system run with no network; `refresh`
replaces cached records with live data from the NVD 2.0 API.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


class Nvd:
    def __init__(self, cache_path: Path, api_url: str):
        self.cache_path = Path(cache_path)
        self.api_url = api_url
        self.cache: Dict[str, Any] = {}
        if self.cache_path.exists():
            with open(self.cache_path, "r", encoding="utf-8") as fh:
                self.cache = json.load(fh)

    def lookup(self, cve: str) -> Optional[Dict[str, Any]]:
        record = self.cache.get(cve)
        return record if isinstance(record, dict) else None

    def fetch(self, cve: str) -> Optional[Dict[str, Any]]:
        req = urllib.request.Request(f"{self.api_url}?cveId={cve}", headers={"User-Agent": "cspm-student-project"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
        items = data.get("vulnerabilities") or []
        if not items:
            return None
        item = items[0]["cve"]
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
            metrics = item.get("metrics", {}).get(key) or []
            if metrics:
                primary = [m for m in metrics if m.get("type") == "Primary"] or metrics
                score = primary[0]["cvssData"]["baseScore"]
                break
        description = next((d["value"] for d in item.get("descriptions", []) if d.get("lang") == "en"), "")
        return {
            "cvss": score, "description": description, "published": item.get("published"),
            "cisa_kev": "cisaExploitAdd" in item, "source": "nvd-api",
        }

    def refresh(self, cves: Iterable[str], delay: float = 6.5) -> Dict[str, str]:
        """Fetch each CVE from NVD. The public API allows about 5 requests per 30 seconds."""
        outcome: Dict[str, str] = {}
        for i, cve in enumerate(sorted(set(cves))):
            if i:
                time.sleep(delay)
            try:
                record = self.fetch(cve)
            except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as exc:
                outcome[cve] = f"failed: {exc}"
                continue
            if record and record["cvss"] is not None:
                self.cache[cve] = record
                outcome[cve] = f"cvss {record['cvss']}"
            else:
                outcome[cve] = "not found"
        self.cache.pop("_note", None)
        with open(self.cache_path, "w", encoding="utf-8") as fh:
            json.dump(self.cache, fh, indent=2)
        return outcome
