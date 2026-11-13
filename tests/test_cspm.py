"""Tests on the simulated company.  Run:  python3 -m unittest discover -s tests -v"""
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cspm import assessment, demo, drift, itsm, patch, risk, scheduler, vuln  # noqa: E402
from cspm.checks import evaluate  # noqa: E402
from cspm.context import Context  # noqa: E402
from cspm.store import from_iso  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cspm-test-")
        self.ctx = Context(state_dir=self.tmp, provider_name="mock", quiet=True)
        self.ctx.store.set_now(from_iso("2026-01-05T09:00:00Z"))

    def tearDown(self):
        self.ctx.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


class ChecksTest(Base):
    def test_world_ingress_flags_only_internet_rules(self):
        snap = self.ctx.provider.snapshot()
        results = {r["resource_id"]: r["compliant"] for r in evaluate(self.ctx.control("NET.1"), snap)}
        self.assertFalse(results["sg-web-0001"])     # 22 open to 0.0.0.0/0
        self.assertTrue(results["sg-fin-0004"])      # 22 open only to 10.0.0.0/16

    def test_where_filter_skips_users_without_console(self):
        snap = self.ctx.provider.snapshot()
        ids = {r["resource_id"] for r in evaluate(self.ctx.control("IAM.4"), snap)}
        self.assertNotIn("finance-app-svc", ids)


class DriftTest(Base):
    def test_baseline_then_drift_is_attributed_and_restored(self):
        ctx = self.ctx
        b = drift.baseline_apply(ctx)
        self.assertEqual(len(b["failed"]), 0)
        self.assertEqual(len(drift.scan(ctx)["new"]), 0)            # nothing drifted yet

        ctx.provider.violate(ctx.control("DP.1"), "stride-cloudtrail-logs", "ops-admin")
        ctx.store.advance(minutes=3)
        s = drift.scan(ctx)
        self.assertEqual(len(s["auto_fixed"]), 1)
        event = drift.issues(ctx, kind="drift")[0]
        self.assertEqual(event["actor"], "ops-admin")
        self.assertEqual(event["status"], "remediated")
        bucket = next(b for b in ctx.provider.snapshot()["s3_buckets"] if b["id"] == "stride-cloudtrail-logs")
        self.assertTrue(bucket["public_access_blocked"])

    def test_sensitive_setting_waits_for_approval_and_exception_stops_reflagging(self):
        ctx = self.ctx
        drift.baseline_apply(ctx)
        for t in itsm.list_tickets(ctx, status="active"):
            drift.decide(ctx, t["id"], "restore")
        ctx.provider.violate(ctx.control("NET.4"), "sg-db-0002", "dev-priya")
        s = drift.scan(ctx)
        self.assertEqual(len(s["tickets"]), 1)
        sg = next(g for g in ctx.provider.snapshot()["security_groups"] if g["id"] == "sg-db-0002")
        self.assertTrue(any(r["cidr"] == "0.0.0.0/0" for r in sg["ingress"]))   # not touched without approval
        drift.decide(ctx, s["tickets"][0], "accept", reason="temporary vendor access")
        self.assertEqual(len(drift.scan(ctx)["new"]), 0)
        self.assertEqual(ctx.store.one("SELECT COUNT(*) AS n FROM exceptions")["n"], 1)


class VulnTest(Base):
    def test_deadlines_follow_severity(self):
        vuln.scan(self.ctx)
        rows = {r["cve"]: r for r in self.ctx.store.q("SELECT * FROM vulnerabilities")}
        days = lambda r: (from_iso(r["due_at"]) - from_iso(r["first_seen"])).days
        self.assertEqual(rows["CVE-2021-44228"]["severity"], "zero-day")
        self.assertEqual(days(rows["CVE-2021-44228"]), 0)
        self.assertEqual(days(rows["CVE-2023-38408"]), 7)       # critical
        self.assertEqual(days(rows["CVE-2021-3156"]), 28)       # high
        self.assertEqual(days(rows["CVE-2023-2650"]), 90)       # medium
        self.assertEqual(vuln.scan(self.ctx)["new"], 0)         # rescanning raises no duplicates

    def test_failed_patch_rolls_back_and_reopens_then_retry_succeeds(self):
        ctx = self.ctx
        vuln.scan(ctx)
        job = patch.patch_server(ctx, "mfg-erp-01")
        self.assertEqual(job["status"], "rolled_back")
        self.assertEqual(len(vuln.open_vulns(ctx, instance_id=job["instance_id"])), 4)
        self.assertEqual({t["status"] for t in itsm.list_tickets(ctx, bu="manufacturing")}, {"reopened"})
        self.assertEqual(sum(1 for v in ctx.provider.list_vulnerabilities() if v["instance_id"] == job["instance_id"]), 4)
        job = patch.patch_server(ctx, "mfg-erp-01")
        self.assertEqual(job["status"], "success")
        self.assertEqual({t["status"] for t in itsm.list_tickets(ctx, bu="manufacturing")}, {"closed"})


class SchedulerTest(Base):
    def test_window_bounds(self):
        unit = self.ctx.bu("manufacturing")                     # SAT 20:00, 3 hours
        at = lambda s: datetime.strptime(s, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        self.assertTrue(scheduler.is_open(unit, at("2026-01-10 20:00")))
        self.assertTrue(scheduler.is_open(unit, at("2026-01-10 22:59")))
        self.assertFalse(scheduler.is_open(unit, at("2026-01-10 23:00")))
        self.assertFalse(scheduler.is_open(unit, at("2026-01-10 19:59")))
        self.assertEqual(scheduler.window_for(unit, at("2026-01-11 09:00"))[0], at("2026-01-17 20:00"))

    def test_hold_blocks_scheduled_patching(self):
        ctx = self.ctx
        vuln.scan(ctx)
        scheduler.hold(ctx, "finance-hr", "payroll run")
        ctx.store.set_now(from_iso("2026-01-09T21:00:00Z"))
        entry = scheduler.run(ctx, only_bu="finance-hr")[0]
        self.assertEqual(entry["jobs"], [])
        scheduler.release(ctx, "finance-hr")
        entry = scheduler.run(ctx, only_bu="finance-hr")[0]
        self.assertEqual(entry["jobs"][0]["status"], "success")


class RiskTest(Base):
    def test_overdue_and_exposure_raise_risk_and_alert_fires_once(self):
        ctx = self.ctx
        vuln.scan(ctx)
        first = {r["bu"]: r for r in risk.compute(ctx)}
        self.assertGreater(first["online-store"]["score"], first["manufacturing"]["score"])
        alerts = lambda: ctx.store.one("SELECT COUNT(*) AS n FROM notifications WHERE subject LIKE '%goal line%'")["n"]
        n = alerts()
        risk.compute(ctx)                                        # still above: no repeat alert the same day
        self.assertEqual(alerts(), n)
        ctx.store.advance(days=20)
        later = {r["bu"]: r for r in risk.compute(ctx)}
        self.assertGreater(later["finance-hr"]["score"], first["finance-hr"]["score"])
        self.assertGreater(alerts(), n)                          # weekly reminder


class EndToEndTest(Base):
    def test_demo_scenario_metrics(self):
        m = demo.run(self.ctx)
        self.assertEqual(m["assessment"]["detection_rate_pct"], 100.0)
        self.assertEqual(m["assessment"]["false_positives"], [])
        self.assertEqual(m["drift"]["attribution_accuracy_pct"], 100.0)
        self.assertEqual(m["drift"]["unresolved"], 0)
        self.assertEqual(m["vulnerabilities"]["open"], 0)
        self.assertEqual(m["patching"]["rolled_back"], 1)
        self.assertTrue(all(r["within_goal"] for r in m["risk"]))


if __name__ == "__main__":
    unittest.main()
