"""Live run on AWS: a failed patch that rolls back, then out-of-schedule windows for every unit.

    CSPM_PROVIDER=aws CSPM_STATE=state-aws .venv/bin/python tools/live_patch_run.py

The rollback is provoked honestly: a bad line is added to nginx.conf on store-web-01 while
nginx is running. Nothing breaks until the patch job restarts the service, which is exactly
how a latent fault surfaces during real patching. Because the fault predates the snapshot,
the restored server still carries it; the script then removes the line and patches again.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cspm import drift, patch, risk, scheduler, vuln  # noqa: E402
from cspm.context import Context  # noqa: E402


def say(text):
    print(time.strftime("%H:%M:%S", time.gmtime()), text, flush=True)


def wait_online(provider, instance_id, minutes=12):
    deadline = time.time() + minutes * 60
    while time.time() < deadline:
        info = provider.ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])["InstanceInformationList"]
        if info and info[0]["PingStatus"] == "Online":
            return True
        time.sleep(15)
    return False


def main():
    ctx = Context(quiet=True)
    p = ctx.provider
    web = patch.find_instance(ctx, "store-web-01")["id"]

    say("planting a latent fault in nginx.conf on store-web-01")
    say(str(p._run(web, ["echo 'cspm_latent_fault;' >> /etc/nginx/nginx.conf; systemctl is-active nginx"], timeout=300)))

    say("self-service patch of store-web-01 (expected to fail its health check)")
    job = patch.patch_server(ctx, "store-web-01", mode="self-service")
    say(f"result: {job['status']} | {job['detail']}")
    risk.compute(ctx, label="Failed patch rolled back")

    say("waiting for store-web-01 to come back, then removing the fault")
    say(f"online: {wait_online(p, web)}")
    say(str(p._run(web, ["sed -i '/cspm_latent_fault/d' /etc/nginx/nginx.conf; nginx -t 2>&1 | tail -1; "
                         "systemctl restart nginx; systemctl is-active nginx"], timeout=300)))

    v = vuln.scan(ctx)
    say(f"vulnerability scan: {v['reported']} reported, {v['new']} new tickets, {v['fixed']} confirmed fixed")
    risk.compute(ctx, label="Rescan")

    for bu in ("online-store", "manufacturing", "finance-hr"):
        say(f"opening an out-of-schedule window for {bu}")
        entry = scheduler.run(ctx, only_bu=bu, force=True)[0]
        say(f"  {entry['status']}")
        for j in entry["jobs"]:
            say(f"  {j['server_name']}: {j['status']} | {j['detail']}")
        risk.compute(ctx, label=f"{entry['name']} window")

    v = vuln.scan(ctx)
    say(f"final vulnerability scan: {v['reported']} reported, {v['new']} new tickets, {v['fixed']} confirmed fixed")
    s = drift.scan(ctx)
    say(f"final drift scan: {len(s['new'])} new, {len(s['self_healed'])} found fixed")
    for r in risk.compute(ctx, label="After live patching"):
        say(f"  {r['bu_name']:<22} risk {r['score']:>7}  open vulns {r['open_vulns']}")
    say("done")


if __name__ == "__main__":
    main()
