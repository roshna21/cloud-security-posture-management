# Demo script: showing the project in 10 minutes

Use the **simulation** for the demo. It needs no AWS account, cannot fail on a network
problem, and you control the clock. Show the live AWS evidence at the end.

## Before you start

```bash
cd ~/Documents/cspm-project
python3 -m cspm web
```

Open http://localhost:8770 and press **Reset** (top right) so you start from a blank company.

## The script

| Minute | What you do | What you say |
|---|---|---|
| 0 to 1 | Stay on the empty Overview page. | "Mid-sized firms run on the cloud but can't afford commercial security posture tools. So nobody checks their settings, settings drift, and vulnerabilities stay unpatched because security finds them, IT needs downtime to fix them, and the business refuses the downtime. Nobody owns the risk. This system automates the work and makes each business unit own its number." |
| 1 to 2 | Click **Run the initial assessment**. Open **Assessment**. | "This is a sports-goods company with four servers, three storage buckets and a few users. The assessment checks 26 rules from the CIS Benchmark across five security domains. It found 26 gaps and 14 known vulnerabilities, each with a plain-language fix." |
| 2 to 3 | Open **Baseline and drift**. Click **Implement the MBSS**. | "The firm doesn't adopt all of CIS. It signs off its own subset, the Minimum Baseline Security Standard. Implementing it fixed 15 safe settings automatically. Seven sensitive ones were not touched: each became a ticket for the business unit head." |
| 3 to 4 | On one card click **Approve fix**; on another click **Accept risk** and type a reason. | "The head either approves the fix or formally accepts the risk. Accepted risks go into an exceptions register with an expiry date. That is the governance view." |
| 4 to 6 | In **Try it**, choose NET.1, a resource and a user. Click **Make the change**, then **Run drift scan**. | "Now someone opens SSH to the internet outside the process. The scan catches it, reads the audit trail to see who did it and when, and puts the setting back. If I pick a sensitive setting instead, it raises a ticket rather than fixing it." |
| 6 to 7 | Open **Vulnerabilities**. Click **Scan servers**. | "Each vulnerability is scored from the National Vulnerability Database and gets a deadline from its severity: 7 days for critical, 28 for high, 90 for medium, immediate for one being actively exploited. Each gets a ticket and the server owner gets one email per server." |
| 7 to 8 | Click **Patch now** on store-web-01. Open **Patching**. | "The owner can patch right away. The system takes a snapshot, stops the services, patches, restarts and runs health checks. If the checks fail, it restores the snapshot and reopens the tickets." Then use **Jump to window and patch** on Manufacturing to show a rollback. |
| 8 to 9 | On **Patching**, click **Decline downtime** for Finance and HR. Click **+1 week** twice. Open **Overview**. | "This is the core idea. Finance refuses downtime. Their deadlines pass, their risk score climbs above the goal line leadership set, and the head gets an alert that says: agreeing to downtime is how this comes down. The business owns the risk, not the security team." |
| 9 to 10 | Click a business unit card. Then open **Report** and **Print or save as PDF**. | "Each unit has its own page: where its risk comes from, its servers, its tickets. And this is the report leadership would receive." |

## Then show the live evidence

1. Start the console on the recorded AWS data: `python3 -m cspm --provider recorded web --port 8771 --state state-aws`
   and open http://localhost:8771. It is a read-only recording of the real run; the buttons cannot change anything.
2. Point out the real instance ids, the real CVE numbers, and the drift events traced to the real IAM user.
3. Say what was hard: "The free AWS plan only allowed one region and blocked Security Hub and
   Inspector, which the design relied on. I replaced Inspector by asking each server's package
   manager which CVEs its pending updates fix, and kept the assessment on the system's own CIS checks."

## Questions you should be ready for

- **Why not just use AWS Security Hub?** It reports findings; it doesn't decide what is safe to
  auto-fix, doesn't route approvals to the business, and doesn't turn findings into a risk
  number per business unit with a goal line.
- **How is the risk score calculated?** CVSS times exposure, criticality, exploitation and an
  overdue factor; plus points for unresolved settings. Read `cspm/risk.py`; it is 100 lines.
- **How do you know who changed a setting?** CloudTrail records every API call. The drift engine
  looks up the most recent matching call for that resource.
- **What happens if a patch breaks the server?** Snapshot before, health check after, restore on failure.
- **What is simulated and what is real?** Say it plainly: the simulation is a data file; the
  engine and every calculation are real; the AWS run was real but small.
- **Did you write all of it yourself?** Answer honestly, including the help you had.
