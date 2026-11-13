# Study guide: understand the project well enough to explain and change it

Work through this in order. After each part, close the file and explain it aloud in your own
words. If you can't, read that source file again; they are all short.

## 1. The words you must know

| Term | Meaning in one sentence |
|---|---|
| CSPM | Cloud Security Posture Management: continuously checking that cloud settings are safe. |
| CIS Benchmark | A public checklist of safe settings, published by the Center for Internet Security. |
| MBSS | Minimum Baseline Security Standard: the subset of CIS that this firm signed off. |
| Drift | A controlled setting that was compliant and then changed. |
| CloudTrail | AWS's audit log of who called which API and when. |
| AWS Config | AWS's record of how each resource's configuration changed over time. |
| CVE | A publicly catalogued vulnerability, with an id such as CVE-2021-44228. |
| CVSS | A 0 to 10 severity score for a CVE. |
| NVD | The National Vulnerability Database, which publishes CVSS scores. |
| SSM | AWS Systems Manager: runs commands and installs patches on servers without SSH. |
| Terraform | A tool that creates and destroys cloud resources from text files. |
| ITSM | IT Service Management: the ticketing system (simulated here). |
| Goal line | The most risk leadership accepts for a business unit. |

## 2. The shape of the code

```
config/            what the firm decided: rules, business units, deadlines, weights
cspm/checks.py     compares one rule with the environment        (start here, 100 lines)
cspm/assessment.py runs every rule once and writes the report
cspm/drift.py      baseline, drift detection, approvals, exceptions
cspm/vuln.py       scan -> score -> deadline -> ticket -> email
cspm/patch.py      snapshot -> stop -> patch -> start -> health check -> close or roll back
cspm/scheduler.py  weekly downtime windows and holds
cspm/risk.py       the risk score and goal-line alerts
cspm/itsm.py       tickets
cspm/store.py      the SQLite database and the clock
cspm/providers/    mock.py (simulated company) and aws.py (real AWS)
cspm/web.py        the web server; cspm/webui/ is the page
terraform/         the company's cloud, with planted issues
```

**The one design idea to remember:** the engine never talks to AWS directly. It asks a
*provider* for a snapshot of the environment in a neutral format. `mock.py` builds that
snapshot from a JSON file; `aws.py` builds it from AWS API calls. That is why the same
engine runs in simulation and live, and why another cloud could be added.

## 3. Exercises that prove you understand it

Do these yourself. Each takes 10 to 30 minutes.

1. **Read a rule.** Open `config/mbss.json`, find NET.1, and explain each field.
2. **Add a rule.** Add a control "NET.5: no security group allows Telnet (port 23) from the
   internet" by copying NET.1. Run `python3 -m cspm init` then `python3 -m cspm assess` and
   confirm it is checked.
3. **Plant an issue.** In `data/sample/environment.json`, add a port-23 rule open to
   `0.0.0.0/0` on one security group. Re-run the assessment and see your rule catch it.
4. **Change a deadline.** In `config/settings.json`, change critical from 7 days to 3. Run the
   tests (`python3 -m unittest discover -s tests`). One fails. Explain why, then fix the test.
5. **Change the risk model.** In `config/settings.json`, raise the internet exposure factor
   from 1.5 to 2.0. Predict what happens to Online Store's score, then check.
6. **Trace one drift event.** Run the demo, then `python3 -m cspm drift list`. Pick one row and
   find, in `cspm/drift.py`, the lines that detected it, attributed it and restored it.
7. **Read the AWS side.** In `cspm/providers/aws.py`, find `_fix_revoke_world_ingress` and
   explain which AWS API call removes the rule.

## 4. Numbers to know by heart

Simulation (two-week scripted scenario):

- 26 of 26 planted configuration issues and 14 of 14 planted CVEs detected
- 5 of 5 injected changes attributed to the right user
- 12 of 14 vulnerabilities fixed within deadline; 5 patch jobs, 1 rolled back

Live AWS run: see the "Live run" section of the README for the measured figures.

Be precise about what each number means. The simulation figures show the pipeline is wired
correctly; the ground truth was written by the same author as the checks. The live figures
are the ones that show it works on a real account.

## 5. Honest limits to state before anyone asks

- One cloud, four servers, 26 rules. It is a prototype.
- The risk formula and the scheduling rule are this project's own defaults, not a published model.
- Security Hub and Inspector were unavailable on the free AWS plan; the project works around both.
- On AWS only the 25 worst CVEs per server are ticketed per scan.
- Notifications on AWS all go to one topic; the ticketing system is simulated.
