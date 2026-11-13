# Evaluation results (mock provider)

Generated at 2026-01-19T09:00:00Z.

## Assessment

- Planted configuration issues detected: **26 of 26 (100.0%)**
- Planted vulnerabilities detected: **14 of 14 (100.0%)**
- Missed: none
- Findings not in the ground truth: none

| Domain | Planted | Detected |
|---|---:|---:|
| Identity and access | 6 | 6 |
| Data protection | 8 | 8 |
| Network | 4 | 4 |
| Logging and monitoring | 4 | 4 |
| Server security | 4 | 4 |

## Drift management

- Drift events detected: **5** (5 attributed to a user)
- Mean time to detect: **4.0 min**
- Mean time to remediate, automatic: **0.0 min** (4 events)
- Mean time to remediate, with approval: **39.0 min** (1 events)
- Accepted as exception: 0; unresolved: 0
- Injected changes detected: 5 of 5
- Attribution accuracy: **5 of 5 (100.0%)**

## Vulnerability management

- Vulnerabilities: 14 total, 14 fixed, 0 open (0 past deadline)
- Fixed within deadline: **12 of 14 (85.7%)** (zero-day tickets count as on time when fixed within 48 hours of detection)
- Mean days to fix: 8.0
- Patch jobs: 5; success rate **80.0%**, rollback rate **20.0%**

## Risk per business unit

| Business unit | Goal line | Initial | Peak | Latest | Within goal |
|---|---:|---:|---:|---:|---|
| Online Store | 30 | 145.6 | 145.6 | 0.0 | yes |
| Manufacturing | 20 | 39.7 | 39.7 | 0.0 | yes |
| Finance and HR | 25 | 70.4 | 70.4 | 0.0 | yes |
| Shared Platform (IT) | 15 | 55.0 | 55.0 | 0.0 | yes |
