# Going live on AWS without surprise charges

The card on the account belongs to someone else, so the rule for this project is:
**nothing billable is created without the account holder seeing the plan and saying yes,
and everything is destroyed at the end of each working session.**

## 1. The strongest protection: the account plan

AWS accounts created since mid-2025 choose between two plans at sign-up. As far as I know:

| Plan | What it means |
|---|---|
| **Free plan** | Spends only the sign-up credits. The card is not charged. The account closes when credits run out or after 6 months unless you upgrade. Some services are not available. |
| **Paid plan** | Credits are used first, then the card is charged for anything beyond them. There is **no hard spending cap**; budgets only send emails. |

**Check this before anything else**: Billing and Cost Management console, then look for the
account plan and the credit balance. If the account is on the Free plan, the card cannot be
billed for this project. If it is on the Paid plan, the guardrails below are the only protection.

I have not been able to verify the plan rules or your credit balance from here. Confirm both in
the console. The amount is commonly 100 USD at sign-up plus up to 100 USD more for completing
onboarding tasks, so the full 200 may not be there on day one.

One risk on the Free plan: Security Hub, Inspector or Config might be restricted. If one is, the
system still runs; that data source is skipped and reported as unavailable.

## 2. Guardrails built into this project

- `terraform/main.tf` creates a **budget first**, with emails at 25, 50, 80 and 100 percent of
  a monthly limit (default 20 USD, measured before credits so you can see credits burning).
- The environment is small: 4 `t3.micro` servers with 8 GB disks, 3 buckets, no NAT gateway,
  no load balancer, no database service.
- AWS Config records only the 8 resource types the baseline watches.
- Planted IAM users carry a deny-all permissions boundary, so leaked credentials are useless.
- `terraform destroy` removes everything in one command.

## 3. What it should cost

My estimates for the Mumbai region, from memory of public pricing. Check them in the AWS
Pricing Calculator before relying on them.

| Item | While running | Notes |
|---|---|---|
| 4 x t3.micro servers | about 0.05 USD per hour | The main cost. Zero when destroyed. |
| 4 public IPv4 addresses | about 0.02 USD per hour | Charged while the servers exist. |
| 32 GB of disk | about 0.12 USD per day | |
| Amazon Inspector | free for 15 days, then about 1.25 USD per server per month | |
| Security Hub | free for 30 days, then a fraction of a cent per check | |
| AWS Config | about 0.003 USD per recorded change | A few cents per session. |
| CloudTrail, Lambda, SQS, SNS, S3 | effectively zero at this size | |

| Way of working | Estimated total |
|---|---|
| One 3-hour session, then destroy | under 1 USD |
| Twenty such sessions over the project | 10 to 20 USD |
| Left running by mistake for a month | 60 to 80 USD |

So the project fits well inside 200 USD of credits **if the environment is destroyed after each
session**. The realistic way to lose money is forgetting to destroy it.

## 4. Who does what

**You (I must not handle credentials or card details):**

1. Finish creating the account and confirm the plan and credit balance (section 1).
2. Turn on MFA for the root user.
3. Create an IAM user for this project with programmatic access, and run `aws configure`
   yourself in a terminal to store its keys. Do not paste keys into the chat.
4. Tell me the email address that should receive budget alerts.

**Me, each step only after you say yes:**

1. Install Terraform, the AWS CLI and boto3 on this machine.
2. Run `terraform plan` and show you exactly what would be created, with the cost table above.
3. Run `terraform apply` only on your go-ahead.
4. Run the assessment, baseline, drift, vulnerability and risk flows against the live account,
   fixing the AWS code where it meets reality.
5. Run `terraform destroy` at the end of the session and confirm in the billing console view
   that nothing is left running.

## 5. Stop conditions

I stop and ask before continuing if any of these happen:

- a budget alert email arrives;
- `terraform plan` shows a resource that is not in the cost table;
- anything needs a service outside the list above;
- a session would end with resources still running.

## 6. What the account actually allows (checked 12 November 2026)

- Plan: **Free**, 100 USD of credits, plan expires 11 May 2027.
- Region: only **Sydney (`ap-southeast-2`)** is usable. Every other region tested is blocked by the plan.
- Blocked even in Sydney: **Security Hub** and **Amazon Inspector**.
  - Assessment: the engine's own CIS checks do the work; the optional Security Hub merge is skipped.
  - Vulnerabilities: the engine asks each server's package manager (`yum updateinfo list cves`,
    through Systems Manager) which CVEs its pending updates fix, then scores them from NVD.
- `terraform plan` in Sydney: 53 resources to create, no errors. Server image:
  `amzn2-ami-hvm-2.0.20221210.1` (December 2022). `t3.micro` is free-tier eligible.
