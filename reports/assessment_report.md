# Cloud Security Assessment Report: Stride Sports Goods Pvt Ltd

Assessment run 1 at 2026-01-05T09:00:00Z, provider `mock`. Baseline: CIS AWS Foundations Benchmark v3.0.0 and CIS Amazon Linux 2 Benchmark.

## Summary

- **26 configuration gaps** across 5 security domains: 3 critical, 9 high, 8 medium, 6 low.
- **14 server vulnerabilities**: 1 zero-day, 2 critical, 7 high, 4 medium.

| Domain | Controls checked | Resource checks | Passed | Gaps |
|---|---:|---:|---:|---:|
| Identity and access | 7 | 15 | 9 | 6 |
| Data protection | 6 | 17 | 9 | 8 |
| Network | 4 | 16 | 12 | 4 |
| Logging and monitoring | 5 | 7 | 3 | 4 |
| Server security | 4 | 16 | 12 | 4 |

## Identity and access

| Severity | Control | Resource | Business unit | Gap | Recommended fix |
|---|---|---|---|---|---|
| critical | IAM.1 MFA is enabled for the root user (CIS AWS 1.5) | AWS account | Shared Platform (IT) | The root user has no MFA device | Sign in as root and register an MFA device. This cannot be automated. |
| high | IAM.4 MFA is enabled for all IAM users with a console password (CIS AWS 1.10) | ops-admin | Shared Platform (IT) | This user can sign in to the console without MFA | Have the user register an MFA device, or remove their console password. |
| high | IAM.6 No IAM user has a full administrator policy attached directly (CIS AWS 1.16) | ops-admin | Shared Platform (IT) | This user has the full administrator policy attached directly | Detach AdministratorAccess and grant only the permissions the user needs, through a group or role. |
| medium | IAM.2 IAM password policy requires a minimum length of 14 (CIS AWS 1.8) | AWS account | Shared Platform (IT) | The password policy allows passwords as short as 8 characters; the baseline requires 14 | Set the account password policy minimum length to 14 or more. |
| medium | IAM.5 Access keys are rotated every 90 days or less (CIS AWS 1.14) | dev-priya | Shared Platform (IT) | This user's access key is 200 days old; the limit is 90 | Create a new access key, update the applications that use it, then deactivate the old key. |
| low | IAM.7 Hardware MFA is enabled for the root user (CIS AWS 1.6) *(not adopted in MBSS)* | AWS account | Shared Platform (IT) | The root user is not protected by a hardware MFA device | Register a hardware MFA device for the root user. |

## Data protection

| Severity | Control | Resource | Business unit | Gap | Recommended fix |
|---|---|---|---|---|---|
| critical | DP.1 S3 buckets block public access (CIS AWS 2.1.4) | stride-product-images | Online Store | Block Public Access is off, so the bucket can be made public | Turn on all four Block Public Access settings for the bucket. |
| high | DP.5 EBS volumes attached to servers are encrypted (CIS AWS 2.2.1 (existing volumes)) | store-web-01 | Online Store | The server has a disk that is not encrypted | Snapshot the volume, copy the snapshot with encryption, and replace the volume in a downtime window. |
| medium | DP.2 S3 bucket policy denies requests that do not use HTTPS (CIS AWS 2.1.1) | stride-product-images | Online Store | The bucket accepts unencrypted (HTTP) requests | Add a bucket policy statement that denies requests where aws:SecureTransport is false. |
| medium | DP.4 EBS encryption by default is enabled (CIS AWS 2.2.1) | AWS account | Shared Platform (IT) | New disks are not encrypted by default | Enable EBS encryption by default in the region. |
| low | DP.3 S3 bucket versioning is enabled (CIS AWS 2.1.3 (data recovery)) | stride-finance-reports | Finance and HR | Versioning is off, so deleted or overwritten objects cannot be recovered | Enable versioning on the bucket. |
| low | DP.6 MFA delete is enabled on S3 buckets (CIS AWS 2.1.2) *(not adopted in MBSS)* | stride-product-images | Online Store | MFA delete is off | Enable MFA delete using the root user's credentials. |
| low | DP.6 MFA delete is enabled on S3 buckets (CIS AWS 2.1.2) *(not adopted in MBSS)* | stride-finance-reports | Finance and HR | MFA delete is off | Enable MFA delete using the root user's credentials. |
| low | DP.6 MFA delete is enabled on S3 buckets (CIS AWS 2.1.2) *(not adopted in MBSS)* | stride-cloudtrail-logs | Shared Platform (IT) | MFA delete is off | Enable MFA delete using the root user's credentials. |

## Network

| Severity | Control | Resource | Business unit | Gap | Recommended fix |
|---|---|---|---|---|---|
| critical | NET.4 No security group allows database ports (3306, 5432) from the internet (CIS AWS 5.2 (database ports)) | fin-payroll-sg | Finance and HR | Anyone on the internet can reach port 3306 | Remove the 0.0.0.0/0 rule and allow the database port only from the application tier. |
| high | NET.1 No security group allows SSH (port 22) from the internet (CIS AWS 5.2) | store-web-sg | Online Store | Anyone on the internet can reach port 22 | Remove the 0.0.0.0/0 rule for port 22 and use Systems Manager Session Manager or a restricted source range. |
| high | NET.2 No security group allows RDP (port 3389) from the internet (CIS AWS 5.3) | mfg-erp-sg | Manufacturing | Anyone on the internet can reach port 3389 | Remove the 0.0.0.0/0 rule for port 3389. |
| medium | NET.3 The default security group of every VPC restricts all traffic (CIS AWS 5.4) | default | Shared Platform (IT) | The default security group still has rules | Remove all rules from the default security group and move resources to purpose-built groups. |

## Logging and monitoring

| Severity | Control | Resource | Business unit | Gap | Recommended fix |
|---|---|---|---|---|---|
| high | LOG.1 CloudTrail is enabled in all regions (CIS AWS 3.1) | stride-trail | Shared Platform (IT) | The audit trail only covers one region | Make the trail a multi-region trail. |
| medium | LOG.2 CloudTrail log file validation is enabled (CIS AWS 3.2) | stride-trail | Shared Platform (IT) | Log file validation is off, so tampering with audit logs would go unnoticed | Enable log file validation on the trail. |
| medium | LOG.4 VPC flow logging is enabled (CIS AWS 3.7) | stride-vpc | Shared Platform (IT) | Network flow logging is off | Create a flow log for the VPC that captures rejected traffic at minimum. |
| low | LOG.5 S3 server access logging is enabled on buckets (CIS AWS 3.4) | stride-finance-reports | Finance and HR | Access to the bucket is not being logged | Enable server access logging to the central log bucket. |

## Server security

| Severity | Control | Resource | Business unit | Gap | Recommended fix |
|---|---|---|---|---|---|
| high | SRV.1 EC2 instances require IMDSv2 (CIS AWS 5.6) | store-web-01 | Online Store | The server still accepts the older, weaker metadata service (IMDSv1) | Set the instance metadata option HttpTokens to required. |
| high | SRV.1 EC2 instances require IMDSv2 (CIS AWS 5.6) | fin-payroll-01 | Finance and HR | The server still accepts the older, weaker metadata service (IMDSv1) | Set the instance metadata option HttpTokens to required. |
| high | SRV.3 SSH root login is disabled (CIS Amazon Linux 2 5.2.10) | store-web-01 | Online Store | Root can log in over SSH | Set PermitRootLogin no in /etc/ssh/sshd_config and reload sshd. |
| medium | SRV.4 SSH password authentication is disabled (CIS Amazon Linux 2 5.2 (authentication)) | mfg-erp-01 | Manufacturing | SSH accepts passwords instead of keys only | Set PasswordAuthentication no in /etc/ssh/sshd_config and reload sshd. |

## Server vulnerabilities

| Severity | CVE | CVSS | Server | Package | Installed | Fixed in | Deadline once ticketed |
|---|---|---:|---|---|---|---|---|
| zero-day | CVE-2021-44228 | 10.0 | store-web-01 | log4j-core | 2.14.1 | 2.17.1 | immediate |
| critical | CVE-2023-38408 | 9.8 | fin-payroll-01 | openssh | 7.4p1 | 9.3p2 | 7 days |
| critical | CVE-2022-22965 | 9.8 | fin-payroll-01 | spring-webmvc | 5.3.15 | 5.3.18 | 7 days |
| high | CVE-2024-6387 | 8.1 | store-web-01 | openssh | 8.7p1 | 9.8p1 | 28 days |
| high | CVE-2023-4911 | 7.8 | store-db-01 | glibc | 2.34-60 | 2.34-83 | 28 days |
| high | CVE-2021-3156 | 7.8 | mfg-erp-01 | sudo | 1.8.23 | 1.9.5p2 | 28 days |
| high | CVE-2021-4034 | 7.8 | mfg-erp-01 | polkit | 0.112 | 0.120 | 28 days |
| high | CVE-2022-0847 | 7.8 | mfg-erp-01 | kernel | 5.10.90 | 5.10.102 | 28 days |
| high | CVE-2023-44487 | 7.5 | store-web-01 | nginx | 1.20.0 | 1.25.3 | 28 days |
| high | CVE-2023-0286 | 7.4 | fin-payroll-01 | openssl | 1.1.1k | 1.1.1t | 28 days |
| medium | CVE-2023-2650 | 6.5 | store-db-01 | openssl | 3.0.7 | 3.0.9 | 90 days |
| medium | CVE-2023-48795 | 5.9 | store-web-01 | openssh | 8.7p1 | 9.6p1 | 90 days |
| medium | CVE-2020-1971 | 5.9 | fin-payroll-01 | openssl | 1.1.1g | 1.1.1i | 90 days |
| medium | CVE-2023-5678 | 5.3 | mfg-erp-01 | openssl | 1.0.2k | 1.0.2zj | 90 days |
