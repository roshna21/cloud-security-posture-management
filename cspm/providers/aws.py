"""AWS provider (boto3).

Data sources:  IAM, S3, EC2, CloudTrail, AWS Config, Security Hub, Inspector, SSM.
Actions:       direct API calls for configuration fixes, Systems Manager Run
               Command and Patch Manager for servers, EBS snapshots for rollback,
               SNS for email, SQS for change events forwarded by the drift Lambda.

NOTE: this module has not been run against a live AWS account. It was written
against the boto3 API reference; expect to adjust details the first time it
meets the real environment built by terraform/.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import NotAutomatable

WORLD = ("0.0.0.0/0", "::/0")
ADMIN_POLICY_SUFFIX = ":policy/AdministratorAccess"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tags(tag_list: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
    return {t["Key"]: t["Value"] for t in (tag_list or [])}


class AwsProvider:
    name = "aws"

    def __init__(self, cfg: Dict[str, Any]):
        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError as exc:
            raise RuntimeError("the AWS provider needs boto3: pip install boto3") from exc
        self.cfg = cfg
        self.ClientError = ClientError
        session = boto3.Session(region_name=cfg["region"])
        for name in ("ec2", "iam", "s3", "cloudtrail", "config", "ssm", "inspector2",
                     "sns", "sqs", "securityhub", "sts"):
            setattr(self, name, session.client(name))
        # The identity the engine itself runs as. It is never assessed or "fixed":
        # detaching its admin policy or deactivating its key would lock the engine out.
        self.own_user = self.sts.get_caller_identity()["Arn"].split("/")[-1]
        self.project = cfg.get("project_tag", "")

    def _in_scope(self, tags: Dict[str, str]) -> bool:
        """Network resources are limited to the project's own, so the account's default VPC is left alone."""
        return not self.project or tags.get("Project") == self.project

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------
    def snapshot(self) -> Dict[str, Any]:
        return {
            "account": self._account(),
            "iam_users": self._iam_users(),
            "s3_buckets": self._buckets(),
            "security_groups": self._security_groups(),
            "vpcs": self._vpcs(),
            "trails": self._trails(),
            "instances": self._instances(),
        }

    def _account(self) -> Dict[str, Any]:
        summary = self.iam.get_account_summary()["SummaryMap"]
        root_mfa = summary.get("AccountMFAEnabled", 0) == 1
        virtual = self.iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")["VirtualMFADevices"]
        root_virtual = any(d["SerialNumber"].endswith(":mfa/root-account-mfa-device") for d in virtual)
        try:
            pol = self.iam.get_account_password_policy()["PasswordPolicy"]
            policy = {"min_length": pol.get("MinimumPasswordLength", 8),
                      "reuse_prevention": pol.get("PasswordReusePrevention", 0)}
        except self.ClientError:
            policy = {"min_length": 8, "reuse_prevention": 0}  # AWS default when no policy is set
        recorders = self.config.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
        return {
            "id": "account", "name": "AWS account", "bu": "platform",
            "root_mfa": root_mfa, "root_hardware_mfa": root_mfa and not root_virtual,
            "password_policy": policy,
            "ebs_default_encryption": self.ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"],
            "config_recorder": any(r.get("recording") for r in recorders),
        }

    def _iam_users(self) -> List[Dict[str, Any]]:
        users = []
        now = datetime.now(timezone.utc)
        for page in self.iam.get_paginator("list_users").paginate():
            for u in page["Users"]:
                name = u["UserName"]
                if name == self.own_user:
                    continue
                try:
                    self.iam.get_login_profile(UserName=name)
                    console = True
                except self.ClientError:
                    console = False
                keys = self.iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
                ages = [(now - k["CreateDate"]).days for k in keys if k["Status"] == "Active"]
                attached = self.iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
                tags = _tags(self.iam.list_user_tags(UserName=name)["Tags"])
                users.append({
                    "id": name, "name": name, "bu": tags.get("BusinessUnit", "platform"),
                    "console_access": console,
                    "mfa": bool(self.iam.list_mfa_devices(UserName=name)["MFADevices"]),
                    "access_key_age_days": max(ages) if ages else 0,
                    "admin_policy": any(p["PolicyArn"].endswith(ADMIN_POLICY_SUFFIX) for p in attached),
                })
        return users

    def _buckets(self) -> List[Dict[str, Any]]:
        out = []
        for b in self.s3.list_buckets()["Buckets"]:
            name = b["Name"]
            try:
                pab = self.s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                blocked = all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                                   "BlockPublicPolicy", "RestrictPublicBuckets"))
            except self.ClientError:
                blocked = False
            try:
                policy = json.loads(self.s3.get_bucket_policy(Bucket=name)["Policy"])
            except self.ClientError:
                policy = {"Statement": []}
            ssl = any(
                s.get("Effect") == "Deny"
                and str(s.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport", "")).lower() == "false"
                for s in policy.get("Statement", []))
            versioning = self.s3.get_bucket_versioning(Bucket=name)
            try:
                tags = _tags(self.s3.get_bucket_tagging(Bucket=name)["TagSet"])
            except self.ClientError:
                tags = {}
            out.append({
                "id": name, "name": name, "bu": tags.get("BusinessUnit", "platform"),
                "public_access_blocked": blocked, "ssl_enforced": ssl,
                "versioning": versioning.get("Status") == "Enabled",
                "mfa_delete": versioning.get("MFADelete") == "Enabled",
                # The central log bucket is where access logs are delivered; it does not log to itself.
                "access_logging": name == self.cfg.get("log_bucket") or "LoggingEnabled" in self.s3.get_bucket_logging(Bucket=name),
            })
        return out

    def _security_groups(self) -> List[Dict[str, Any]]:
        out = []
        for page in self.ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                if not self._in_scope(_tags(sg.get("Tags"))):
                    continue
                rules = []
                for perm in sg["IpPermissions"]:
                    all_ports = perm["IpProtocol"] == "-1"
                    cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])] + \
                            [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
                    for cidr in cidrs:
                        rules.append({
                            "protocol": perm["IpProtocol"],
                            "from_port": 0 if all_ports else perm.get("FromPort", 0),
                            "to_port": 65535 if all_ports else perm.get("ToPort", 65535),
                            "cidr": cidr,
                        })
                    # Rules that reference another security group count as rules for the default-SG check.
                    for pair in perm.get("UserIdGroupPairs", []):
                        rules.append({"protocol": perm["IpProtocol"], "from_port": perm.get("FromPort", 0),
                                      "to_port": perm.get("ToPort", 65535), "cidr": pair["GroupId"]})
                out.append({
                    "id": sg["GroupId"], "name": sg["GroupName"],
                    "bu": _tags(sg.get("Tags")).get("BusinessUnit", "platform"),
                    "is_default": sg["GroupName"] == "default", "ingress": rules,
                })
        return out

    def _vpcs(self) -> List[Dict[str, Any]]:
        flow = {f["ResourceId"] for f in self.ec2.describe_flow_logs()["FlowLogs"]}
        return [{"id": v["VpcId"], "name": _tags(v.get("Tags")).get("Name", v["VpcId"]),
                 "bu": "platform", "flow_logs": v["VpcId"] in flow}
                for v in self.ec2.describe_vpcs()["Vpcs"] if self._in_scope(_tags(v.get("Tags")))]

    def _trails(self) -> List[Dict[str, Any]]:
        return [{"id": t["Name"], "name": t["Name"], "bu": "platform",
                 "multi_region": t.get("IsMultiRegionTrail", False),
                 "log_validation": t.get("LogFileValidationEnabled", False)}
                for t in self.cloudtrail.describe_trails(includeShadowTrails=False)["trailList"]]

    def _instances(self) -> List[Dict[str, Any]]:
        managed = set()
        for page in self.ssm.get_paginator("describe_instance_information").paginate():
            managed.update(i["InstanceId"] for i in page["InstanceInformationList"] if i["PingStatus"] == "Online")
        out = []
        pages = self.ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}])
        for page in pages:
            for res in page["Reservations"]:
                for i in res["Instances"]:
                    tags = _tags(i.get("Tags"))
                    if not self._in_scope(tags):
                        continue
                    vol_ids = [m["Ebs"]["VolumeId"] for m in i.get("BlockDeviceMappings", []) if "Ebs" in m]
                    vols = self.ec2.describe_volumes(VolumeIds=vol_ids)["Volumes"] if vol_ids else []
                    is_managed = i["InstanceId"] in managed
                    out.append({
                        "id": i["InstanceId"], "name": tags.get("Name", i["InstanceId"]),
                        "bu": tags.get("BusinessUnit", "platform"),
                        "owner": tags.get("Owner", ""), "owner_email": tags.get("OwnerEmail", ""),
                        "criticality": tags.get("Criticality", "medium").lower(),
                        "internet_facing": tags.get("InternetFacing", "false").lower() == "true",
                        "imdsv2_required": i.get("MetadataOptions", {}).get("HttpTokens") == "required",
                        "ssm_managed": is_managed,
                        "volumes_encrypted": all(v["Encrypted"] for v in vols),
                        "os": self._sshd_settings(i["InstanceId"]) if is_managed else
                              {"permit_root_login": None, "password_auth": None},
                        "services": [s.strip() for s in tags.get("Services", "").split(",") if s.strip()],
                    })
        return out

    def _sshd_settings(self, instance_id: str) -> Dict[str, Optional[bool]]:
        """Read two CIS operating-system settings through Run Command. None means 'could not verify'."""
        status, stdout = self._run(instance_id, ["sshd -T 2>/dev/null | egrep '^(permitrootlogin|passwordauthentication) '"])
        values = dict(line.split(None, 1) for line in stdout.splitlines() if " " in line)
        if status != "Success" or not values:
            return {"permit_root_login": None, "password_auth": None}
        return {"permit_root_login": values.get("permitrootlogin", "yes").strip() != "no",
                "password_auth": values.get("passwordauthentication", "yes").strip() != "no"}

    # ------------------------------------------------------------------
    # Systems Manager helper
    # ------------------------------------------------------------------
    def _run(self, instance_id: str, commands: Optional[List[str]] = None, document: str = "AWS-RunShellScript",
             parameters: Optional[Dict[str, List[str]]] = None, timeout: int = 1800) -> Tuple[str, str]:
        params = parameters if parameters is not None else {"commands": commands or []}
        cmd = self.ssm.send_command(InstanceIds=[instance_id], DocumentName=document, Parameters=params,
                                    Comment="cspm")["Command"]["CommandId"]
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(3)
            try:
                inv = self.ssm.get_command_invocation(CommandId=cmd, InstanceId=instance_id)
            except self.ClientError:
                continue  # the invocation is not registered yet
            if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
                return inv["Status"], inv.get("StandardOutputContent", "")
        return "TimedOut", ""

    # ------------------------------------------------------------------
    # Attribution
    # ------------------------------------------------------------------
    def lookup_change(self, resource_id: str, event_names: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        """Most recent matching CloudTrail management event. CloudTrail can lag a change by several minutes."""
        if resource_id == "account":
            lookups = [{"AttributeKey": "EventName", "AttributeValue": n} for n in (event_names or [])]
        else:
            lookups = [{"AttributeKey": "ResourceName", "AttributeValue": resource_id}]
        best = None
        for attr in lookups:
            events = self.cloudtrail.lookup_events(LookupAttributes=[attr], MaxResults=50)["Events"]
            for e in events:
                if event_names and e["EventName"] not in event_names:
                    continue
                if best is None or e["EventTime"] > best["EventTime"]:
                    best = e
        if best is None:
            return None
        detail = json.loads(best.get("CloudTrailEvent", "{}"))
        return {"time": _iso(best["EventTime"]), "user": best.get("Username", "unknown"),
                "event_name": best["EventName"], "source_ip": detail.get("sourceIPAddress", "")}

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------
    def remediate(self, control: Dict[str, Any], resource_id: str) -> str:
        action = control["remediation"]["action"]
        handler = getattr(self, f"_fix_{action}", None)
        if action == "manual" or handler is None:
            raise NotAutomatable(control["recommendation"])
        return handler(control, resource_id)

    def _fix_set_password_policy(self, control, resource_id) -> str:
        try:
            current = self.iam.get_account_password_policy()["PasswordPolicy"]
        except self.ClientError:
            current = {}
        allowed = ("RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", "RequireLowercaseCharacters",
                   "AllowUsersToChangePassword", "MaxPasswordAge", "HardExpiry")
        args = {k: current[k] for k in allowed if k in current}
        args["MinimumPasswordLength"] = max(14, current.get("MinimumPasswordLength", 0))
        args["PasswordReusePrevention"] = max(24, current.get("PasswordReusePrevention", 0))
        self.iam.update_account_password_policy(**args)
        return "password policy set to length 14, reuse prevention 24"

    def _fix_block_s3_public_access(self, control, bucket) -> str:
        self.s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        return "all four Block Public Access settings turned on"

    def _fix_enforce_s3_ssl(self, control, bucket) -> str:
        try:
            policy = json.loads(self.s3.get_bucket_policy(Bucket=bucket)["Policy"])
        except self.ClientError:
            policy = {"Version": "2012-10-17", "Statement": []}
        policy["Statement"].append({
            "Sid": "CspmDenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}})
        self.s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
        return "bucket policy now denies non-HTTPS requests"

    def _fix_enable_s3_versioning(self, control, bucket) -> str:
        self.s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        return "versioning enabled"

    def _log_bucket(self) -> str:
        bucket = self.cfg.get("log_bucket")
        if not bucket:
            raise NotAutomatable("set aws.log_bucket in config/settings.json (terraform output log_bucket)")
        return bucket

    def _fix_enable_s3_logging(self, control, bucket) -> str:
        self.s3.put_bucket_logging(Bucket=bucket, BucketLoggingStatus={"LoggingEnabled": {
            "TargetBucket": self._log_bucket(), "TargetPrefix": f"s3-access/{bucket}/"}})
        return "server access logging enabled"

    def _fix_enable_ebs_default_encryption(self, control, resource_id) -> str:
        self.ec2.enable_ebs_encryption_by_default()
        return "EBS encryption by default enabled"

    def _fix_revoke_world_ingress(self, control, group_id) -> str:
        ports = control["check"]["ports"]
        sg = self.ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
        revoke = []
        for perm in sg["IpPermissions"]:
            lo = 0 if perm["IpProtocol"] == "-1" else perm.get("FromPort", 0)
            hi = 65535 if perm["IpProtocol"] == "-1" else perm.get("ToPort", 65535)
            if not any(lo <= p <= hi for p in ports):
                continue
            v4 = [r for r in perm.get("IpRanges", []) if r["CidrIp"] in WORLD]
            v6 = [r for r in perm.get("Ipv6Ranges", []) if r["CidrIpv6"] in WORLD]
            if v4 or v6:
                entry = {"IpProtocol": perm["IpProtocol"], "IpRanges": v4, "Ipv6Ranges": v6}
                if perm["IpProtocol"] != "-1":
                    entry.update(FromPort=perm["FromPort"], ToPort=perm["ToPort"])
                revoke.append(entry)
        if revoke:
            self.ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=revoke)
        return f"revoked {len(revoke)} internet ingress rule(s)"

    def _fix_clear_default_sg(self, control, group_id) -> str:
        sg = self.ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
        if sg["IpPermissions"]:
            self.ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=sg["IpPermissions"])
        return "all ingress rules removed from the default security group"

    def _fix_enable_trail_multi_region(self, control, trail) -> str:
        self.cloudtrail.update_trail(Name=trail, IsMultiRegionTrail=True, IncludeGlobalServiceEvents=True)
        return "trail is now multi-region"

    def _fix_enable_trail_log_validation(self, control, trail) -> str:
        self.cloudtrail.update_trail(Name=trail, EnableLogFileValidation=True)
        return "log file validation enabled"

    def _fix_start_config_recorder(self, control, resource_id) -> str:
        for rec in self.config.describe_configuration_recorders()["ConfigurationRecorders"]:
            self.config.start_configuration_recorder(ConfigurationRecorderName=rec["name"])
        return "configuration recorder started"

    def _fix_enable_flow_logs(self, control, vpc_id) -> str:
        self.ec2.create_flow_logs(ResourceIds=[vpc_id], ResourceType="VPC", TrafficType="REJECT",
                                  LogDestinationType="s3",
                                  LogDestination=f"arn:aws:s3:::{self._log_bucket()}/vpc-flow-logs/")
        return "VPC flow log created"

    def _fix_require_imdsv2(self, control, instance_id) -> str:
        self.ec2.modify_instance_metadata_options(InstanceId=instance_id, HttpTokens="required", HttpEndpoint="enabled")
        return "IMDSv2 required"

    def _fix_harden_sshd(self, control, instance_id) -> str:
        p = control["remediation"]["params"]
        setting, value = p["setting"], p["value"]
        status, _ = self._run(instance_id, [
            f"sed -i -E '/^[#[:space:]]*{setting}[[:space:]]/d' /etc/ssh/sshd_config",
            f"echo '{setting} {value}' >> /etc/ssh/sshd_config",
            "sshd -t && systemctl reload sshd",
        ])
        if status != "Success":
            raise RuntimeError(f"Run Command ended with status {status}")
        return f"sshd {setting} set to {value}"

    def _fix_deactivate_old_access_keys(self, control, user) -> str:
        limit = control["check"]["value"]
        now = datetime.now(timezone.utc)
        n = 0
        for k in self.iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
            if k["Status"] == "Active" and (now - k["CreateDate"]).days > limit:
                self.iam.update_access_key(UserName=user, AccessKeyId=k["AccessKeyId"], Status="Inactive")
                n += 1
        return f"deactivated {n} access key(s) older than {limit} days"

    def _fix_detach_admin_policy(self, control, user) -> str:
        for p in self.iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]:
            if p["PolicyArn"].endswith(ADMIN_POLICY_SUFFIX):
                self.iam.detach_user_policy(UserName=user, PolicyArn=p["PolicyArn"])
        return "AdministratorAccess detached"

    # ------------------------------------------------------------------
    # Assessment extras
    # ------------------------------------------------------------------
    def security_hub_findings(self) -> List[Dict[str, Any]]:
        """Failed controls from Security Hub (CIS AWS Foundations standard must be enabled)."""
        domain_of = {"IAM": "Identity and access", "S3": "Data protection", "KMS": "Data protection",
                     "RDS": "Data protection", "EFS": "Data protection", "EC2": "Network",
                     "CloudTrail": "Logging and monitoring", "Config": "Logging and monitoring",
                     "CloudWatch": "Logging and monitoring", "SSM": "Server security"}
        out = []
        filters = {"ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
                   "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}
        try:
            pages = self.securityhub.get_paginator("get_findings").paginate(Filters=filters)
            for page in pages:
                for f in page["Findings"]:
                    control = f.get("Compliance", {}).get("SecurityControlId", "")
                    res = (f.get("Resources") or [{}])[0]
                    rid = res.get("Id", "").split("/")[-1].split(":")[-1] or "account"
                    label = f.get("Severity", {}).get("Label", "LOW").lower()
                    rec = f.get("Remediation", {}).get("Recommendation", {})
                    out.append({
                        "control_id": f"SH-{control}", "cis_ref": f"Security Hub {control}",
                        "domain": domain_of.get(control.split(".")[0], "Server security"),
                        "title": f.get("Title", ""),
                        "severity": label if label in ("critical", "high", "medium", "low") else "low",
                        "resource_type": res.get("Type", ""), "resource_id": rid, "resource_name": rid,
                        "bu": _tags([{"Key": k, "Value": v} for k, v in (res.get("Tags") or {}).items()]).get("BusinessUnit", "platform"),
                        "detail": f.get("Description", ""),
                        "recommendation": " ".join(x for x in (rec.get("Text"), rec.get("Url")) if x),
                    })
        except self.ClientError:
            return []  # Security Hub is not enabled in this account
        return out

    # ------------------------------------------------------------------
    # Vulnerabilities and patching
    # ------------------------------------------------------------------
    def list_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Amazon Inspector when the account can use it; otherwise the servers' own package manager."""
        if self.cfg.get("vulnerability_source") != "package-manager":
            try:
                return self._inspector_findings()
            except self.ClientError:
                self.cfg["vulnerability_source"] = "package-manager"   # blocked or not enabled: stop retrying
        return self._package_manager_cves()

    def _package_manager_cves(self) -> List[Dict[str, Any]]:
        """Ask each server which CVEs its pending security updates fix (Amazon Linux `yum updateinfo`).

        Runs through Systems Manager Run Command, costs nothing, and reports real CVE identifiers
        with the vendor's severity. Only the worst `max_cves_per_server` are returned per server,
        because an old image can have hundreds and Run Command output is limited in size.
        """
        limit = int(self.cfg.get("max_cves_per_server", 25))
        script = (
            "yum -q updateinfo list cves 2>/dev/null | awk '$1 ~ /^CVE-/ {print $1, $2, $3}' | sort -u -k1,1 | "
            "awk '{o=4} $2 ~ /^[Cc]ritical/ {o=1} $2 ~ /^[Ii]mportant/ {o=2} $2 ~ /^([Mm]edium|[Mm]oderate)/ {o=3} {print o, $0}' | "
            f"sort -n | head -{limit} | cut -d' ' -f2-"
        )
        fallback_score = {"critical": 9.5, "important": 7.5, "medium": 5.5, "moderate": 5.5, "low": 2.5}
        managed = []
        for page in self.ssm.get_paginator("describe_instance_information").paginate():
            managed += [i["InstanceId"] for i in page["InstanceInformationList"] if i["PingStatus"] == "Online"]
        out = []
        for instance_id in managed:
            status, stdout = self._run(instance_id, [script], timeout=600)
            if status != "Success":
                continue
            for line in stdout.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                cve, severity, package = parts[0], parts[1].split("/")[0].lower(), parts[2]
                name = package.rsplit("-", 2)[0] if package.count("-") >= 2 else package
                out.append({
                    "instance_id": instance_id, "cve": cve, "package": name, "installed_version": "",
                    "fixed_version": package[len(name) + 1:] if package.startswith(name + "-") else package,
                    "cvss": fallback_score.get(severity, 5.5),     # used only when NVD has no score cached
                    "description": f"Vendor severity: {severity}. Fixed by updating {name}.",
                })
        return out

    def _inspector_findings(self) -> List[Dict[str, Any]]:
        criteria = {
            "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
            "resourceType": [{"comparison": "EQUALS", "value": "AWS_EC2_INSTANCE"}],
        }
        seen, out = set(), []
        for page in self.inspector2.get_paginator("list_findings").paginate(filterCriteria=criteria):
            for f in page["findings"]:
                detail = f.get("packageVulnerabilityDetails", {})
                cve = detail.get("vulnerabilityId", "")
                instance_id = f["resources"][0]["id"]
                if not cve.startswith("CVE-") or (instance_id, cve) in seen:
                    continue
                seen.add((instance_id, cve))
                pkg = (detail.get("vulnerablePackages") or [{}])[0]
                out.append({
                    "instance_id": instance_id, "cve": cve, "package": pkg.get("name", ""),
                    "installed_version": pkg.get("version", ""),
                    "fixed_version": pkg.get("fixedInVersion", "") if pkg.get("fixedInVersion") != "NotAvailable" else "",
                    "cvss": f.get("inspectorScore"), "description": f.get("description", "")[:500],
                })
        return out

    def _root_volume(self, instance_id: str) -> str:
        inst = self.ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
        root = inst["RootDeviceName"]
        return next(m["Ebs"]["VolumeId"] for m in inst["BlockDeviceMappings"] if m["DeviceName"] == root)

    def create_snapshot(self, instance_id: str) -> str:
        snap = self.ec2.create_snapshot(
            VolumeId=self._root_volume(instance_id), Description=f"cspm pre-patch {instance_id}",
            TagSpecifications=[{"ResourceType": "snapshot", "Tags": [
                {"Key": "Project", "Value": self.cfg.get("project_tag", "cspm")},
                {"Key": "InstanceId", "Value": instance_id}]}])
        self.ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap["SnapshotId"]])
        return snap["SnapshotId"]

    def stop_services(self, instance_id: str, services: List[str]) -> None:
        if services:
            self._run(instance_id, [f"systemctl stop {' '.join(services)}"])

    def start_services(self, instance_id: str, services: List[str]) -> None:
        if services:
            self._run(instance_id, [f"systemctl start {' '.join(services)}"])

    def install_patches(self, instance_id: str) -> str:
        status, _ = self._run(instance_id, document="AWS-RunPatchBaseline",
                              parameters={"Operation": ["Install"], "RebootOption": ["RebootIfNeeded"]},
                              timeout=3600)
        if status != "Success":
            raise RuntimeError(f"AWS-RunPatchBaseline ended with status {status}")
        self.ec2.get_waiter("instance_status_ok").wait(InstanceIds=[instance_id])
        return "AWS-RunPatchBaseline Install succeeded"

    def health_check(self, instance_id: str, services: List[str]) -> Tuple[bool, str]:
        state = self.ssm.describe_instance_patch_states(InstanceIds=[instance_id])["InstancePatchStates"]
        missing = state[0].get("MissingCount", 0) + state[0].get("FailedCount", 0) if state else 0
        if not services:
            return missing == 0, f"{missing} patch(es) missing or failed"
        status, stdout = self._run(instance_id, [f"systemctl is-active {' '.join(services)}"])
        states = stdout.split()
        ok = status == "Success" and len(states) == len(services) and all(s == "active" for s in states)
        return ok and missing == 0, f"services: {', '.join(states) or status}; {missing} patch(es) missing or failed"

    def restore_snapshot(self, instance_id: str, snapshot_id: str) -> None:
        # DeleteReplacedRootVolume: without it the failed root disk is left behind, detached but still billed.
        task = self.ec2.create_replace_root_volume_task(InstanceId=instance_id, SnapshotId=snapshot_id,
                                                        DeleteReplacedRootVolume=True)
        task_id = task["ReplaceRootVolumeTask"]["ReplaceRootVolumeTaskId"]
        for _ in range(120):
            time.sleep(10)
            t = self.ec2.describe_replace_root_volume_tasks(ReplaceRootVolumeTaskIds=[task_id])["ReplaceRootVolumeTasks"][0]
            if t["TaskState"] == "succeeded":
                return
            if t["TaskState"] in ("failed", "failed-detached"):
                raise RuntimeError(f"root volume restore {task_id} {t['TaskState']}")
        raise RuntimeError(f"root volume restore {task_id} timed out")

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------
    def send_notification(self, recipient: str, subject: str, body: str) -> None:
        topic = self.cfg.get("sns_topic_arn")
        if not topic:
            return
        # One SNS topic serves the whole simulated company; the intended reader is named in the body.
        self.sns.publish(TopicArn=topic, Subject=subject[:100], Message=f"To: {recipient}\n\n{body}")

    def poll_drift_events(self) -> List[Dict[str, Any]]:
        """Change events the drift Lambda forwarded to SQS (long poll, up to 10 seconds)."""
        queue = self.cfg.get("drift_queue_url")
        if not queue:
            return []
        resp = self.sqs.receive_message(QueueUrl=queue, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        events = []
        for m in resp.get("Messages", []):
            try:
                events.append(json.loads(m["Body"]))
            except ValueError:
                pass
            self.sqs.delete_message(QueueUrl=queue, ReceiptHandle=m["ReceiptHandle"])
        return events
