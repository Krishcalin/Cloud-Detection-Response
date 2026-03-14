#!/usr/bin/env python3
"""
Cloud Detection & Response (CDR) Scanner
Version : 1.0.0
License : MIT
Requires: Python 3.10+ (no external dependencies)

Analyses cloud audit logs (AWS CloudTrail, Azure Activity/Sign-in, GCP Audit)
to detect threats, misconfigurations, and suspicious activity mapped to the
MITRE ATT&CK Cloud Matrix.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

# ════════════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK CLOUD MATRIX MAPPING
# ════════════════════════════════════════════════════════════════════════════════
MITRE_MAP: dict[str, str] = {
    "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1136": "Create Account",
    "T1136.003": "Create Account: Cloud Account",
    "T1098": "Account Manipulation",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1484": "Domain Policy Modification",
    "T1484.002": "Domain Policy Modification: Trust Modification",
    "T1562": "Impair Defenses",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1562.008": "Impair Defenses: Disable Cloud Logs",
    "T1530": "Data from Cloud Storage",
    "T1537": "Transfer Data to Cloud Account",
    "T1580": "Cloud Infrastructure Discovery",
    "T1526": "Cloud Service Discovery",
    "T1538": "Cloud Service Dashboard",
    "T1021": "Remote Services",
    "T1021.004": "Remote Services: SSH",
    "T1021.001": "Remote Services: RDP",
    "T1496": "Resource Hijacking",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1190": "Exploit Public-Facing Application",
    "T1552": "Unsecured Credentials",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1528": "Steal Application Access Token",
    "T1556": "Modify Authentication Process",
    "T1525": "Implant Internal Image",
    "T1578": "Modify Cloud Compute Infrastructure",
    "T1578.002": "Modify Cloud Compute Infrastructure: Create Cloud Instance",
    "T1578.003": "Modify Cloud Compute Infrastructure: Delete Cloud Instance",
    "T1578.004": "Modify Cloud Compute Infrastructure: Revert Cloud Instance",
    "T1199": "Trusted Relationship",
    "T1535": "Unused/Unsupported Cloud Regions",
    "T1619": "Cloud Storage Object Discovery",
    "T1613": "Container and Resource Discovery",
}

# ════════════════════════════════════════════════════════════════════════════════
#  COMPLIANCE FRAMEWORK MAPPING
# ════════════════════════════════════════════════════════════════════════════════
COMPLIANCE_MAP: dict[str, str] = {
    "CIS-AWS": "CIS AWS Foundations Benchmark",
    "CIS-AZURE": "CIS Azure Foundations Benchmark",
    "CIS-GCP": "CIS GCP Foundations Benchmark",
    "NIST-800-53": "NIST 800-53",
    "SOC2": "SOC 2 Type II",
    "PCI-DSS": "PCI-DSS v4.0",
    "ISO27001": "ISO 27001:2022",
}

# ════════════════════════════════════════════════════════════════════════════════
#  FINDING DATACLASS
# ════════════════════════════════════════════════════════════════════════════════
@dataclass
class Finding:
    rule_id: str
    name: str
    tactic: str
    severity: str
    cloud: str
    source_file: str
    event_time: str
    event_name: str
    actor: str
    source_ip: str
    region: str
    description: str
    recommendation: str
    mitre: list[str] = field(default_factory=list)
    compliance: list[str] = field(default_factory=list)
    raw_event: dict = field(default_factory=dict)

# ════════════════════════════════════════════════════════════════════════════════
#  DETECTION RULES
# ════════════════════════════════════════════════════════════════════════════════

# ── AWS CloudTrail Detection Rules ───────────────────────────────────────────

AWS_RULES: list[dict] = [
    # ── Initial Access ──
    {"id": "CDR-AWS-IA-001", "tactic": "Initial Access", "name": "Root account login detected",
     "severity": "CRITICAL", "event_names": ["ConsoleLogin"],
     "condition": lambda e: _ct_user_type(e) == "Root",
     "description": "AWS root account was used to log in. Root should never be used for daily operations.",
     "recommendation": "Disable root account console access. Use IAM users with MFA instead.",
     "mitre": ["T1078.004"], "compliance": ["CIS-AWS", "NIST-800-53"]},

    {"id": "CDR-AWS-IA-002", "tactic": "Initial Access", "name": "Console login without MFA",
     "severity": "HIGH", "event_names": ["ConsoleLogin"],
     "condition": lambda e: _ct_mfa_used(e) is False and _ct_login_success(e),
     "description": "User logged into AWS console without multi-factor authentication.",
     "recommendation": "Enforce MFA for all IAM users with console access.",
     "mitre": ["T1078.004"], "compliance": ["CIS-AWS", "NIST-800-53", "PCI-DSS"]},

    {"id": "CDR-AWS-IA-003", "tactic": "Initial Access", "name": "Console login failure — possible brute force",
     "severity": "MEDIUM", "event_names": ["ConsoleLogin"],
     "condition": lambda e: _ct_login_success(e) is False,
     "description": "Failed console login attempt detected. Multiple failures may indicate brute force.",
     "recommendation": "Investigate source IP. Enable account lockout and MFA.",
     "mitre": ["T1110.001"], "compliance": ["NIST-800-53"]},

    {"id": "CDR-AWS-IA-004", "tactic": "Initial Access", "name": "API call from unusual region",
     "severity": "MEDIUM", "event_names": ["*"],
     "condition": lambda e: _ct_unusual_region(e),
     "description": "API call made from an unusual or unused AWS region.",
     "recommendation": "Investigate if activity is legitimate. Use SCPs to restrict unused regions.",
     "mitre": ["T1535"], "compliance": ["CIS-AWS"]},

    # ── Persistence ──
    {"id": "CDR-AWS-PE-001", "tactic": "Persistence", "name": "IAM user created",
     "severity": "HIGH", "event_names": ["CreateUser"],
     "condition": lambda e: True,
     "description": "New IAM user created — could be a backdoor account.",
     "recommendation": "Verify the user creation was authorised. Review the user's permissions.",
     "mitre": ["T1136.003"], "compliance": ["CIS-AWS", "SOC2"]},

    {"id": "CDR-AWS-PE-002", "tactic": "Persistence", "name": "Access key created",
     "severity": "HIGH", "event_names": ["CreateAccessKey"],
     "condition": lambda e: True,
     "description": "New IAM access key created — could enable persistent programmatic access.",
     "recommendation": "Verify key creation was authorised. Rotate keys regularly.",
     "mitre": ["T1098.001"], "compliance": ["CIS-AWS", "NIST-800-53"]},

    {"id": "CDR-AWS-PE-003", "tactic": "Persistence", "name": "Login profile created (console access added)",
     "severity": "HIGH", "event_names": ["CreateLoginProfile"],
     "condition": lambda e: True,
     "description": "Console login profile added to an IAM user — grants console access.",
     "recommendation": "Verify this was intentional. Ensure MFA is required.",
     "mitre": ["T1098.001"], "compliance": ["CIS-AWS"]},

    {"id": "CDR-AWS-PE-004", "tactic": "Persistence", "name": "Lambda function created or updated",
     "severity": "MEDIUM", "event_names": ["CreateFunction20150331", "UpdateFunctionCode20150331v2", "CreateFunction", "UpdateFunctionCode"],
     "condition": lambda e: True,
     "description": "Lambda function created or modified — could be used as a backdoor or for data exfiltration.",
     "recommendation": "Review the function code and IAM role for excessive permissions.",
     "mitre": ["T1525"], "compliance": ["SOC2"]},

    {"id": "CDR-AWS-PE-005", "tactic": "Persistence", "name": "EC2 key pair created or imported",
     "severity": "MEDIUM", "event_names": ["CreateKeyPair", "ImportKeyPair"],
     "condition": lambda e: True,
     "description": "SSH key pair created or imported — enables SSH access to EC2 instances.",
     "recommendation": "Verify key pair creation. Use Session Manager instead of SSH keys.",
     "mitre": ["T1098.001"], "compliance": ["NIST-800-53"]},

    # ── Privilege Escalation ──
    {"id": "CDR-AWS-PR-001", "tactic": "Privilege Escalation", "name": "AdministratorAccess policy attached",
     "severity": "CRITICAL", "event_names": ["AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy"],
     "condition": lambda e: "AdministratorAccess" in json.dumps(e.get("requestParameters", {})),
     "description": "AdministratorAccess policy attached — grants full AWS access.",
     "recommendation": "Follow least privilege. Use scoped policies instead of AdministratorAccess.",
     "mitre": ["T1098.003"], "compliance": ["CIS-AWS", "NIST-800-53", "SOC2"]},

    {"id": "CDR-AWS-PR-002", "tactic": "Privilege Escalation", "name": "IAM policy created with wildcard permissions",
     "severity": "CRITICAL", "event_names": ["CreatePolicy", "CreatePolicyVersion", "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy"],
     "condition": lambda e: _ct_has_wildcard_policy(e),
     "description": "IAM policy with Action:* or Resource:* created — overly permissive.",
     "recommendation": "Apply least privilege. Scope actions and resources explicitly.",
     "mitre": ["T1098.003"], "compliance": ["CIS-AWS", "NIST-800-53"]},

    {"id": "CDR-AWS-PR-003", "tactic": "Privilege Escalation", "name": "Inline policy added to user",
     "severity": "HIGH", "event_names": ["PutUserPolicy"],
     "condition": lambda e: True,
     "description": "Inline policy attached directly to IAM user — bypasses group-based controls.",
     "recommendation": "Use managed policies attached to groups or roles instead.",
     "mitre": ["T1098.003"], "compliance": ["CIS-AWS"]},

    {"id": "CDR-AWS-PR-004", "tactic": "Privilege Escalation", "name": "STS AssumeRole to cross-account role",
     "severity": "MEDIUM", "event_names": ["AssumeRole"],
     "condition": lambda e: _ct_cross_account(e),
     "description": "Cross-account role assumption detected.",
     "recommendation": "Verify cross-account access is authorised and uses external ID.",
     "mitre": ["T1199"], "compliance": ["NIST-800-53", "SOC2"]},

    # ── Defense Evasion ──
    {"id": "CDR-AWS-DE-001", "tactic": "Defense Evasion", "name": "CloudTrail logging stopped",
     "severity": "CRITICAL", "event_names": ["StopLogging"],
     "condition": lambda e: True,
     "description": "CloudTrail logging was stopped — attacker covering tracks.",
     "recommendation": "Re-enable CloudTrail immediately. Investigate who stopped it and why.",
     "mitre": ["T1562.008"], "compliance": ["CIS-AWS", "NIST-800-53", "SOC2", "PCI-DSS"]},

    {"id": "CDR-AWS-DE-002", "tactic": "Defense Evasion", "name": "CloudTrail trail deleted",
     "severity": "CRITICAL", "event_names": ["DeleteTrail"],
     "condition": lambda e: True,
     "description": "CloudTrail trail deleted — severe indicator of attacker covering tracks.",
     "recommendation": "Recreate trail immediately. Investigate the actor and timeline.",
     "mitre": ["T1562.008"], "compliance": ["CIS-AWS", "NIST-800-53", "SOC2"]},

    {"id": "CDR-AWS-DE-003", "tactic": "Defense Evasion", "name": "CloudTrail event selectors modified",
     "severity": "HIGH", "event_names": ["PutEventSelectors", "UpdateTrail"],
     "condition": lambda e: True,
     "description": "CloudTrail event selectors modified — may reduce logging coverage.",
     "recommendation": "Verify logging configuration includes all management and data events.",
     "mitre": ["T1562.008"], "compliance": ["CIS-AWS"]},

    {"id": "CDR-AWS-DE-004", "tactic": "Defense Evasion", "name": "GuardDuty detector disabled or deleted",
     "severity": "CRITICAL", "event_names": ["DeleteDetector", "UpdateDetector"],
     "condition": lambda e: True,
     "description": "GuardDuty threat detection disabled or deleted.",
     "recommendation": "Re-enable GuardDuty immediately. Investigate who disabled it.",
     "mitre": ["T1562.001"], "compliance": ["CIS-AWS", "NIST-800-53"]},

    {"id": "CDR-AWS-DE-005", "tactic": "Defense Evasion", "name": "S3 bucket logging disabled",
     "severity": "HIGH", "event_names": ["PutBucketLogging"],
     "condition": lambda e: True,
     "description": "S3 bucket access logging configuration changed.",
     "recommendation": "Ensure server access logging is enabled on all sensitive buckets.",
     "mitre": ["T1562.008"], "compliance": ["CIS-AWS", "SOC2"]},

    {"id": "CDR-AWS-DE-006", "tactic": "Defense Evasion", "name": "Config recorder stopped or deleted",
     "severity": "CRITICAL", "event_names": ["StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel"],
     "condition": lambda e: True,
     "description": "AWS Config recorder stopped or deleted — compliance monitoring disabled.",
     "recommendation": "Re-enable AWS Config. Investigate the actor.",
     "mitre": ["T1562.001"], "compliance": ["CIS-AWS", "NIST-800-53"]},

    {"id": "CDR-AWS-DE-007", "tactic": "Defense Evasion", "name": "VPC flow log deleted",
     "severity": "HIGH", "event_names": ["DeleteFlowLogs"],
     "condition": lambda e: True,
     "description": "VPC Flow Logs deleted — network monitoring disabled.",
     "recommendation": "Recreate flow logs. Investigate who deleted them.",
     "mitre": ["T1562.008"], "compliance": ["CIS-AWS", "NIST-800-53"]},

    # ── Credential Access ──
    {"id": "CDR-AWS-CA-001", "tactic": "Credential Access", "name": "Secrets Manager secret accessed",
     "severity": "MEDIUM", "event_names": ["GetSecretValue"],
     "condition": lambda e: True,
     "description": "Secret retrieved from Secrets Manager.",
     "recommendation": "Verify the accessor is authorised. Enable secret rotation.",
     "mitre": ["T1552"], "compliance": ["NIST-800-53", "PCI-DSS"]},

    {"id": "CDR-AWS-CA-002", "tactic": "Credential Access", "name": "SSM Parameter Store sensitive parameter accessed",
     "severity": "MEDIUM", "event_names": ["GetParameter", "GetParameters"],
     "condition": lambda e: True,
     "description": "Parameter Store parameter accessed — may contain secrets.",
     "recommendation": "Use SecureString type and restrict access via IAM policies.",
     "mitre": ["T1552"], "compliance": ["NIST-800-53"]},

    {"id": "CDR-AWS-CA-003", "tactic": "Credential Access", "name": "Password policy weakened",
     "severity": "HIGH", "event_names": ["UpdateAccountPasswordPolicy"],
     "condition": lambda e: True,
     "description": "IAM password policy was modified — may have been weakened.",
     "recommendation": "Review password policy. Enforce strong password requirements.",
     "mitre": ["T1556"], "compliance": ["CIS-AWS", "NIST-800-53"]},

    # ── Discovery ──
    {"id": "CDR-AWS-DI-001", "tactic": "Discovery", "name": "Reconnaissance API calls detected",
     "severity": "LOW", "event_names": ["ListBuckets", "DescribeInstances", "DescribeSecurityGroups",
                                         "GetCallerIdentity", "ListRoles", "ListUsers", "ListGroups"],
     "condition": lambda e: True,
     "description": "Reconnaissance/enumeration API calls detected.",
     "recommendation": "Verify if the caller has a legitimate need for this discovery.",
     "mitre": ["T1580", "T1526"], "compliance": []},

    {"id": "CDR-AWS-DI-002", "tactic": "Discovery", "name": "S3 bucket enumeration",
     "severity": "MEDIUM", "event_names": ["ListBuckets", "GetBucketAcl", "GetBucketPolicy", "ListObjects"],
     "condition": lambda e: True,
     "description": "S3 bucket enumeration detected — attacker mapping storage surface.",
     "recommendation": "Review if the caller has legitimate need to list/inspect bucket configurations.",
     "mitre": ["T1619"], "compliance": []},

    # ── Exfiltration ──
    {"id": "CDR-AWS-EX-001", "tactic": "Exfiltration", "name": "S3 bucket policy made public",
     "severity": "CRITICAL", "event_names": ["PutBucketPolicy", "PutBucketAcl"],
     "condition": lambda e: _ct_s3_public(e),
     "description": "S3 bucket ACL or policy changed to allow public access — data exposure risk.",
     "recommendation": "Remove public access immediately. Enable S3 Block Public Access.",
     "mitre": ["T1530"], "compliance": ["CIS-AWS", "NIST-800-53", "PCI-DSS"]},

    {"id": "CDR-AWS-EX-002", "tactic": "Exfiltration", "name": "EBS snapshot shared publicly",
     "severity": "CRITICAL", "event_names": ["ModifySnapshotAttribute"],
     "condition": lambda e: _ct_snapshot_public(e),
     "description": "EBS snapshot shared publicly or with external account.",
     "recommendation": "Remove public sharing. Review snapshot contents for sensitive data.",
     "mitre": ["T1537"], "compliance": ["CIS-AWS", "NIST-800-53"]},

    {"id": "CDR-AWS-EX-003", "tactic": "Exfiltration", "name": "RDS snapshot shared externally",
     "severity": "CRITICAL", "event_names": ["ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"],
     "condition": lambda e: True,
     "description": "RDS database snapshot sharing modified — potential data exfiltration.",
     "recommendation": "Verify the target account. Restrict snapshot sharing.",
     "mitre": ["T1537"], "compliance": ["NIST-800-53", "PCI-DSS"]},

    # ── Network ──
    {"id": "CDR-AWS-NET-001", "tactic": "Network", "name": "Security group opened to 0.0.0.0/0",
     "severity": "CRITICAL", "event_names": ["AuthorizeSecurityGroupIngress"],
     "condition": lambda e: _ct_sg_open(e),
     "description": "Security group rule added allowing traffic from any IP (0.0.0.0/0).",
     "recommendation": "Restrict security group rules to specific CIDR ranges.",
     "mitre": ["T1190"], "compliance": ["CIS-AWS", "NIST-800-53", "PCI-DSS"]},

    {"id": "CDR-AWS-NET-002", "tactic": "Network", "name": "Security group rule deleted",
     "severity": "MEDIUM", "event_names": ["RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress"],
     "condition": lambda e: True,
     "description": "Security group rule removed — may weaken network controls.",
     "recommendation": "Verify the rule removal was intentional and does not weaken security posture.",
     "mitre": ["T1562.001"], "compliance": ["NIST-800-53"]},

    {"id": "CDR-AWS-NET-003", "tactic": "Network", "name": "VPC or subnet modified",
     "severity": "MEDIUM", "event_names": ["CreateVpc", "DeleteVpc", "CreateSubnet", "DeleteSubnet",
                                            "ModifyVpcAttribute", "CreateInternetGateway", "AttachInternetGateway"],
     "condition": lambda e: True,
     "description": "VPC or subnet infrastructure modified.",
     "recommendation": "Verify network changes are authorised and follow architecture standards.",
     "mitre": ["T1578"], "compliance": ["NIST-800-53"]},

    # ── Impact ──
    {"id": "CDR-AWS-IM-001", "tactic": "Impact", "name": "EC2 instances terminated in bulk",
     "severity": "HIGH", "event_names": ["TerminateInstances"],
     "condition": lambda e: True,
     "description": "EC2 instances terminated — potential destructive action.",
     "recommendation": "Verify the termination was authorised. Enable termination protection on critical instances.",
     "mitre": ["T1578.003", "T1485"], "compliance": ["SOC2"]},

    {"id": "CDR-AWS-IM-002", "tactic": "Impact", "name": "RDS instance or cluster deleted",
     "severity": "CRITICAL", "event_names": ["DeleteDBInstance", "DeleteDBCluster"],
     "condition": lambda e: True,
     "description": "RDS database deleted — potential data destruction.",
     "recommendation": "Enable deletion protection on production databases. Verify final snapshots.",
     "mitre": ["T1485"], "compliance": ["SOC2", "PCI-DSS"]},

    {"id": "CDR-AWS-IM-003", "tactic": "Impact", "name": "S3 bucket deleted",
     "severity": "HIGH", "event_names": ["DeleteBucket"],
     "condition": lambda e: True,
     "description": "S3 bucket deleted — potential data loss.",
     "recommendation": "Enable versioning and MFA Delete on critical buckets.",
     "mitre": ["T1485"], "compliance": ["SOC2"]},

    {"id": "CDR-AWS-IM-004", "tactic": "Impact", "name": "Potential cryptominer — large/GPU instance launched",
     "severity": "HIGH", "event_names": ["RunInstances"],
     "condition": lambda e: _ct_crypto_instance(e),
     "description": "Large or GPU-based EC2 instance launched — potential cryptomining.",
     "recommendation": "Verify the instance type is justified. Set up billing alerts.",
     "mitre": ["T1496"], "compliance": ["SOC2"]},

    {"id": "CDR-AWS-IM-005", "tactic": "Impact", "name": "KMS key scheduled for deletion",
     "severity": "CRITICAL", "event_names": ["ScheduleKeyDeletion", "DisableKey"],
     "condition": lambda e: True,
     "description": "KMS encryption key scheduled for deletion or disabled — may cause data loss.",
     "recommendation": "Cancel key deletion if unauthorised. Review key usage before deletion.",
     "mitre": ["T1485"], "compliance": ["NIST-800-53", "PCI-DSS"]},
]

# ── Azure Activity / Sign-in Log Detection Rules ────────────────────────────

AZURE_RULES: list[dict] = [
    # ── Initial Access ──
    {"id": "CDR-AZ-IA-001", "tactic": "Initial Access", "name": "Sign-in from unfamiliar location",
     "severity": "HIGH", "event_names": ["Sign-in activity"],
     "condition": lambda e: _az_risky_signin(e),
     "description": "Sign-in detected from an unfamiliar or risky location.",
     "recommendation": "Verify with the user. Enable Conditional Access with location-based policies.",
     "mitre": ["T1078.004"], "compliance": ["CIS-AZURE", "NIST-800-53"]},

    {"id": "CDR-AZ-IA-002", "tactic": "Initial Access", "name": "Multiple failed sign-in attempts",
     "severity": "MEDIUM", "event_names": ["Sign-in activity"],
     "condition": lambda e: _az_failed_signin(e),
     "description": "Multiple failed sign-in attempts — possible brute force or credential stuffing.",
     "recommendation": "Enable smart lockout. Enforce MFA and Conditional Access.",
     "mitre": ["T1110"], "compliance": ["CIS-AZURE", "NIST-800-53"]},

    {"id": "CDR-AZ-IA-003", "tactic": "Initial Access", "name": "Sign-in without MFA",
     "severity": "HIGH", "event_names": ["Sign-in activity"],
     "condition": lambda e: _az_no_mfa(e),
     "description": "Successful sign-in without MFA enforcement.",
     "recommendation": "Enforce MFA via Conditional Access for all users.",
     "mitre": ["T1078.004"], "compliance": ["CIS-AZURE", "NIST-800-53", "PCI-DSS"]},

    # ── Persistence ──
    {"id": "CDR-AZ-PE-001", "tactic": "Persistence", "name": "New user or guest account created",
     "severity": "HIGH", "event_names": ["Add user", "Invite external user"],
     "condition": lambda e: True,
     "description": "New user or guest account created in Entra ID.",
     "recommendation": "Verify account creation was authorised. Review assigned roles.",
     "mitre": ["T1136.003"], "compliance": ["CIS-AZURE", "SOC2"]},

    {"id": "CDR-AZ-PE-002", "tactic": "Persistence", "name": "Application credentials added",
     "severity": "HIGH", "event_names": ["Add service principal credentials", "Update application – Certificates and secrets management"],
     "condition": lambda e: True,
     "description": "Credentials (secret or certificate) added to an application registration.",
     "recommendation": "Verify the credential addition. Monitor for unused app credentials.",
     "mitre": ["T1098.001"], "compliance": ["CIS-AZURE"]},

    {"id": "CDR-AZ-PE-003", "tactic": "Persistence", "name": "OAuth2 consent grant (admin consent)",
     "severity": "HIGH", "event_names": ["Consent to application"],
     "condition": lambda e: True,
     "description": "Admin consent granted to an application — grants persistent API access.",
     "recommendation": "Review the application permissions. Use admin consent workflow.",
     "mitre": ["T1528"], "compliance": ["CIS-AZURE", "SOC2"]},

    # ── Privilege Escalation ──
    {"id": "CDR-AZ-PR-001", "tactic": "Privilege Escalation", "name": "Global Administrator role assigned",
     "severity": "CRITICAL", "event_names": ["Add member to role", "Add eligible member to role"],
     "condition": lambda e: _az_global_admin(e),
     "description": "Global Administrator role assigned — highest privilege in Entra ID.",
     "recommendation": "Limit Global Admins to 2-4. Use PIM with time-bound assignments.",
     "mitre": ["T1098.003"], "compliance": ["CIS-AZURE", "NIST-800-53", "SOC2"]},

    {"id": "CDR-AZ-PR-002", "tactic": "Privilege Escalation", "name": "Privileged role assigned",
     "severity": "HIGH", "event_names": ["Add member to role", "Add eligible member to role"],
     "condition": lambda e: _az_priv_role(e),
     "description": "Privileged directory role assigned to a user or service principal.",
     "recommendation": "Verify the role assignment. Use PIM for just-in-time access.",
     "mitre": ["T1098.003"], "compliance": ["CIS-AZURE", "NIST-800-53"]},

    # ── Defense Evasion ──
    {"id": "CDR-AZ-DE-001", "tactic": "Defense Evasion", "name": "Conditional Access policy disabled or deleted",
     "severity": "CRITICAL", "event_names": ["Update conditional access policy", "Delete conditional access policy"],
     "condition": lambda e: True,
     "description": "Conditional Access policy modified or deleted — may weaken access controls.",
     "recommendation": "Review the policy change. Ensure critical policies are protected.",
     "mitre": ["T1562.001"], "compliance": ["CIS-AZURE", "NIST-800-53"]},

    {"id": "CDR-AZ-DE-002", "tactic": "Defense Evasion", "name": "Diagnostic setting deleted",
     "severity": "HIGH", "event_names": ["Delete diagnostic setting", "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE"],
     "condition": lambda e: True,
     "description": "Azure diagnostic logging setting deleted — audit trail disruption.",
     "recommendation": "Re-enable diagnostic settings. Investigate who deleted them.",
     "mitre": ["T1562.008"], "compliance": ["CIS-AZURE", "NIST-800-53"]},

    {"id": "CDR-AZ-DE-003", "tactic": "Defense Evasion", "name": "Security Center/Defender setting disabled",
     "severity": "CRITICAL", "event_names": ["Update security policy", "MICROSOFT.SECURITY/POLICIES/WRITE",
                                               "Disable security policy"],
     "condition": lambda e: True,
     "description": "Microsoft Defender for Cloud or Security Center setting modified.",
     "recommendation": "Re-enable Defender settings. Investigate the actor.",
     "mitre": ["T1562.001"], "compliance": ["CIS-AZURE", "NIST-800-53"]},

    # ── Network ──
    {"id": "CDR-AZ-NET-001", "tactic": "Network", "name": "NSG rule allowing any source created",
     "severity": "CRITICAL", "event_names": ["Create or Update Security Rule",
                                               "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"],
     "condition": lambda e: True,
     "description": "Network security group rule created — verify it does not allow unrestricted access.",
     "recommendation": "Restrict NSG rules to specific source IPs/ranges.",
     "mitre": ["T1190"], "compliance": ["CIS-AZURE", "NIST-800-53", "PCI-DSS"]},

    # ── Impact ──
    {"id": "CDR-AZ-IM-001", "tactic": "Impact", "name": "Resource group or resource deleted",
     "severity": "HIGH", "event_names": ["Delete resource group", "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"],
     "condition": lambda e: True,
     "description": "Azure resource group deleted — potential data destruction.",
     "recommendation": "Enable resource locks on critical resources.",
     "mitre": ["T1485"], "compliance": ["SOC2"]},

    {"id": "CDR-AZ-IM-002", "tactic": "Impact", "name": "Key Vault key or secret deleted",
     "severity": "CRITICAL", "event_names": ["SecretDelete", "KeyDelete", "CertificateDelete",
                                               "MICROSOFT.KEYVAULT/VAULTS/SECRETS/DELETE"],
     "condition": lambda e: True,
     "description": "Key Vault secret, key, or certificate deleted.",
     "recommendation": "Enable soft delete and purge protection on Key Vaults.",
     "mitre": ["T1485"], "compliance": ["NIST-800-53", "PCI-DSS"]},
]

# ── GCP Audit Log Detection Rules ───────────────────────────────────────────

GCP_RULES: list[dict] = [
    # ── Persistence ──
    {"id": "CDR-GCP-PE-001", "tactic": "Persistence", "name": "Service account created",
     "severity": "HIGH", "event_names": ["google.iam.admin.v1.CreateServiceAccount",
                                          "CreateServiceAccount"],
     "condition": lambda e: True,
     "description": "New GCP service account created.",
     "recommendation": "Verify service account creation. Apply least privilege roles.",
     "mitre": ["T1136.003"], "compliance": ["CIS-GCP", "SOC2"]},

    {"id": "CDR-GCP-PE-002", "tactic": "Persistence", "name": "Service account key created",
     "severity": "HIGH", "event_names": ["google.iam.admin.v1.CreateServiceAccountKey",
                                          "CreateServiceAccountKey"],
     "condition": lambda e: True,
     "description": "Service account key created — enables persistent API access.",
     "recommendation": "Avoid user-managed keys. Use Workload Identity Federation.",
     "mitre": ["T1098.001"], "compliance": ["CIS-GCP", "NIST-800-53"]},

    # ── Privilege Escalation ──
    {"id": "CDR-GCP-PR-001", "tactic": "Privilege Escalation", "name": "IAM policy binding with Owner/Editor role",
     "severity": "CRITICAL", "event_names": ["SetIamPolicy", "google.iam.admin.v1.SetIAMPolicy"],
     "condition": lambda e: _gcp_owner_editor(e),
     "description": "IAM policy binding with Owner or Editor role — highly permissive.",
     "recommendation": "Use predefined or custom roles with least privilege.",
     "mitre": ["T1098.003"], "compliance": ["CIS-GCP", "NIST-800-53"]},

    {"id": "CDR-GCP-PR-002", "tactic": "Privilege Escalation", "name": "Custom IAM role created",
     "severity": "MEDIUM", "event_names": ["google.iam.admin.v1.CreateRole", "CreateRole"],
     "condition": lambda e: True,
     "description": "Custom IAM role created — verify it follows least privilege.",
     "recommendation": "Review custom role permissions for overly broad access.",
     "mitre": ["T1098.003"], "compliance": ["CIS-GCP"]},

    # ── Defense Evasion ──
    {"id": "CDR-GCP-DE-001", "tactic": "Defense Evasion", "name": "Audit log sink deleted",
     "severity": "CRITICAL", "event_names": ["google.logging.v2.ConfigServiceV2.DeleteSink",
                                               "DeleteSink", "DeleteLogMetric"],
     "condition": lambda e: True,
     "description": "Cloud Logging sink deleted — audit logs may be lost.",
     "recommendation": "Recreate the logging sink. Investigate the actor.",
     "mitre": ["T1562.008"], "compliance": ["CIS-GCP", "NIST-800-53"]},

    {"id": "CDR-GCP-DE-002", "tactic": "Defense Evasion", "name": "Firewall rule deleted or modified",
     "severity": "HIGH", "event_names": ["v1.compute.firewalls.delete", "v1.compute.firewalls.patch",
                                           "beta.compute.firewalls.delete", "DeleteFirewall", "PatchFirewall"],
     "condition": lambda e: True,
     "description": "VPC firewall rule deleted or modified.",
     "recommendation": "Verify firewall changes. Use Organisation Policies for guardrails.",
     "mitre": ["T1562.001"], "compliance": ["CIS-GCP", "NIST-800-53"]},

    # ── Exfiltration ──
    {"id": "CDR-GCP-EX-001", "tactic": "Exfiltration", "name": "GCS bucket made public",
     "severity": "CRITICAL", "event_names": ["storage.setIamPermissions", "SetIamPolicy",
                                               "storage.buckets.update"],
     "condition": lambda e: _gcp_public_bucket(e),
     "description": "GCS bucket IAM policy changed to allow public access.",
     "recommendation": "Remove allUsers/allAuthenticatedUsers. Enable Uniform Bucket-Level Access.",
     "mitre": ["T1530"], "compliance": ["CIS-GCP", "NIST-800-53", "PCI-DSS"]},

    # ── Network ──
    {"id": "CDR-GCP-NET-001", "tactic": "Network", "name": "Firewall rule allowing 0.0.0.0/0 created",
     "severity": "CRITICAL", "event_names": ["v1.compute.firewalls.insert", "beta.compute.firewalls.insert",
                                               "CreateFirewall"],
     "condition": lambda e: _gcp_open_firewall(e),
     "description": "Firewall rule created allowing traffic from any IP.",
     "recommendation": "Restrict source ranges. Use Identity-Aware Proxy for access.",
     "mitre": ["T1190"], "compliance": ["CIS-GCP", "NIST-800-53", "PCI-DSS"]},

    # ── Impact ──
    {"id": "CDR-GCP-IM-001", "tactic": "Impact", "name": "Project or resource deleted",
     "severity": "HIGH", "event_names": ["DeleteProject", "v1.compute.instances.delete"],
     "condition": lambda e: True,
     "description": "GCP project or compute instance deleted.",
     "recommendation": "Enable liens on critical projects. Verify deletion was authorised.",
     "mitre": ["T1485"], "compliance": ["SOC2"]},

    {"id": "CDR-GCP-IM-002", "tactic": "Impact", "name": "KMS key version destroyed",
     "severity": "CRITICAL", "event_names": ["DestroyCryptoKeyVersion", "google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion"],
     "condition": lambda e: True,
     "description": "Cloud KMS key version destroyed — encrypted data may become unrecoverable.",
     "recommendation": "Review key usage. Enable key version destroy delay.",
     "mitre": ["T1485"], "compliance": ["NIST-800-53", "PCI-DSS"]},
]

# ════════════════════════════════════════════════════════════════════════════════
#  CONDITION HELPER FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

def _ct_user_type(event: dict) -> str:
    ui = event.get("userIdentity", {})
    return ui.get("type", "")

def _ct_mfa_used(event: dict) -> bool | None:
    add = event.get("additionalEventData", {})
    val = add.get("MFAUsed", add.get("MfaAuthenticated"))
    if val is None:
        return None
    return str(val).lower() in ("yes", "true")

def _ct_login_success(event: dict) -> bool:
    rd = event.get("responseElements", {})
    return rd.get("ConsoleLogin") == "Success" if rd else False

def _ct_unusual_region(event: dict) -> bool:
    common = {"us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1",
              "eu-west-2", "eu-central-1", "ap-southeast-1", "ap-northeast-1"}
    region = event.get("awsRegion", "")
    return bool(region and region not in common)

def _ct_has_wildcard_policy(event: dict) -> bool:
    rp = json.dumps(event.get("requestParameters", {}))
    return '"*"' in rp and ("Action" in rp or "Resource" in rp)

def _ct_cross_account(event: dict) -> bool:
    ui = event.get("userIdentity", {})
    acct = ui.get("accountId", "")
    rp = event.get("requestParameters", {})
    role_arn = rp.get("roleArn", "") if isinstance(rp, dict) else ""
    if role_arn and acct:
        role_acct = role_arn.split(":")[4] if len(role_arn.split(":")) > 4 else ""
        return role_acct != acct
    return False

def _ct_s3_public(event: dict) -> bool:
    rp = json.dumps(event.get("requestParameters", {})).lower()
    return any(k in rp for k in ["public-read", "public-read-write", "authenticated-read", '"*"'])

def _ct_snapshot_public(event: dict) -> bool:
    rp = json.dumps(event.get("requestParameters", {})).lower()
    return "all" in rp or '"*"' in rp

def _ct_sg_open(event: dict) -> bool:
    rp = json.dumps(event.get("requestParameters", {}))
    return "0.0.0.0/0" in rp or "::/0" in rp

def _ct_crypto_instance(event: dict) -> bool:
    rp = json.dumps(event.get("requestParameters", {})).lower()
    crypto_types = ["p3.", "p4d.", "p4de.", "p5.", "g4dn.", "g5.", "g5g.",
                    "x2idn.", "x2iedn.", "m6i.24xlarge", "m6i.32xlarge",
                    "c6i.24xlarge", "c6i.32xlarge", "inf1.", "inf2.", "trn1."]
    return any(t in rp for t in crypto_types)

def _az_risky_signin(event: dict) -> bool:
    risk = event.get("properties", {}).get("riskLevelDuringSignIn", "none")
    return risk.lower() not in ("none", "")

def _az_failed_signin(event: dict) -> bool:
    status = event.get("properties", {}).get("status", {})
    code = status.get("errorCode", 0) if isinstance(status, dict) else 0
    return code != 0

def _az_no_mfa(event: dict) -> bool:
    props = event.get("properties", {})
    auth_details = props.get("authenticationDetails", [])
    if isinstance(auth_details, list):
        for detail in auth_details:
            if isinstance(detail, dict) and detail.get("authenticationMethod", "").lower() in ("mfa", "multifactorauthentication"):
                return False
    mfa = props.get("mfaDetail", {})
    if mfa and isinstance(mfa, dict) and mfa.get("authMethod"):
        return False
    status = props.get("status", {})
    code = status.get("errorCode", 0) if isinstance(status, dict) else 0
    return code == 0

def _az_global_admin(event: dict) -> bool:
    props = event.get("properties", {})
    targets = props.get("targetResources", [])
    ev_str = json.dumps(event).lower()
    return "global administrator" in ev_str or "62e90394-69f5-4237-9190-012177145e10" in ev_str

def _az_priv_role(event: dict) -> bool:
    priv_roles = ["global administrator", "user administrator", "privileged role administrator",
                  "application administrator", "exchange administrator", "sharepoint administrator",
                  "security administrator", "conditional access administrator"]
    ev_str = json.dumps(event).lower()
    return any(r in ev_str for r in priv_roles)

def _gcp_owner_editor(event: dict) -> bool:
    ev_str = json.dumps(event).lower()
    return "roles/owner" in ev_str or "roles/editor" in ev_str

def _gcp_public_bucket(event: dict) -> bool:
    ev_str = json.dumps(event).lower()
    return "allusers" in ev_str or "allauthenticatedusers" in ev_str

def _gcp_open_firewall(event: dict) -> bool:
    ev_str = json.dumps(event).lower()
    return "0.0.0.0/0" in ev_str

# ════════════════════════════════════════════════════════════════════════════════
#  LOG PARSERS
# ════════════════════════════════════════════════════════════════════════════════

def _parse_cloudtrail(data: dict | list) -> list[dict]:
    """Parse CloudTrail JSON (single event, Records array, or log file)."""
    if isinstance(data, list):
        return data
    if "Records" in data:
        return data["Records"]
    if "eventName" in data:
        return [data]
    return []

def _parse_azure_log(data: dict | list) -> list[dict]:
    """Parse Azure Activity/Sign-in log JSON."""
    if isinstance(data, list):
        return data
    if "value" in data:
        return data["value"]
    if "records" in data:
        return data["records"]
    if "operationName" in data or "properties" in data:
        return [data]
    return []

def _parse_gcp_log(data: dict | list) -> list[dict]:
    """Parse GCP Audit Log JSON."""
    if isinstance(data, list):
        return data
    if "entries" in data:
        return data["entries"]
    if "protoPayload" in data or "logName" in data:
        return [data]
    return []

def _detect_cloud(data: dict | list) -> str:
    """Auto-detect cloud provider from log structure."""
    # Unwrap common envelope keys to get at the actual events
    if isinstance(data, dict):
        if "Records" in data:
            inner = data["Records"]
            if inner and isinstance(inner[0], dict) and "eventSource" in inner[0]:
                return "aws"
            return "aws"
        if "value" in data and isinstance(data["value"], list) and data["value"]:
            sample = data["value"][0]
            if isinstance(sample, dict) and ("operationName" in sample or "resourceId" in sample
                                              or "callerIpAddress" in sample):
                return "azure"
        if "records" in data and isinstance(data["records"], list) and data["records"]:
            sample = data["records"][0]
            if isinstance(sample, dict) and ("operationName" in sample or "resourceId" in sample):
                return "azure"
        if "entries" in data and isinstance(data["entries"], list):
            return "gcp"

    sample = data if isinstance(data, dict) else (data[0] if data else {})
    if not isinstance(sample, dict):
        return "unknown"
    if "eventSource" in sample or "awsRegion" in sample:
        return "aws"
    if "operationName" in sample or "resourceId" in sample:
        return "azure"
    if "properties" in sample and "status" in sample.get("properties", {}):
        return "azure"
    if "protoPayload" in sample or "logName" in sample:
        return "gcp"
    return "unknown"

def _extract_aws_fields(event: dict) -> dict:
    ui = event.get("userIdentity", {})
    return {
        "event_time": event.get("eventTime", ""),
        "event_name": event.get("eventName", ""),
        "actor": ui.get("arn", ui.get("userName", ui.get("principalId", ""))),
        "source_ip": event.get("sourceIPAddress", ""),
        "region": event.get("awsRegion", ""),
    }

def _extract_azure_fields(event: dict) -> dict:
    props = event.get("properties", {})
    caller = event.get("caller", props.get("userPrincipalName", props.get("initiatedBy", "")))
    op = event.get("operationName", {})
    op_str = op.get("localizedValue", op) if isinstance(op, dict) else str(op)
    return {
        "event_time": event.get("time", event.get("createdDateTime", "")),
        "event_name": op_str,
        "actor": str(caller),
        "source_ip": props.get("ipAddress", event.get("callerIpAddress", "")),
        "region": event.get("location", event.get("resourceLocation", "")),
    }

def _extract_gcp_fields(event: dict) -> dict:
    pp = event.get("protoPayload", {})
    auth = pp.get("authenticationInfo", {})
    req_meta = pp.get("requestMetadata", {})
    return {
        "event_time": event.get("timestamp", event.get("receiveTimestamp", "")),
        "event_name": pp.get("methodName", event.get("methodName", "")),
        "actor": auth.get("principalEmail", ""),
        "source_ip": req_meta.get("callerIp", ""),
        "region": event.get("resource", {}).get("labels", {}).get("location", ""),
    }

# ════════════════════════════════════════════════════════════════════════════════
#  SCANNER CLASS
# ════════════════════════════════════════════════════════════════════════════════
class CDRScanner:
    """Cloud Detection & Response Scanner — analyses cloud audit logs for threats."""

    SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    SEVERITY_COLOR: dict[str, str] = {
        "CRITICAL": "\033[91m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
        "LOW": "\033[36m", "INFO": "\033[37m",
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def __init__(self, verbose: bool = False) -> None:
        self.findings: list[Finding] = []
        self.events_analysed: int = 0
        self.files_scanned: int = 0
        self.verbose = verbose
        self.cloud_summary: dict[str, int] = {"aws": 0, "azure": 0, "gcp": 0, "unknown": 0}
        self.tactic_summary: dict[str, int] = {}

    def scan_path(self, target: str) -> list[Finding]:
        p = Path(target).resolve()
        if p.is_file():
            self._scan_file(str(p))
        elif p.is_dir():
            self._scan_directory(str(p))
        else:
            self._warn(f"Target not found: {target}")
        return self.findings

    def _scan_directory(self, root: str) -> None:
        skip = {"node_modules", "__pycache__", ".git", ".venv", "venv"}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext in (".json", ".log"):
                    self._scan_file(os.path.join(dirpath, fname))

    def _scan_file(self, fpath: str) -> None:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return

        self.files_scanned += 1
        self._vprint(f"  Scanning: {fpath}")

        cloud = _detect_cloud(data)
        self.cloud_summary[cloud] = self.cloud_summary.get(cloud, 0) + 1

        if cloud == "aws":
            events = _parse_cloudtrail(data)
            self._analyse_events(events, AWS_RULES, cloud, fpath, _extract_aws_fields)
        elif cloud == "azure":
            events = _parse_azure_log(data)
            self._analyse_events(events, AZURE_RULES, cloud, fpath, _extract_azure_fields)
        elif cloud == "gcp":
            events = _parse_gcp_log(data)
            self._analyse_events(events, GCP_RULES, cloud, fpath, _extract_gcp_fields)
        else:
            # Try all parsers
            events = _parse_cloudtrail(data)
            if events:
                self._analyse_events(events, AWS_RULES, "aws", fpath, _extract_aws_fields)

    def _analyse_events(self, events: list[dict], rules: list[dict], cloud: str,
                        fpath: str, extract_fn) -> None:
        for event in events:
            if not isinstance(event, dict):
                continue
            self.events_analysed += 1
            fields = extract_fn(event)
            event_name = fields.get("event_name", "")

            for rule in rules:
                matched = False
                for pattern in rule["event_names"]:
                    if pattern == "*" or pattern == event_name:
                        matched = True
                        break
                    if pattern.upper() == event_name.upper():
                        matched = True
                        break
                if not matched:
                    continue

                try:
                    if rule["condition"](event):
                        self._add_finding(rule, cloud, fpath, fields, event)
                except Exception:
                    pass

    def _add_finding(self, rule: dict, cloud: str, fpath: str, fields: dict, event: dict) -> None:
        tactic = rule["tactic"]
        self.tactic_summary[tactic] = self.tactic_summary.get(tactic, 0) + 1
        self.findings.append(Finding(
            rule_id=rule["id"], name=rule["name"], tactic=tactic,
            severity=rule["severity"], cloud=cloud.upper(),
            source_file=fpath,
            event_time=fields.get("event_time", ""),
            event_name=fields.get("event_name", ""),
            actor=fields.get("actor", ""),
            source_ip=fields.get("source_ip", ""),
            region=fields.get("region", ""),
            description=rule["description"],
            recommendation=rule["recommendation"],
            mitre=rule.get("mitre", []),
            compliance=rule.get("compliance", []),
            raw_event={k: v for k, v in event.items()
                       if k in ("eventTime", "eventName", "userIdentity", "sourceIPAddress",
                                "awsRegion", "requestParameters", "responseElements",
                                "operationName", "time", "caller", "callerIpAddress",
                                "properties", "protoPayload", "timestamp", "resource")},
        ))

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def _warn(self, msg: str) -> None:
        print(f"\033[33m[WARN]\033[0m {msg}", file=sys.stderr)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_sev: str) -> None:
        cutoff = self.SEVERITY_ORDER.get(min_sev, 4)
        self.findings = [f for f in self.findings if self.SEVERITY_ORDER.get(f.severity, 4) <= cutoff]

    # ════════════════════════════════════════════════════════════════════════
    #  CONSOLE REPORT
    # ════════════════════════════════════════════════════════════════════════
    def print_report(self) -> None:
        self.findings.sort(key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 4), f.event_time))
        s = self.summary()
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        hdr = (
            f"\n{'=' * 80}\n"
            f"  Cloud Detection & Response (CDR) — Threat Report\n"
            f"  Scanner Version : {__version__}\n"
            f"  Analysis Date   : {now}\n"
            f"  Files Scanned   : {self.files_scanned}\n"
            f"  Events Analysed : {self.events_analysed}\n"
            f"  Threats Detected: {len(self.findings)}\n"
            f"{'=' * 80}\n"
        )
        print(hdr)

        clouds = {k: v for k, v in self.cloud_summary.items() if v > 0}
        if clouds:
            print("  Cloud Logs Analysed:")
            for c, n in clouds.items():
                print(f"    {c.upper()}: {n} file(s)")
            print()

        if self.tactic_summary:
            print("  MITRE ATT&CK Tactics:")
            for tac, cnt in sorted(self.tactic_summary.items(), key=lambda x: -x[1]):
                print(f"    {tac}: {cnt} detection(s)")
            print()

        for idx, f in enumerate(self.findings, 1):
            clr = self.SEVERITY_COLOR.get(f.severity, self.RESET)
            mitre_str = ", ".join(f"{t} ({MITRE_MAP.get(t, '')})" for t in f.mitre) if f.mitre else ""
            comp_str = ", ".join(COMPLIANCE_MAP.get(c, c) for c in f.compliance) if f.compliance else ""

            print(f"  {self.BOLD}[{idx}]{self.RESET} {f.rule_id} — {clr}{f.severity}{self.RESET}")
            print(f"      {f.name}")
            print(f"      Cloud: {f.cloud}  |  Tactic: {f.tactic}")
            print(f"      Time: {f.event_time}")
            print(f"      Event: {f.event_name}")
            print(f"      Actor: {f.actor}")
            if f.source_ip:
                print(f"      Source IP: {f.source_ip}")
            if f.region:
                print(f"      Region: {f.region}")
            if mitre_str:
                print(f"      MITRE ATT&CK: {mitre_str}")
            if comp_str:
                print(f"      Compliance: {comp_str}")
            print(f"      Recommendation: {f.recommendation}")
            print()

        bar = "  ".join(f"{k}: {v}" for k, v in s.items())
        print(f"{'=' * 80}")
        print(f"  Summary:  {bar}")
        print(f"{'=' * 80}\n")

    # ════════════════════════════════════════════════════════════════════════
    #  JSON REPORT
    # ════════════════════════════════════════════════════════════════════════
    def save_json(self, path: str) -> None:
        data = {
            "scanner": "Cloud Detection & Response (CDR) Scanner",
            "version": __version__,
            "analysis_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "files_scanned": self.files_scanned,
            "events_analysed": self.events_analysed,
            "cloud_summary": {k: v for k, v in self.cloud_summary.items() if v > 0},
            "tactic_summary": self.tactic_summary,
            "summary": self.summary(),
            "findings": [asdict(f) for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        print(f"JSON report saved to {path}")

    # ════════════════════════════════════════════════════════════════════════
    #  HTML REPORT
    # ════════════════════════════════════════════════════════════════════════
    def save_html(self, path: str) -> None:
        s = self.summary()
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sev_colors = {"CRITICAL": "#ff4757", "HIGH": "#ff6b81", "MEDIUM": "#ffa502", "LOW": "#1e90ff", "INFO": "#a4b0be"}
        cloud_colors = {"AWS": "#ff9900", "AZURE": "#0078d4", "GCP": "#4285f4"}

        findings_html = ""
        for idx, f in enumerate(self.findings, 1):
            mitre_tags = "".join(f'<span class="tag mitre">{t}</span>' for t in f.mitre)
            comp_tags = "".join(f'<span class="tag comp">{COMPLIANCE_MAP.get(c, c)}</span>' for c in f.compliance)
            cloud_clr = cloud_colors.get(f.cloud, "#a4b0be")
            findings_html += f"""
            <tr class="sev-{f.severity}">
              <td>{idx}</td><td>{f.rule_id}</td>
              <td><span class="sev" style="background:{sev_colors.get(f.severity,'#a4b0be')}">{f.severity}</span></td>
              <td><span class="cloud" style="background:{cloud_clr}">{f.cloud}</span></td>
              <td>{f.tactic}</td><td>{f.name}</td>
              <td><code>{f.event_time}</code></td><td><code>{f.event_name}</code></td>
              <td><code>{f.actor[:60]}</code></td><td><code>{f.source_ip}</code></td>
              <td>{f.region}</td><td>{mitre_tags}</td><td>{comp_tags}</td>
              <td>{f.recommendation}</td>
            </tr>"""

        tactic_html = ""
        if self.tactic_summary:
            for tac, cnt in sorted(self.tactic_summary.items(), key=lambda x: -x[1]):
                tactic_html += f"<div class='tac-item'><span class='tac-name'>{tac}</span><span class='tac-count'>{cnt}</span></div>"

        cards_html = "".join(
            f'<div class="card" style="border-top:3px solid {sev_colors[sv]}">'
            f'<div class="card-count">{cnt}</div><div class="card-label">{sv}</div></div>'
            for sv, cnt in s.items()
        )

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CDR Threat Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0a1a;color:#e0e0e0}}
.header{{background:linear-gradient(135deg,#dc2626,#991b1b,#7f1d1d);padding:32px;text-align:center}}
.header h1{{font-size:28px;font-weight:700;color:#fff}}.header p{{color:#fca5a5;margin-top:6px}}
.meta{{display:flex;justify-content:center;gap:32px;margin-top:12px;color:#fecaca;font-size:13px}}
.cards{{display:flex;justify-content:center;gap:16px;padding:24px;flex-wrap:wrap}}
.card{{background:#1a1a2e;border-radius:8px;padding:20px 32px;text-align:center;min-width:120px}}
.card-count{{font-size:32px;font-weight:700;color:#fff}}.card-label{{font-size:13px;color:#a4b0be;margin-top:4px}}
.tactics{{background:#1a1a2e;margin:0 24px 16px;padding:16px 24px;border-radius:8px;border-left:3px solid #dc2626}}
.tac-item{{display:inline-flex;align-items:center;gap:6px;margin:4px 8px 4px 0;background:#2a2a3e;padding:4px 12px;border-radius:4px;font-size:13px}}
.tac-count{{background:#dc2626;color:#fff;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:700}}
.container{{padding:0 24px 24px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#1a1a2e;padding:10px 6px;text-align:left;position:sticky;top:0}}
td{{padding:6px;border-bottom:1px solid #2a2a3e;vertical-align:top}}
tr:hover{{background:#1e1e30}}
.sev{{padding:2px 8px;border-radius:4px;color:#fff;font-weight:600;font-size:11px}}
.cloud{{padding:2px 8px;border-radius:4px;color:#fff;font-weight:600;font-size:11px}}
.tag{{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;margin:1px}}
.tag.mitre{{background:#2a2a5e;color:#818cf8}}.tag.comp{{background:#1e3a2e;color:#6ee7b7}}
code{{background:#1a1a2e;padding:2px 4px;border-radius:3px;font-size:11px;word-break:break-all}}
.filters{{padding:8px 24px;display:flex;gap:12px;flex-wrap:wrap;align-items:center}}
.filters label{{font-size:13px;cursor:pointer;display:flex;align-items:center;gap:4px}}
</style></head><body>
<div class="header"><h1>Cloud Detection & Response — Threat Report</h1>
<p>Multi-Cloud Audit Log Analysis &amp; Threat Detection</p>
<div class="meta"><span>Version {__version__}</span><span>{now}</span>
<span>Files: {self.files_scanned}</span><span>Events: {self.events_analysed}</span>
<span>Threats: {len(self.findings)}</span></div></div>
<div class="cards">{cards_html}</div>
{"<div class='tactics'><strong>MITRE ATT&CK Tactics</strong><br><br>" + tactic_html + "</div>" if tactic_html else ""}
<div class="filters"><strong>Filter:</strong>
{"".join(f'<label><input type="checkbox" checked onchange="filterSev()" class="sev-chk" value="{sv}"> {sv}</label>' for sv in s)}</div>
<div class="container"><table><thead><tr>
<th>#</th><th>Rule</th><th>Severity</th><th>Cloud</th><th>Tactic</th><th>Threat</th>
<th>Time</th><th>Event</th><th>Actor</th><th>Source IP</th><th>Region</th>
<th>MITRE</th><th>Compliance</th><th>Recommendation</th>
</tr></thead><tbody>{findings_html}</tbody></table></div>
<script>
function filterSev(){{
  const chk=document.querySelectorAll('.sev-chk');
  const on=new Set();chk.forEach(c=>{{if(c.checked)on.add(c.value)}});
  document.querySelectorAll('tbody tr').forEach(r=>{{
    const s=r.className.replace('sev-','');r.style.display=on.has(s)?'':'none';
  }});
}}
</script></body></html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"HTML report saved to {path}")


# ════════════════════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════════════════════
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cdr_scanner.py",
        description="Cloud Detection & Response (CDR) Scanner — Multi-cloud audit log threat analysis",
    )
    parser.add_argument("target", help="JSON log file or directory containing log files")
    parser.add_argument("--json", metavar="FILE", dest="json_file", help="Save JSON report")
    parser.add_argument("--html", metavar="FILE", dest="html_file", help="Save HTML report")
    parser.add_argument("--severity", metavar="SEV", default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"CDR Scanner v{__version__}")
    args = parser.parse_args()

    scanner = CDRScanner(verbose=args.verbose)
    scanner.scan_path(args.target)
    scanner.filter_severity(args.severity)
    scanner.print_report()
    if args.json_file:
        scanner.save_json(args.json_file)
    if args.html_file:
        scanner.save_html(args.html_file)

    s = scanner.summary()
    sys.exit(1 if s.get("CRITICAL", 0) + s.get("HIGH", 0) > 0 else 0)


if __name__ == "__main__":
    main()
