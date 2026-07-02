#!/usr/bin/env python3
"""Check #2: security groups with sensitive ports open to the internet.

CIS AWS Foundations 5.2/5.3 · SOC 2 CC6.6.
Ports 80/443 open to the world are usually intentional (websites) and are
NOT flagged — noise kills posture tools. Emits the three-output standard.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

try:
    from checks.models import Finding, print_findings
except ImportError:  # running as a script from the checks/ directory
    from models import Finding, print_findings

CHECK_ID = "UC-002"

PUBLIC_V4 = "0.0.0.0/0"
PUBLIC_V6 = "::/0"

# Ports where internet exposure is almost always a mistake.
SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH (remote server login)",
    3389: "RDP (remote desktop)",
    3306: "MySQL database",
    5432: "PostgreSQL database",
    27017: "MongoDB database",
    6379: "Redis cache",
    1433: "SQL Server database",
    9200: "Elasticsearch",
    5601: "Kibana dashboard",
}


def _public_sources(permission: dict[str, Any]) -> list[str]:
    sources = [
        r["CidrIp"] for r in permission.get("IpRanges", []) if r.get("CidrIp") == PUBLIC_V4
    ]
    sources += [
        r["CidrIpv6"] for r in permission.get("Ipv6Ranges", []) if r.get("CidrIpv6") == PUBLIC_V6
    ]
    return sources


def _ports_in_range(permission: dict[str, Any]) -> tuple[str, list[int]]:
    """Return a label for the rule's port range and the sensitive ports it covers."""
    if permission.get("IpProtocol") == "-1":
        return "ALL ports / ALL protocols", list(SENSITIVE_PORTS)

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return "unknown ports", []

    label = str(from_port) if from_port == to_port else f"{from_port}-{to_port}"
    covered = [p for p in SENSITIVE_PORTS if from_port <= p <= to_port]
    return label, covered


def _fix_cli(group_id: str, permission: dict[str, Any], source: str, region: str) -> str:
    if source == PUBLIC_V6:
        return (
            f"aws ec2 revoke-security-group-ingress --group-id {group_id} "
            f"--ip-permissions 'IpProtocol={permission.get('IpProtocol', 'tcp')},"
            f"FromPort={permission.get('FromPort')},ToPort={permission.get('ToPort')},"
            f"Ipv6Ranges=[{{CidrIpv6=::/0}}]' --region {region}"
        )
    if permission.get("IpProtocol") == "-1":
        proto_args = "--protocol all"
    elif permission.get("FromPort") == permission.get("ToPort"):
        proto_args = (
            f"--protocol {permission.get('IpProtocol', 'tcp')} "
            f"--port {permission.get('FromPort')}"
        )
    else:
        proto_args = (
            f"--protocol {permission.get('IpProtocol', 'tcp')} "
            f"--port {permission.get('FromPort')}-{permission.get('ToPort')}"
        )
    return (
        f"aws ec2 revoke-security-group-ingress --group-id {group_id} "
        f"{proto_args} --cidr {source} --region {region}"
    )


def _fix_terraform(port_label: str) -> str:
    return (
        "# Replace the open ingress rule with one restricted to a trusted CIDR\n"
        'resource "aws_vpc_security_group_ingress_rule" "restricted" {\n'
        "  security_group_id = <your-sg-id>\n"
        '  cidr_ipv4         = "YOUR.OFFICE.IP.0/32"  # never 0.0.0.0/0\n'
        f"  # ports: {port_label}\n"
        "}\n"
        "# Better for SSH: delete the rule entirely and use AWS SSM Session Manager"
    )


def check_group(group: dict[str, Any], region: str) -> list[Finding]:
    findings: list[Finding] = []
    group_id = group["GroupId"]
    group_name = group.get("GroupName", "unnamed")
    resource = f"{group_id} '{group_name}'"

    risky_rules: list[tuple[str, str, list[int], dict[str, Any]]] = []
    for permission in group.get("IpPermissions", []):
        sources = _public_sources(permission)
        if not sources:
            continue
        port_label, sensitive_hit = _ports_in_range(permission)
        all_protocols = permission.get("IpProtocol") == "-1"
        if not sensitive_hit and not all_protocols:
            continue  # public web ports (80/443) are often intentional
        for source in sources:
            risky_rules.append((port_label, source, sensitive_hit, permission))

    if not risky_rules:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name="Security group open to internet",
                resource=resource,
                region=region,
                severity="high",
                status="pass",
                detection="No sensitive ports exposed to the internet",
                plain_english_risk="",
                fix_terraform="",
                fix_cli="",
                cis_refs=["5.2", "5.3"],
                soc2_refs=["CC6.6"],
            )
        )
        return findings

    for port_label, source, sensitive_hit, permission in risky_rules:
        if permission.get("IpProtocol") == "-1":
            risk = (
                "Anyone on the internet can reach EVERY port on anything using this "
                "group — this is a fully open door."
            )
        else:
            services = ", ".join(SENSITIVE_PORTS[p] for p in sensitive_hit)
            risk = (
                f"Anyone on the internet can attempt to connect to {services} on "
                "anything using this group — these ports are scanned constantly and "
                "brute-forced within hours."
            )
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name="Security group open to internet",
                resource=resource,
                region=region,
                severity="high",
                status="fail",
                detection=f"Inbound ports {port_label} open to {source}",
                plain_english_risk=risk,
                fix_terraform=_fix_terraform(port_label),
                fix_cli=_fix_cli(group_id, permission, source, region),
                cis_refs=["5.2", "5.3"],
                soc2_refs=["CC6.6"],
            )
        )
    return findings


def run_check(profile: str | None = None, region: str | None = None) -> list[Finding]:
    session_kwargs: dict[str, Any] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    ec2 = session.client("ec2")
    active_region = ec2.meta.region_name

    findings: list[Finding] = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for group in page.get("SecurityGroups", []):
            findings.extend(check_group(group, active_region))
    return findings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Flag security groups with sensitive ports open to the internet."
    )
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", help="AWS region to scan (defaults to profile region)")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    try:
        findings = run_check(profile=args.profile, region=args.region)
    except (NoCredentialsError, ProfileNotFound) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        print(
            "Configure credentials first, e.g. `aws configure` or export AWS_ACCESS_KEY_ID.",
            file=sys.stderr,
        )
        return 2
    except ClientError as error:
        print(f"ERROR: AWS API call failed: {error}", file=sys.stderr)
        return 1

    failed = [f for f in findings if f.status == "fail"]

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        groups = {f.resource for f in findings}
        print(f"Scanned {len(groups)} security group(s)\n")
        if not findings:
            print("No security groups found in this region.")
        print_findings(findings)
        print(f"Summary: {len(failed)} open-to-internet rule(s)")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
