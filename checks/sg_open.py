#!/usr/bin/env python3
"""Check security groups for inbound rules open to the internet.

Three-output standard: detection, plain-English risk, and an exact fix
command for every finding. CIS AWS Foundations 5.2/5.3 · SOC 2 CC6.6.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

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


@dataclass
class RuleFinding:
    port_label: str
    service: str
    source: str
    risk: str
    fix: str


@dataclass
class GroupFinding:
    group_id: str
    group_name: str
    vpc_id: str
    region: str
    risky: bool
    rules: list[RuleFinding] = field(default_factory=list)


def _public_sources(permission: dict[str, Any]) -> list[str]:
    sources = [
        r["CidrIp"] for r in permission.get("IpRanges", []) if r.get("CidrIp") == PUBLIC_V4
    ]
    sources += [
        r["CidrIpv6"] for r in permission.get("Ipv6Ranges", []) if r.get("CidrIpv6") == PUBLIC_V6
    ]
    return sources


def _ports_in_range(permission: dict[str, Any]) -> tuple[str, list[int]]:
    """Return a human label for the rule's port range and the sensitive ports it covers."""
    if permission.get("IpProtocol") == "-1":
        return "ALL ports / ALL protocols", list(SENSITIVE_PORTS)

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return "unknown ports", []

    label = str(from_port) if from_port == to_port else f"{from_port}-{to_port}"
    covered = [p for p in SENSITIVE_PORTS if from_port <= p <= to_port]
    return label, covered


def _revoke_command(group_id: str, permission: dict[str, Any], source: str, region: str) -> str:
    if permission.get("IpProtocol") == "-1":
        proto_args = "--protocol all"
    else:
        proto_args = (
            f"--protocol {permission.get('IpProtocol', 'tcp')} "
            f"--port {permission.get('FromPort')}"
            if permission.get("FromPort") == permission.get("ToPort")
            else f"--protocol {permission.get('IpProtocol', 'tcp')} "
            f"--port {permission.get('FromPort')}-{permission.get('ToPort')}"
        )
    cidr_flag = "--cidr" if source == PUBLIC_V4 else "--source-group"  # v6 handled below
    if source == PUBLIC_V6:
        return (
            f"aws ec2 revoke-security-group-ingress --group-id {group_id} "
            f"--ip-permissions 'IpProtocol={permission.get('IpProtocol', 'tcp')},"
            f"FromPort={permission.get('FromPort')},ToPort={permission.get('ToPort')},"
            f"Ipv6Ranges=[{{CidrIpv6=::/0}}]' --region {region}"
        )
    return (
        f"aws ec2 revoke-security-group-ingress --group-id {group_id} "
        f"{proto_args} {cidr_flag} {source} --region {region}"
    )


def check_group(group: dict[str, Any], region: str) -> GroupFinding:
    finding = GroupFinding(
        group_id=group["GroupId"],
        group_name=group.get("GroupName", "unnamed"),
        vpc_id=group.get("VpcId", "no-vpc"),
        region=region,
        risky=False,
    )

    for permission in group.get("IpPermissions", []):
        sources = _public_sources(permission)
        if not sources:
            continue

        port_label, sensitive_hit = _ports_in_range(permission)

        for source in sources:
            if permission.get("IpProtocol") == "-1":
                risk = (
                    "Anyone on the internet can reach EVERY port on anything using this "
                    "group - this is a fully open door"
                )
            elif sensitive_hit:
                services = ", ".join(SENSITIVE_PORTS[p] for p in sensitive_hit)
                risk = (
                    f"Anyone on the internet can attempt to connect to {services} "
                    "on anything using this group - these ports are scanned constantly "
                    "and brute-forced within hours"
                )
            else:
                # Public web ports (80/443 etc.) are often intentional; report as info-level.
                continue

            finding.rules.append(
                RuleFinding(
                    port_label=port_label,
                    service=", ".join(SENSITIVE_PORTS[p] for p in sensitive_hit) or "all services",
                    source=source,
                    risk=risk,
                    fix=_revoke_command(finding.group_id, permission, source, region),
                )
            )
            finding.risky = True

    return finding


def run_check(profile: str | None = None, region: str | None = None) -> list[GroupFinding]:
    session_kwargs: dict[str, Any] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    ec2 = session.client("ec2")
    active_region = ec2.meta.region_name

    findings: list[GroupFinding] = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for group in page.get("SecurityGroups", []):
            findings.append(check_group(group, active_region))
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

    risky_groups = [finding for finding in findings if finding.risky]

    if args.json:
        print(json.dumps([asdict(finding) for finding in findings], indent=2))
    else:
        print(f"Scanned {len(findings)} security group(s)\n")
        if not findings:
            print("No security groups found in this region.")
        for finding in findings:
            status = "OPEN TO INTERNET" if finding.risky else "OK"
            print(
                f"[{status}] {finding.group_id} '{finding.group_name}' "
                f"({finding.vpc_id}, {finding.region})"
            )
            for rule in finding.rules:
                print(f"  - Ports {rule.port_label} open to {rule.source}")
                print(f"    Risk: {rule.risk}")
                print(f"    Fix:  {rule.fix}")
            if not finding.rules:
                print("  - No sensitive ports exposed to the internet")
            print()

        print(f"Summary: {len(risky_groups)} security group(s) open to the internet")

    return 1 if risky_groups else 0


if __name__ == "__main__":
    raise SystemExit(main())
