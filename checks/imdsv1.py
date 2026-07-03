#!/usr/bin/env python3
"""Check #9: EC2 instances that still allow IMDSv1.

CIS AWS Foundations 5.6 · SOC 2 CC6.6.
IMDSv1 is how Capital One got breached: a server-side request forgery
tricks the instance into handing its IAM credentials to an attacker.
IMDSv2 (session tokens) closes that door with zero application impact
for almost every workload.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

try:
    from checks.models import Finding, print_findings
    from checks.aws_session import build_session
except ImportError:
    from models import Finding, print_findings
    from aws_session import build_session

CHECK_ID = "UC-009"


def run_check(
    profile: str | None = None,
    region: str | None = None,
    session: boto3.Session | None = None,
) -> list[Finding]:
    if session is None:
        session = build_session(profile=profile, region=region)
    ec2 = session.client("ec2")
    active_region = ec2.meta.region_name

    findings: list[Finding] = []
    flagged = 0
    total = 0

    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]}]
    ):
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                total += 1
                instance_id = instance["InstanceId"]
                metadata = instance.get("MetadataOptions", {})
                if metadata.get("HttpTokens") == "required":
                    continue
                flagged += 1
                findings.append(
                    Finding(
                        check_id=CHECK_ID,
                        check_name="EC2 instance allows IMDSv1",
                        resource=instance_id,
                        region=active_region,
                        severity="high",
                        status="fail",
                        detection=(
                            f"Instance metadata HttpTokens is "
                            f"'{metadata.get('HttpTokens', 'unset')}' (IMDSv1 allowed)"
                        ),
                        plain_english_risk=(
                            "If any app on this server can be tricked into fetching a "
                            "URL (a common web bug), an attacker can steal the server's "
                            "AWS credentials and act as it. This exact weakness caused "
                            "the Capital One breach."
                        ),
                        fix_terraform=(
                            'resource "aws_instance" "this" {\n'
                            "  # ... existing config ...\n"
                            "  metadata_options {\n"
                            '    http_tokens = "required"\n'
                            "  }\n"
                            "}"
                        ),
                        fix_cli=(
                            f"aws ec2 modify-instance-metadata-options "
                            f"--instance-id {instance_id} --http-tokens required "
                            f"--http-endpoint enabled --region {active_region}"
                        ),
                        cis_refs=["5.6"],
                        soc2_refs=["CC6.6"],
                    )
                )

    if flagged == 0:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name="EC2 instance allows IMDSv1",
                resource=f"all EC2 instances ({total} checked)",
                region=active_region,
                severity="high",
                status="pass",
                detection="All instances require IMDSv2 session tokens"
                if total
                else "No EC2 instances in this region",
                plain_english_risk="",
                fix_terraform="",
                fix_cli="",
                cis_refs=["5.6"],
                soc2_refs=["CC6.6"],
            )
        )
    return findings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Flag EC2 instances allowing IMDSv1.")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", help="AWS region to scan")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    try:
        findings = run_check(profile=args.profile, region=args.region)
    except (NoCredentialsError, ProfileNotFound) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except ClientError as error:
        print(f"ERROR: AWS API call failed: {error}", file=sys.stderr)
        return 1

    failed = [f for f in findings if f.status == "fail"]
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print("Checked EC2 instance metadata service\n")
        print_findings(findings)
        print(f"Summary: {len(failed)} IMDSv1 instance(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
