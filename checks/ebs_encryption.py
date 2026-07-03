#!/usr/bin/env python3
"""Check #7: unencrypted EBS volumes and default encryption disabled.

CIS AWS Foundations 2.2.1 · SOC 2 CC6.7 (data at rest).
Encryption at rest is a question on every security review and audit.
AWS makes it free and transparent — there is no reason to skip it.
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

CHECK_ID = "UC-007"

FIX_TERRAFORM = (
    'resource "aws_ebs_encryption_by_default" "on" {\n'
    "  enabled = true\n"
    "}\n"
    "# Existing volumes cannot be encrypted in place: snapshot -> copy the\n"
    "# snapshot with encryption -> create a new volume -> swap it in."
)


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

    default_on = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    findings.append(
        Finding(
            check_id=CHECK_ID,
            check_name="EBS default encryption",
            resource="account EBS default",
            region=active_region,
            severity="medium",
            status="pass" if default_on else "fail",
            detection=(
                "EBS encryption-by-default is enabled"
                if default_on
                else "EBS encryption-by-default is disabled for this region"
            ),
            plain_english_risk=(
                ""
                if default_on
                else "Every new disk created in this region starts unencrypted unless "
                "someone remembers to tick a box. One forgotten disk with customer data "
                "on it is an audit exception and a breach-disclosure risk."
            ),
            fix_terraform=FIX_TERRAFORM if not default_on else "",
            fix_cli=(
                f"aws ec2 enable-ebs-encryption-by-default --region {active_region}"
                if not default_on
                else ""
            ),
            cis_refs=["2.2.1"],
            soc2_refs=["CC6.7"],
        )
    )

    paginator = ec2.get_paginator("describe_volumes")
    unencrypted = 0
    for page in paginator.paginate():
        for volume in page.get("Volumes", []):
            if volume.get("Encrypted"):
                continue
            unencrypted += 1
            volume_id = volume["VolumeId"]
            attached_to = ", ".join(
                a.get("InstanceId", "?") for a in volume.get("Attachments", [])
            ) or "unattached"
            findings.append(
                Finding(
                    check_id=CHECK_ID,
                    check_name="Unencrypted EBS volume",
                    resource=volume_id,
                    region=active_region,
                    severity="medium",
                    status="fail",
                    detection=f"Volume is not encrypted (attached to: {attached_to})",
                    plain_english_risk=(
                        "The data on this disk sits unencrypted in AWS's storage layer. "
                        "If a snapshot of it is ever shared or leaks, the contents are "
                        "readable by whoever gets it — and your auditor will flag it."
                    ),
                    fix_terraform=FIX_TERRAFORM,
                    fix_cli=(
                        f"# Encrypt via snapshot-copy-restore:\n"
                        f"aws ec2 create-snapshot --volume-id {volume_id}\n"
                        f"aws ec2 copy-snapshot --source-snapshot-id <snap-id> "
                        f"--source-region {active_region} --encrypted\n"
                        f"# then create a volume from the encrypted copy and swap it in"
                    ),
                    cis_refs=["2.2.1"],
                    soc2_refs=["CC6.7"],
                )
            )

    if unencrypted == 0:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name="Unencrypted EBS volume",
                resource="all EBS volumes",
                region=active_region,
                severity="medium",
                status="pass",
                detection="All EBS volumes in this region are encrypted",
                plain_english_risk="",
                fix_terraform="",
                fix_cli="",
                cis_refs=["2.2.1"],
                soc2_refs=["CC6.7"],
            )
        )
    return findings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Flag unencrypted EBS volumes.")
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
        print("Checked EBS encryption\n")
        print_findings(findings)
        print(f"Summary: {len(failed)} encryption issue(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
