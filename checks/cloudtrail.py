#!/usr/bin/env python3
"""Check #5: CloudTrail disabled or not multi-region.

CIS AWS Foundations 3.1 · SOC 2 CC7.2.
Without CloudTrail there is no record of who did what — no breach
investigation, no auditor evidence, no answer to "how did this happen".
"""

from __future__ import annotations

import json
import sys
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

try:
    from checks.models import Finding, print_findings
except ImportError:
    from models import Finding, print_findings

CHECK_ID = "UC-005"

FIX_TERRAFORM = (
    'resource "aws_cloudtrail" "main" {\n'
    '  name                          = "org-trail"\n'
    "  s3_bucket_name                = aws_s3_bucket.trail_logs.id\n"
    "  is_multi_region_trail         = true\n"
    "  enable_log_file_validation    = true\n"
    "  include_global_service_events = true\n"
    "}"
)


def run_check(profile: str | None = None, region: str | None = None) -> list[Finding]:
    session_kwargs: dict[str, Any] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    trail_client = session.client("cloudtrail")
    active_region = trail_client.meta.region_name

    trails = trail_client.describe_trails(includeShadowTrails=True).get("trailList", [])

    logging_multi_region = []
    for trail in trails:
        if not trail.get("IsMultiRegionTrail"):
            continue
        try:
            status = trail_client.get_trail_status(Name=trail["TrailARN"])
            if status.get("IsLogging"):
                logging_multi_region.append(trail.get("Name", trail["TrailARN"]))
        except ClientError:
            continue

    if logging_multi_region:
        detection = (
            f"Multi-region trail(s) actively logging: {', '.join(logging_multi_region)}"
        )
        status = "pass"
    elif trails:
        detection = (
            f"{len(trails)} trail(s) exist but none is a logging multi-region trail"
        )
        status = "fail"
    else:
        detection = "No CloudTrail trails exist in this account"
        status = "fail"

    finding = Finding(
        check_id=CHECK_ID,
        check_name="CloudTrail multi-region logging",
        resource="account trails",
        region=active_region,
        severity="high",
        status=status,
        detection=detection,
        plain_english_risk=(
            ""
            if status == "pass"
            else "Nothing is recording who does what in your AWS account. If credentials "
            "leak or data disappears, you will have no way to know what happened, when, "
            "or how — and no activity evidence to show an auditor."
        ),
        fix_terraform=FIX_TERRAFORM if status == "fail" else "",
        fix_cli=(
            "aws cloudtrail create-trail --name org-trail --s3-bucket-name "
            "<your-log-bucket> --is-multi-region-trail && "
            "aws cloudtrail start-logging --name org-trail"
            if status == "fail"
            else ""
        ),
        cis_refs=["3.1"],
        soc2_refs=["CC7.2"],
    )
    return [finding]


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Check CloudTrail multi-region logging.")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", help="Default AWS region for the session")
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
        print("Checked CloudTrail configuration\n")
        print_findings(findings)
        print(f"Summary: {len(failed)} logging issue(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
