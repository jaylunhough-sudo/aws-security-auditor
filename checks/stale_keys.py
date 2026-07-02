#!/usr/bin/env python3
"""Check #6: IAM access keys older than 90 days.

CIS AWS Foundations 1.14 · SOC 2 CC6.1.
Old keys accumulate exposure: ex-employees' laptops, forgotten CI configs,
old repos. Rotation caps how long a silent leak stays exploitable.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

try:
    from checks.models import Finding, print_findings
except ImportError:
    from models import Finding, print_findings

CHECK_ID = "UC-006"
MAX_AGE_DAYS = 90


def run_check(profile: str | None = None, region: str | None = None) -> list[Finding]:
    session_kwargs: dict[str, Any] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    iam = session.client("iam")
    now = datetime.now(timezone.utc)

    findings: list[Finding] = []
    stale_found = False

    user_paginator = iam.get_paginator("list_users")
    for page in user_paginator.paginate():
        for user in page.get("Users", []):
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                if key.get("Status") != "Active":
                    continue
                age_days = (now - key["CreateDate"]).days
                if age_days <= MAX_AGE_DAYS:
                    continue
                stale_found = True
                key_id = key["AccessKeyId"]
                findings.append(
                    Finding(
                        check_id=CHECK_ID,
                        check_name="Stale access key",
                        resource=f"user/{username} key {key_id}",
                        region="global",
                        severity="medium",
                        status="fail",
                        detection=f"Active access key is {age_days} days old (max {MAX_AGE_DAYS})",
                        plain_english_risk=(
                            f"This key has been valid for {age_days} days. The longer a key "
                            "lives, the more places it has been — old laptops, CI logs, "
                            "config files — and any one of those copies still works today."
                        ),
                        fix_terraform="",  # key rotation is operational, not IaC
                        fix_cli=(
                            f"# 1. Create a new key, update whatever uses it, then:\n"
                            f"aws iam update-access-key --user-name {username} "
                            f"--access-key-id {key_id} --status Inactive\n"
                            f"# 2. After confirming nothing broke:\n"
                            f"aws iam delete-access-key --user-name {username} "
                            f"--access-key-id {key_id}"
                        ),
                        cis_refs=["1.14"],
                        soc2_refs=["CC6.1"],
                    )
                )

    if not stale_found:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name="Stale access key",
                resource="all IAM user access keys",
                region="global",
                severity="medium",
                status="pass",
                detection=f"No active access keys older than {MAX_AGE_DAYS} days",
                plain_english_risk="",
                fix_terraform="",
                fix_cli="",
                cis_refs=["1.14"],
                soc2_refs=["CC6.1"],
            )
        )
    return findings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Flag IAM access keys older than 90 days.")
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
        print("Checked IAM access key ages\n")
        print_findings(findings)
        print(f"Summary: {len(failed)} stale key(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
