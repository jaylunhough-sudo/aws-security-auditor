#!/usr/bin/env python3
"""Check #3: root account MFA and root access keys.

CIS AWS Foundations 1.5/1.6 (v1.x numbering: 1.13/1.12) · SOC 2 CC6.1.
The root account can do anything, including delete the whole account —
it must have MFA and must not have programmatic access keys.
"""

from __future__ import annotations

import json
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

try:
    from checks.models import Finding, print_findings
except ImportError:  # running as a script from the checks/ directory
    from models import Finding, print_findings

CHECK_ID_MFA = "UC-003"
CHECK_ID_KEYS = "UC-003b"


def run_check(profile: str | None = None, region: str | None = None) -> list[Finding]:
    session_kwargs: dict[str, str] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]

    findings: list[Finding] = []

    mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
    findings.append(
        Finding(
            check_id=CHECK_ID_MFA,
            check_name="Root account MFA",
            resource="root account",
            region="global",
            severity="critical",
            status="pass" if mfa_enabled else "fail",
            detection=(
                "Root account has MFA enabled"
                if mfa_enabled
                else "Root account has NO multi-factor authentication"
            ),
            plain_english_risk=(
                ""
                if mfa_enabled
                else "Anyone who phishes or guesses the root password owns your entire "
                "AWS account — every server, every database, every backup. MFA is the "
                "single highest-impact security setting in AWS."
            ),
            fix_terraform="",  # root MFA cannot be managed via Terraform
            fix_cli=(
                ""
                if mfa_enabled
                else "Console only: sign in as root -> account menu -> Security credentials "
                "-> Assign MFA device -> Authenticator app"
            ),
            cis_refs=["1.5"],
            soc2_refs=["CC6.1"],
        )
    )

    keys_present = summary.get("AccountAccessKeysPresent", 0) != 0
    findings.append(
        Finding(
            check_id=CHECK_ID_KEYS,
            check_name="Root access keys",
            resource="root account",
            region="global",
            severity="critical",
            status="fail" if keys_present else "pass",
            detection=(
                "Root account has active access keys"
                if keys_present
                else "Root account has no access keys"
            ),
            plain_english_risk=(
                "Programmatic keys for the root user exist. If they leak (a laptop, a "
                "repo, a CI log), the attacker has unlimited, unrevokable-by-policy "
                "access to everything. Root keys have no legitimate use."
                if keys_present
                else ""
            ),
            fix_terraform="",
            fix_cli=(
                "Console only: sign in as root -> Security credentials -> Access keys "
                "-> Delete. Create an IAM user or role for anything programmatic."
                if keys_present
                else ""
            ),
            cis_refs=["1.4"],
            soc2_refs=["CC6.1"],
        )
    )

    return findings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Check root account MFA and access keys.")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", help="Default AWS region for the session")
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
        print(f"Checked root account security ({len(findings)} control(s))\n")
        print_findings(findings)
        print(f"Summary: {len(failed)} root account issue(s)")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
