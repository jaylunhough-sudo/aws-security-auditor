#!/usr/bin/env python3
"""Check #4: customer-managed IAM policies granting full admin (*:*).

CIS AWS Foundations 1.16 · SOC 2 CC6.1 / CC6.3.
A policy that allows every action on every resource is a standing invitation
for privilege escalation — one leaked credential attached to it owns the account.
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

CHECK_ID = "UC-004"

FIX_TERRAFORM = (
    "# Replace the *:* policy with least-privilege statements, e.g.:\n"
    'resource "aws_iam_policy" "scoped" {\n'
    '  name   = "app-s3-read"\n'
    "  policy = jsonencode({\n"
    "    Version = \"2012-10-17\"\n"
    "    Statement = [{\n"
    "      Effect   = \"Allow\"\n"
    "      Action   = [\"s3:GetObject\", \"s3:ListBucket\"]\n"
    "      Resource = [\"arn:aws:s3:::my-bucket\", \"arn:aws:s3:::my-bucket/*\"]\n"
    "    }]\n"
    "  })\n"
    "}"
)


def _statement_is_full_admin(statement: dict[str, Any]) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    actions = statement.get("Action", [])
    resources = statement.get("Resource", [])
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]
    return "*" in actions and "*" in resources


def run_check(
    profile: str | None = None,
    region: str | None = None,
    session: boto3.Session | None = None,
) -> list[Finding]:
    if session is None:
        session = build_session(profile=profile, region=region)
    iam = session.client("iam")

    findings: list[Finding] = []
    paginator = iam.get_paginator("list_policies")
    admin_policies: list[str] = []

    for page in paginator.paginate(Scope="Local"):
        for policy in page.get("Policies", []):
            arn = policy["Arn"]
            version = iam.get_policy_version(
                PolicyArn=arn, VersionId=policy["DefaultVersionId"]
            )
            document = version["PolicyVersion"]["Document"]
            statements = document.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            if any(_statement_is_full_admin(s) for s in statements):
                admin_policies.append(arn)
                findings.append(
                    Finding(
                        check_id=CHECK_ID,
                        check_name="IAM policy allows full admin",
                        resource=arn,
                        region="global",
                        severity="high",
                        status="fail",
                        detection='Customer-managed policy allows Action "*" on Resource "*"',
                        plain_english_risk=(
                            "Anything attached to this policy — a user, a role, a leaked "
                            "key — can do absolutely everything in your AWS account: read "
                            "data, delete backups, create bills. One compromised credential "
                            "becomes total account takeover."
                        ),
                        fix_terraform=FIX_TERRAFORM,
                        fix_cli=(
                            f"aws iam list-entities-for-policy --policy-arn {arn}  "
                            f"# see what uses it, then replace with a scoped policy and "
                            f"detach this one"
                        ),
                        cis_refs=["1.16"],
                        soc2_refs=["CC6.1", "CC6.3"],
                    )
                )

    if not admin_policies:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name="IAM policy allows full admin",
                resource="all customer-managed policies",
                region="global",
                severity="high",
                status="pass",
                detection="No customer-managed policy grants *:* full admin",
                plain_english_risk="",
                fix_terraform="",
                fix_cli="",
                cis_refs=["1.16"],
                soc2_refs=["CC6.1", "CC6.3"],
            )
        )
    return findings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Flag customer-managed *:* admin policies.")
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
        print(f"Checked customer-managed IAM policies\n")
        print_findings(findings)
        print(f"Summary: {len(failed)} full-admin polic(ies)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
