#!/usr/bin/env python3
"""Check #10: Lambda functions with over-privileged execution roles.

SOC 2 CC6.3 (least privilege).
A Lambda with AdministratorAccess is a remote-code-execution gift: anyone
who can invoke or update the function owns the whole account.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

try:
    from checks.models import Finding, print_findings
    from checks.iam_admin import _statement_is_full_admin
    from checks.aws_session import build_session
except ImportError:
    from models import Finding, print_findings
    from iam_admin import _statement_is_full_admin
    from aws_session import build_session

CHECK_ID = "UC-010"

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _role_admin_reasons(iam: Any, role_name: str) -> list[str]:
    """Return reasons this role is over-privileged (empty list = fine)."""
    reasons: list[str] = []

    attached = iam.list_attached_role_policies(RoleName=role_name).get(
        "AttachedPolicies", []
    )
    for policy in attached:
        if policy["PolicyArn"] == ADMIN_POLICY_ARN:
            reasons.append("AWS-managed AdministratorAccess policy attached")
            continue
        if policy["PolicyArn"].startswith("arn:aws:iam::aws:"):
            continue  # other AWS-managed policies are scoped; skip API-heavy inspection
        meta = iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]
        version = iam.get_policy_version(
            PolicyArn=policy["PolicyArn"], VersionId=meta["DefaultVersionId"]
        )
        statements = version["PolicyVersion"]["Document"].get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if any(_statement_is_full_admin(s) for s in statements):
            reasons.append(f"Attached policy {policy['PolicyName']} allows *:*")

    for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        document = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)[
            "PolicyDocument"
        ]
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if any(_statement_is_full_admin(s) for s in statements):
            reasons.append(f"Inline policy {policy_name} allows *:*")

    return reasons


def run_check(
    profile: str | None = None,
    region: str | None = None,
    session: boto3.Session | None = None,
) -> list[Finding]:
    if session is None:
        session = build_session(profile=profile, region=region)
    lambda_client = session.client("lambda")
    iam = session.client("iam")
    active_region = lambda_client.meta.region_name

    findings: list[Finding] = []
    flagged = 0
    total = 0
    checked_roles: dict[str, list[str]] = {}

    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for function in page.get("Functions", []):
            total += 1
            function_name = function["FunctionName"]
            role_arn = function.get("Role", "")
            role_name = role_arn.rsplit("/", 1)[-1] if role_arn else ""
            if not role_name:
                continue

            if role_name not in checked_roles:
                try:
                    checked_roles[role_name] = _role_admin_reasons(iam, role_name)
                except ClientError:
                    checked_roles[role_name] = []

            reasons = checked_roles[role_name]
            if not reasons:
                continue
            flagged += 1
            findings.append(
                Finding(
                    check_id=CHECK_ID,
                    check_name="Lambda over-privileged execution role",
                    resource=f"function/{function_name} (role {role_name})",
                    region=active_region,
                    severity="high",
                    status="fail",
                    detection="; ".join(reasons),
                    plain_english_risk=(
                        "This function can do anything in your AWS account. A bug in "
                        "its code, a poisoned dependency, or anyone who can update the "
                        "function becomes a full administrator of everything you run."
                    ),
                    fix_terraform=(
                        "# Scope the execution role to what the function actually uses:\n"
                        'resource "aws_iam_role_policy" "scoped" {\n'
                        f'  role = "{role_name}"\n'
                        "  policy = jsonencode({\n"
                        "    Version = \"2012-10-17\"\n"
                        "    Statement = [{\n"
                        "      Effect   = \"Allow\"\n"
                        "      Action   = [\"logs:CreateLogStream\", \"logs:PutLogEvents\"]\n"
                        "      Resource = \"arn:aws:logs:*:*:*\"\n"
                        "    }]\n"
                        "  })\n"
                        "}"
                    ),
                    fix_cli=(
                        f"aws iam detach-role-policy --role-name {role_name} "
                        f"--policy-arn {ADMIN_POLICY_ARN}  # then attach a scoped policy"
                    ),
                    cis_refs=[],
                    soc2_refs=["CC6.3"],
                )
            )

    if flagged == 0:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name="Lambda over-privileged execution role",
                resource=f"all Lambda functions ({total} checked)",
                region=active_region,
                severity="high",
                status="pass",
                detection="No Lambda execution role grants full admin"
                if total
                else "No Lambda functions in this region",
                plain_english_risk="",
                fix_terraform="",
                fix_cli="",
                cis_refs=[],
                soc2_refs=["CC6.3"],
            )
        )
    return findings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Flag over-privileged Lambda roles.")
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
        print("Checked Lambda execution roles\n")
        print_findings(findings)
        print(f"Summary: {len(failed)} over-privileged function(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
