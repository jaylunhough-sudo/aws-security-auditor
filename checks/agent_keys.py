#!/usr/bin/env python3
"""Check #21 (AI pack): machine identities running on long-lived access keys.

SOC 2 CC6.1.
Agents, bots, and automation frameworks (n8n, Zapier, LangChain apps...)
are usually wired up with an IAM user's access keys because it's the path
of least resistance. Those keys never expire, end up in .env files and
config screens, and outlive the person who created them. Machines should
use IAM roles with short-lived credentials.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

try:
    from checks.models import Finding, print_findings
except ImportError:
    from models import Finding, print_findings

CHECK_ID = "UC-021"

MACHINE_NAME_PATTERN = re.compile(
    r"agent|bot|svc|service|automation|n8n|zapier|make|airflow|langchain|"
    r"openai|anthropic|llm|genai|ci|deploy|pipeline|integration|api-user|apiuser",
    re.IGNORECASE,
)


def run_check(profile: str | None = None, region: str | None = None) -> list[Finding]:
    session_kwargs: dict[str, Any] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    iam = session.client("iam")

    findings: list[Finding] = []
    flagged = 0

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            username = user["UserName"]
            if not MACHINE_NAME_PATTERN.search(username):
                continue
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            active = [k for k in keys if k.get("Status") == "Active"]
            if not active:
                continue
            flagged += 1
            key_ids = ", ".join(k["AccessKeyId"] for k in active)
            findings.append(
                Finding(
                    check_id=CHECK_ID,
                    check_name="Machine identity on long-lived keys",
                    resource=f"user/{username}",
                    region="global",
                    severity="medium",
                    status="fail",
                    detection=(
                        f"IAM user looks like a machine/agent identity and has "
                        f"{len(active)} active long-lived access key(s): {key_ids}"
                    ),
                    plain_english_risk=(
                        "This automation runs on permanent credentials. They sit in "
                        "a config file or environment variable somewhere, never "
                        "expire, and keep working even after they leak. If the tool "
                        "or laptop holding them is compromised, the attacker has "
                        "standing access until someone notices."
                    ),
                    fix_terraform=(
                        "# Prefer a role the workload assumes (short-lived creds):\n"
                        'resource "aws_iam_role" "workload" {\n'
                        f'  name               = "{username}-role"\n'
                        "  assume_role_policy = data.aws_iam_policy_document.trust.json\n"
                        "}\n"
                        "# EC2/ECS/Lambda get roles natively; external tools can use\n"
                        "# IAM Roles Anywhere or OIDC federation instead of static keys"
                    ),
                    fix_cli=(
                        f"# After migrating the workload to a role:\n"
                        f"aws iam update-access-key --user-name {username} "
                        f"--access-key-id <key-id> --status Inactive"
                    ),
                    cis_refs=[],
                    soc2_refs=["CC6.1"],
                )
            )

    if flagged == 0:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name="Machine identity on long-lived keys",
                resource="all machine-pattern IAM users",
                region="global",
                severity="medium",
                status="pass",
                detection="No machine/agent-pattern IAM users with active access keys",
                plain_english_risk="",
                fix_terraform="",
                fix_cli="",
                cis_refs=[],
                soc2_refs=["CC6.1"],
            )
        )
    return findings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Flag machine identities on static keys.")
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
        print("Checked machine identities for long-lived keys\n")
        print_findings(findings)
        print(f"Summary: {len(failed)} machine identit(ies) on static keys")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
