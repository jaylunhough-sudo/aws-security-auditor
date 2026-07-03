#!/usr/bin/env python3
"""Check #20 (AI pack): AI/agent execution roles with full-admin power.

SOC 2 CC6.3 (least privilege).
AI agents are a new class of cloud identity: provisioned fast, rarely
audited, and often handed god-mode credentials "to make it work". A role
trusted by Bedrock/SageMaker — or named like an agent — with *:* access
means a prompt injection or bad tool call can do anything in the account.
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
    from checks.lambda_iam import _role_admin_reasons
    from checks.aws_session import build_session
except ImportError:
    from models import Finding, print_findings
    from lambda_iam import _role_admin_reasons
    from aws_session import build_session

CHECK_ID = "UC-020"

AI_SERVICES = {"bedrock.amazonaws.com", "sagemaker.amazonaws.com"}
AI_NAME_PATTERN = re.compile(
    r"agent|copilot|langchain|llamaindex|crewai|autogen|autogpt|openai|anthropic|"
    r"chatbot|llm|genai|gen-ai|assistant",
    re.IGNORECASE,
)


def _trusted_services(role: dict[str, Any]) -> set[str]:
    services: set[str] = set()
    document = role.get("AssumeRolePolicyDocument") or {}
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal", {})
        if not isinstance(principal, dict):
            continue
        service = principal.get("Service", [])
        if isinstance(service, str):
            service = [service]
        services.update(service)
    return services


def _is_ai_role(role: dict[str, Any]) -> str | None:
    """Return why this role counts as an AI/agent identity, or None."""
    services = _trusted_services(role)
    ai_hits = services & AI_SERVICES
    if ai_hits:
        return f"trusted by {', '.join(sorted(ai_hits))}"
    if AI_NAME_PATTERN.search(role.get("RoleName", "")):
        return "role name indicates an AI/agent workload"
    return None


def run_check(
    profile: str | None = None,
    region: str | None = None,
    session: boto3.Session | None = None,
) -> list[Finding]:
    if session is None:
        session = build_session(profile=profile, region=region)
    iam = session.client("iam")

    findings: list[Finding] = []
    ai_roles = 0
    flagged = 0

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            why_ai = _is_ai_role(role)
            if not why_ai:
                continue
            ai_roles += 1
            role_name = role["RoleName"]
            try:
                reasons = _role_admin_reasons(iam, role_name)
            except ClientError:
                continue
            if not reasons:
                continue
            flagged += 1
            findings.append(
                Finding(
                    check_id=CHECK_ID,
                    check_name="AI/agent role with full admin",
                    resource=f"role/{role_name}",
                    region="global",
                    severity="critical",
                    status="fail",
                    detection=f"AI identity ({why_ai}); {'; '.join(reasons)}",
                    plain_english_risk=(
                        "This AI workload can do anything in your AWS account. One "
                        "prompt injection, poisoned tool response, or model mistake "
                        "and the agent can read data, delete backups, or create "
                        "credentials — at machine speed, with no human in the loop."
                    ),
                    fix_terraform=(
                        "# Scope the agent's role to only the actions it needs:\n"
                        'resource "aws_iam_role_policy" "agent_scoped" {\n'
                        f'  role = "{role_name}"\n'
                        "  policy = jsonencode({\n"
                        "    Version = \"2012-10-17\"\n"
                        "    Statement = [{\n"
                        "      Effect   = \"Allow\"\n"
                        "      Action   = [\"bedrock:InvokeModel\"]\n"
                        "      Resource = \"arn:aws:bedrock:*::foundation-model/*\"\n"
                        "    }]\n"
                        "  })\n"
                        "}"
                    ),
                    fix_cli=(
                        f"aws iam list-attached-role-policies --role-name {role_name}  "
                        f"# then detach the admin policy and attach a scoped one"
                    ),
                    cis_refs=[],
                    soc2_refs=["CC6.3"],
                )
            )

    if flagged == 0:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name="AI/agent role with full admin",
                resource=f"all AI/agent roles ({ai_roles} identified)",
                region="global",
                severity="critical",
                status="pass",
                detection=(
                    "No AI/agent role grants full admin"
                    if ai_roles
                    else "No AI/agent roles identified in this account"
                ),
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

    parser = argparse.ArgumentParser(description="Flag over-privileged AI/agent roles.")
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
        print("Checked AI/agent execution roles\n")
        print_findings(findings)
        print(f"Summary: {len(failed)} over-privileged AI role(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
