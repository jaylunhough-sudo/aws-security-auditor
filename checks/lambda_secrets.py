#!/usr/bin/env python3
"""Check #22 (AI pack): secrets sitting in Lambda environment variables.

SOC 2 CC6.1.
AI apps are glued together with API keys — OpenAI, Anthropic, database
URLs — and the fastest place to put them is a Lambda env var. Env vars
are visible to anyone with read access to the function config, appear in
consoles and CLI output, and are not what Secrets Manager exists for.

This check inspects variable NAMES and value SHAPES only. It never
prints, stores, or exports the secret values themselves.
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

CHECK_ID = "UC-022"

SECRET_NAME_PATTERN = re.compile(
    r"secret|token|password|passwd|api[_-]?key|apikey|private[_-]?key|"
    r"credential|auth|access[_-]?key",
    re.IGNORECASE,
)

# Known key formats: OpenAI, Anthropic, AWS, GitHub, Slack, Stripe
SECRET_VALUE_PATTERN = re.compile(
    r"^(sk-|sk-ant-|AKIA|ghp_|gho_|xox[bap]-|rk_live_|pk_live_|whsec_)"
)


def _suspicious_vars(variables: dict[str, str]) -> list[str]:
    hits: list[str] = []
    for name, value in variables.items():
        if SECRET_NAME_PATTERN.search(name):
            hits.append(f"{name} (name suggests a secret)")
        elif isinstance(value, str) and SECRET_VALUE_PATTERN.match(value):
            hits.append(f"{name} (value matches a known API-key format)")
    return hits


def run_check(profile: str | None = None, region: str | None = None) -> list[Finding]:
    session_kwargs: dict[str, Any] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    lambda_client = session.client("lambda")
    active_region = lambda_client.meta.region_name

    findings: list[Finding] = []
    flagged = 0
    total = 0

    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for function in page.get("Functions", []):
            total += 1
            function_name = function["FunctionName"]
            variables = (function.get("Environment") or {}).get("Variables") or {}
            hits = _suspicious_vars(variables)
            if not hits:
                continue
            flagged += 1
            uses_default_kms = not function.get("KMSKeyArn")
            detection = f"Env vars likely holding secrets: {'; '.join(hits)}"
            if uses_default_kms:
                detection += " — encrypted only with the AWS default key"
            findings.append(
                Finding(
                    check_id=CHECK_ID,
                    check_name="Secrets in Lambda environment variables",
                    resource=f"function/{function_name}",
                    region=active_region,
                    severity="high",
                    status="fail",
                    detection=detection,
                    plain_english_risk=(
                        "API keys living in this function's configuration are "
                        "readable by anyone (or any tool) with view access to the "
                        "function, show up in consoles and exports, and never "
                        "rotate. One over-shared login or leaked Terraform state "
                        "and those keys are gone."
                    ),
                    fix_terraform=(
                        "# Move the secret to Secrets Manager and fetch at runtime:\n"
                        'resource "aws_secretsmanager_secret" "api_key" {\n'
                        f'  name = "{function_name}/api-key"\n'
                        "}\n"
                        "# Grant the function's role secretsmanager:GetSecretValue\n"
                        "# on this ARN only, and read it in code at cold start"
                    ),
                    fix_cli=(
                        f"aws secretsmanager create-secret --name {function_name}/api-key "
                        f"--secret-string '<the-secret>'  # then remove the env var:\n"
                        f"aws lambda update-function-configuration "
                        f"--function-name {function_name} --environment 'Variables={{}}'"
                    ),
                    cis_refs=[],
                    soc2_refs=["CC6.1"],
                )
            )

    if flagged == 0:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name="Secrets in Lambda environment variables",
                resource=f"all Lambda functions ({total} checked)",
                region=active_region,
                severity="high",
                status="pass",
                detection=(
                    "No secret-shaped environment variables found"
                    if total
                    else "No Lambda functions in this region"
                ),
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

    parser = argparse.ArgumentParser(description="Flag secrets in Lambda env vars.")
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
        print("Checked Lambda environment variables for secrets\n")
        print_findings(findings)
        print(f"Summary: {len(failed)} function(s) with secret-shaped env vars")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
