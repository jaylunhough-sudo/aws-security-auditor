#!/usr/bin/env python3
"""Check #1: S3 buckets with public access misconfigurations.

CIS AWS Foundations 2.1.x · SOC 2 CC6.1 / CC6.6.
Emits the three-output standard: detection + plain-English risk + fix.
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
except ImportError:  # running as a script from the checks/ directory
    from models import Finding, print_findings
    from aws_session import build_session

CHECK_ID = "UC-001"


def _bucket_region(s3_client: Any, bucket_name: str) -> str:
    try:
        location = s3_client.get_bucket_location(Bucket=bucket_name)
        region = location.get("LocationConstraint")
        return region or "us-east-1"
    except ClientError:
        return "unknown"


def _check_public_access_block(s3_client: Any, bucket_name: str) -> list[str]:
    issues: list[str] = []
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
        required = {
            "BlockPublicAcls": "BlockPublicAcls is disabled",
            "IgnorePublicAcls": "IgnorePublicAcls is disabled",
            "BlockPublicPolicy": "BlockPublicPolicy is disabled",
            "RestrictPublicBuckets": "RestrictPublicBuckets is disabled",
        }
        for key, message in required.items():
            if not config.get(key, False):
                issues.append(message)
    except ClientError as error:
        code = error.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            issues.append("No bucket-level public access block configured")
        else:
            raise
    return issues


def _check_bucket_acl(s3_client: Any, bucket_name: str) -> list[str]:
    issues: list[str] = []
    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        permission = grant.get("Permission", "unknown")
        if "AllUsers" in uri:
            issues.append(f"ACL grants {permission} to AllUsers (public internet)")
        elif "AuthenticatedUsers" in uri:
            issues.append(f"ACL grants {permission} to AuthenticatedUsers (any AWS account)")
    return issues


def _check_bucket_policy(s3_client: Any, bucket_name: str) -> list[str]:
    issues: list[str] = []
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_text = response["Policy"]
    except ClientError as error:
        if error.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return issues
        raise

    try:
        policy = json.loads(policy_text)
    except json.JSONDecodeError:
        issues.append("Bucket policy exists but could not be parsed as JSON")
        return issues

    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if principal == "*" or principal == {"AWS": "*"}:
            issues.append("Bucket policy allows Principal: * (public access)")
        elif isinstance(principal, dict):
            aws_principals = principal.get("AWS")
            if aws_principals == "*" or aws_principals == ["*"]:
                issues.append("Bucket policy allows Principal.AWS: * (public access)")
    return issues


def _fix_terraform(bucket_name: str) -> str:
    return (
        f'resource "aws_s3_bucket_public_access_block" "locked" {{\n'
        f'  bucket                  = "{bucket_name}"\n'
        f"  block_public_acls       = true\n"
        f"  block_public_policy     = true\n"
        f"  ignore_public_acls      = true\n"
        f"  restrict_public_buckets = true\n"
        f"}}"
    )


def _fix_cli(bucket_name: str) -> str:
    return (
        f"aws s3api put-public-access-block --bucket {bucket_name} "
        f"--public-access-block-configuration "
        f"BlockPublicAcls=true,IgnorePublicAcls=true,"
        f"BlockPublicPolicy=true,RestrictPublicBuckets=true"
    )


def check_bucket(session: boto3.Session, s3_client: Any, bucket_name: str) -> Finding:
    region = _bucket_region(s3_client, bucket_name)
    regional_client = (
        session.client("s3", region_name=region)
        if region not in ("unknown", "us-east-1")
        else s3_client
    )

    issues: list[str] = []
    issues.extend(_check_public_access_block(regional_client, bucket_name))
    issues.extend(_check_bucket_acl(regional_client, bucket_name))
    issues.extend(_check_bucket_policy(regional_client, bucket_name))

    failed = len(issues) > 0
    return Finding(
        check_id=CHECK_ID,
        check_name="S3 public access",
        resource=f"s3://{bucket_name}",
        region=region,
        severity="critical",
        status="fail" if failed else "pass",
        detection="; ".join(issues) if failed else "No public access indicators found",
        plain_english_risk=(
            "Anyone on the internet may be able to list or download the files in this "
            "bucket — customer data, backups, logs. Public buckets are found by scanners "
            "within hours and are the most common cause of startup data leaks."
            if failed
            else ""
        ),
        fix_terraform=_fix_terraform(bucket_name) if failed else "",
        fix_cli=_fix_cli(bucket_name) if failed else "",
        cis_refs=["2.1.1", "2.1.4"],
        soc2_refs=["CC6.1", "CC6.6"],
    )


def run_check(
    profile: str | None = None,
    region: str | None = None,
    session: boto3.Session | None = None,
) -> list[Finding]:
    if session is None:
        session = build_session(profile=profile, region=region)
    s3_client = session.client("s3")

    findings: list[Finding] = []
    for bucket in s3_client.list_buckets().get("Buckets", []):
        findings.append(check_bucket(session, s3_client, bucket["Name"]))
    return findings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Flag S3 buckets with public access risk.")
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
        print(f"Scanned {len(findings)} bucket(s)\n")
        if not findings:
            print("No buckets found in this account.")
        print_findings(findings)
        print(f"Summary: {len(failed)} bucket(s) with public access risk")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
