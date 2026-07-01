#!/usr/bin/env python3
"""Check S3 buckets for public access misconfigurations."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


@dataclass
class BucketFinding:
    bucket: str
    region: str
    public: bool
    issues: list[str]


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


def check_bucket(session: boto3.Session, s3_client: Any, bucket_name: str) -> BucketFinding:
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

    return BucketFinding(
        bucket=bucket_name,
        region=region,
        public=len(issues) > 0,
        issues=issues,
    )


def run_check(profile: str | None = None, region: str | None = None) -> list[BucketFinding]:
    session_kwargs: dict[str, Any] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    s3_client = session.client("s3")

    findings: list[BucketFinding] = []
    for bucket in s3_client.list_buckets().get("Buckets", []):
        bucket_name = bucket["Name"]
        findings.append(check_bucket(session, s3_client, bucket_name))
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

    public_buckets = [finding for finding in findings if finding.public]

    if args.json:
        print(json.dumps([asdict(finding) for finding in findings], indent=2))
    else:
        print(f"Scanned {len(findings)} bucket(s)\n")
        if not findings:
            print("No buckets found in this account.")
        for finding in findings:
            status = "PUBLIC RISK" if finding.public else "OK"
            print(f"[{status}] s3://{finding.bucket} ({finding.region})")
            for issue in finding.issues:
                print(f"  - {issue}")
            if not finding.issues:
                print("  - No public access indicators found")
            print()

        print(f"Summary: {len(public_buckets)} bucket(s) with public access risk")

    return 1 if public_buckets else 0


if __name__ == "__main__":
    raise SystemExit(main())
