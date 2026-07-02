#!/usr/bin/env python3
"""Run every implemented check and write a timestamped scan file.

Scan files in scans/ are the raw material for SOC 2 evidence: a dated,
machine-readable record that controls were checked and what the result was.
Run this on a schedule and you have Type 2 evidence accumulating.

By default regional checks run in the session's default region only.
Pass --all-regions to fan out across every enabled region (what a real
customer scan should do — settings like EBS default encryption and
resources like security groups exist per region).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

try:
    from checks import (
        agent_keys,
        ai_agent_roles,
        cloudtrail,
        ebs_encryption,
        iam_admin,
        imdsv1,
        lambda_iam,
        lambda_secrets,
        rds_public,
        root_mfa,
        s3_public,
        sg_open,
        stale_keys,
    )
    from checks.models import Finding, summarize
except ImportError:  # running as a script from the checks/ directory
    import agent_keys  # type: ignore[no-redef]
    import ai_agent_roles  # type: ignore[no-redef]
    import cloudtrail  # type: ignore[no-redef]
    import ebs_encryption  # type: ignore[no-redef]
    import iam_admin  # type: ignore[no-redef]
    import imdsv1  # type: ignore[no-redef]
    import lambda_iam  # type: ignore[no-redef]
    import lambda_secrets  # type: ignore[no-redef]
    import rds_public  # type: ignore[no-redef]
    import root_mfa  # type: ignore[no-redef]
    import s3_public  # type: ignore[no-redef]
    import sg_open  # type: ignore[no-redef]
    import stale_keys  # type: ignore[no-redef]
    from models import Finding, summarize  # type: ignore[no-redef]

# (check_id, name, module, scope) — "global" runs once, "regional" fans out
CHECK_MODULES = [
    ("UC-001", "S3 public access", s3_public, "global"),
    ("UC-002", "Security group open to internet", sg_open, "regional"),
    ("UC-003", "Root account MFA + access keys", root_mfa, "global"),
    ("UC-004", "IAM policy allows full admin", iam_admin, "global"),
    ("UC-005", "CloudTrail multi-region logging", cloudtrail, "global"),
    ("UC-006", "Stale access keys", stale_keys, "global"),
    ("UC-007", "EBS encryption", ebs_encryption, "regional"),
    ("UC-008", "RDS public exposure", rds_public, "regional"),
    ("UC-009", "EC2 IMDSv1 allowed", imdsv1, "regional"),
    ("UC-010", "Lambda over-privileged roles", lambda_iam, "regional"),
    ("UC-020", "AI/agent roles with full admin", ai_agent_roles, "global"),
    ("UC-021", "Machine identities on static keys", agent_keys, "global"),
    ("UC-022", "Secrets in Lambda env vars", lambda_secrets, "regional"),
]

SCANS_DIR = Path(__file__).resolve().parent.parent / "scans"


def enabled_regions(profile: str | None) -> list[str]:
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions(AllRegions=False).get("Regions", [])
    return sorted(r["RegionName"] for r in regions)


def run_all(
    profile: str | None = None,
    region: str | None = None,
    all_regions: bool = False,
) -> tuple[list[Finding], list[str]]:
    """Run every check. Returns (findings, errors). A check error never aborts the scan."""
    findings: list[Finding] = []
    errors: list[str] = []

    regions: list[str] = []
    if all_regions:
        try:
            regions = enabled_regions(profile)
        except ClientError as error:
            errors.append(f"Could not enumerate regions ({error}); using default region only")

    for check_id, name, module, scope in CHECK_MODULES:
        targets = regions if (scope == "regional" and regions) else [region]
        for target in targets:
            try:
                findings.extend(module.run_check(profile=profile, region=target))
            except ClientError as error:
                where = f" [{target}]" if target else ""
                errors.append(f"{check_id} {name}{where}: AWS API error: {error}")
    return findings, errors


def posture_score(findings: list[Finding]) -> int:
    """Percent of observations passing — the headline number."""
    stats = summarize(findings)
    if not stats["total"]:
        return 100
    return round(stats["pass"] / stats["total"] * 100)


def write_scan(
    findings: list[Finding], errors: list[str], profile: str | None, region: str | None
) -> Path:
    SCANS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
    path = SCANS_DIR / f"{stamp}.json"
    payload = {
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "region": region,
        "summary": summarize(findings),
        "score": posture_score(findings),
        "errors": errors,
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2))
    return path


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run all Umber Cloud checks.")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", help="Default AWS region for the session")
    parser.add_argument(
        "--all-regions", action="store_true",
        help="Fan regional checks out across every enabled region",
    )
    parser.add_argument("--no-save", action="store_true", help="Do not write a scan file")
    args = parser.parse_args()

    try:
        findings, errors = run_all(
            profile=args.profile, region=args.region, all_regions=args.all_regions
        )
    except (NoCredentialsError, ProfileNotFound) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        print(
            "Configure credentials first, e.g. `aws configure` or export AWS_ACCESS_KEY_ID.",
            file=sys.stderr,
        )
        return 2

    stats = summarize(findings)
    failed = [f for f in findings if f.status == "fail"]
    score = posture_score(findings)

    print(f"Umber Cloud scan — {len(CHECK_MODULES)} check(s), "
          f"{stats['total']} finding(s), {stats['fail']} failing — score {score}/100\n")

    for check_id, name, _, _ in CHECK_MODULES:
        check_findings = [f for f in findings if f.check_id.startswith(check_id)]
        check_fails = [f for f in check_findings if f.status == "fail"]
        marker = "FAIL" if check_fails else "PASS"
        print(f"[{marker}] {check_id} {name}: "
              f"{len(check_fails)} issue(s) across {len(check_findings)} finding(s)")
        for finding in check_fails:
            print(f"       - {finding.resource}: {finding.detection}")
            print(f"         Risk: {finding.plain_english_risk}")
            print(f"         Fix:  {finding.fix_cli or finding.fix_terraform.splitlines()[0]}")
    for error in errors:
        print(f"[ERROR] {error}")

    if not args.no_save:
        path = write_scan(findings, errors, args.profile, args.region)
        print(f"\nScan saved: {path}")

    print(f"\nSummary: {stats['fail']} failing / {stats['total']} total findings "
          f"— score {score}/100")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
