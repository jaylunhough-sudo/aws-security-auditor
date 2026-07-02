#!/usr/bin/env python3
"""Run every implemented check and write a timestamped scan file.

Scan files in scans/ are the raw material for SOC 2 evidence: a dated,
machine-readable record that controls were checked and what the result was.
Run this on a schedule and you have Type 2 evidence accumulating.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

try:
    from checks import cloudtrail, iam_admin, root_mfa, s3_public, sg_open, stale_keys
    from checks.models import Finding, summarize
except ImportError:  # running as a script from the checks/ directory
    import cloudtrail  # type: ignore[no-redef]
    import iam_admin  # type: ignore[no-redef]
    import root_mfa  # type: ignore[no-redef]
    import s3_public  # type: ignore[no-redef]
    import sg_open  # type: ignore[no-redef]
    import stale_keys  # type: ignore[no-redef]
    from models import Finding, summarize  # type: ignore[no-redef]

CHECK_MODULES = [
    ("UC-001", "S3 public access", s3_public),
    ("UC-002", "Security group open to internet", sg_open),
    ("UC-003", "Root account MFA + access keys", root_mfa),
    ("UC-004", "IAM policy allows full admin", iam_admin),
    ("UC-005", "CloudTrail multi-region logging", cloudtrail),
    ("UC-006", "Stale access keys", stale_keys),
]

SCANS_DIR = Path(__file__).resolve().parent.parent / "scans"


def run_all(profile: str | None = None, region: str | None = None) -> tuple[list[Finding], list[str]]:
    """Run every check. Returns (findings, errors). A check error never aborts the scan."""
    findings: list[Finding] = []
    errors: list[str] = []
    for check_id, name, module in CHECK_MODULES:
        try:
            findings.extend(module.run_check(profile=profile, region=region))
        except ClientError as error:
            errors.append(f"{check_id} {name}: AWS API error: {error}")
    return findings, errors


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
    parser.add_argument("--no-save", action="store_true", help="Do not write a scan file")
    args = parser.parse_args()

    try:
        findings, errors = run_all(profile=args.profile, region=args.region)
    except (NoCredentialsError, ProfileNotFound) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        print(
            "Configure credentials first, e.g. `aws configure` or export AWS_ACCESS_KEY_ID.",
            file=sys.stderr,
        )
        return 2

    stats = summarize(findings)
    failed = [f for f in findings if f.status == "fail"]

    print(f"Umber Cloud scan — {len(CHECK_MODULES)} check(s), "
          f"{stats['total']} finding(s), {stats['fail']} failing\n")

    for check_id, name, _ in CHECK_MODULES:
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

    print(f"\nSummary: {stats['fail']} failing / {stats['total']} total findings")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
