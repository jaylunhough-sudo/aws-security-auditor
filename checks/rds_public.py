#!/usr/bin/env python3
"""Check #8: publicly accessible RDS instances and publicly shared snapshots.

CIS AWS Foundations 2.3.x · SOC 2 CC6.1 / CC6.6.
A public RDS snapshot is the worst finding in AWS: anyone with an AWS
account can restore your entire database, offline, without touching you.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

try:
    from checks.models import Finding, print_findings
except ImportError:
    from models import Finding, print_findings

CHECK_ID = "UC-008"


def run_check(profile: str | None = None, region: str | None = None) -> list[Finding]:
    session_kwargs: dict[str, Any] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    rds = session.client("rds")
    active_region = rds.meta.region_name

    findings: list[Finding] = []
    issues = 0

    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for instance in page.get("DBInstances", []):
            if not instance.get("PubliclyAccessible"):
                continue
            issues += 1
            db_id = instance["DBInstanceIdentifier"]
            findings.append(
                Finding(
                    check_id=CHECK_ID,
                    check_name="RDS instance publicly accessible",
                    resource=f"db/{db_id}",
                    region=active_region,
                    severity="critical",
                    status="fail",
                    detection="DB instance has PubliclyAccessible=true (internet-resolvable endpoint)",
                    plain_english_risk=(
                        "Your live database has an address reachable from the public "
                        "internet. Anyone can find it and hammer it with password "
                        "attempts — only a credential stands between them and your data."
                    ),
                    fix_terraform=(
                        'resource "aws_db_instance" "this" {\n'
                        "  # ... existing config ...\n"
                        "  publicly_accessible = false\n"
                        "}"
                    ),
                    fix_cli=(
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        f"--no-publicly-accessible --apply-immediately"
                    ),
                    cis_refs=["2.3.3"],
                    soc2_refs=["CC6.1", "CC6.6"],
                )
            )

    snap_paginator = rds.get_paginator("describe_db_snapshots")
    for page in snap_paginator.paginate(SnapshotType="manual"):
        for snapshot in page.get("DBSnapshots", []):
            snap_id = snapshot["DBSnapshotIdentifier"]
            attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snap_id)
            for attr in attrs["DBSnapshotAttributesResult"].get("DBSnapshotAttributes", []):
                if attr.get("AttributeName") == "restore" and "all" in attr.get(
                    "AttributeValues", []
                ):
                    issues += 1
                    findings.append(
                        Finding(
                            check_id=CHECK_ID,
                            check_name="RDS snapshot shared publicly",
                            resource=f"snapshot/{snap_id}",
                            region=active_region,
                            severity="critical",
                            status="fail",
                            detection="Manual DB snapshot is shared with ALL AWS accounts",
                            plain_english_risk=(
                                "Any AWS account on earth can restore this snapshot and "
                                "read your entire database — every table, every row — "
                                "without ever touching your infrastructure. This is a "
                                "complete, silent data breach."
                            ),
                            fix_terraform="",  # sharing attributes are operational
                            fix_cli=(
                                f"aws rds modify-db-snapshot-attribute "
                                f"--db-snapshot-identifier {snap_id} "
                                f"--attribute-name restore --values-to-remove all"
                            ),
                            cis_refs=["2.3.1"],
                            soc2_refs=["CC6.1", "CC6.6"],
                        )
                    )

    if issues == 0:
        findings.append(
            Finding(
                check_id=CHECK_ID,
                check_name="RDS public exposure",
                resource="all RDS instances and snapshots",
                region=active_region,
                severity="critical",
                status="pass",
                detection="No publicly accessible DB instances or publicly shared snapshots",
                plain_english_risk="",
                fix_terraform="",
                fix_cli="",
                cis_refs=["2.3.1", "2.3.3"],
                soc2_refs=["CC6.1", "CC6.6"],
            )
        )
    return findings


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Flag public RDS instances and snapshots.")
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
        print("Checked RDS public exposure\n")
        print_findings(findings)
        print(f"Summary: {len(failed)} public exposure issue(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
