#!/usr/bin/env python3
"""Concierge scan: assume a customer's cross-account role and deliver evidence.

This is how you charge before the hosted product exists:
  1. python generate_onboarding.py --umber-account-id YOUR_ID --customer acme
  2. Customer creates UmberCloudAudit role with the trust policy + SecurityAudit
  3. python scan_customer.py --verify customers/acme.customer.json
  4. python scan_customer.py customers/acme.customer.json

Outputs: scans/<customer>-<timestamp>.json + evidence CSV/Markdown/PDF
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from checks.cross_account import temporary_credentials, verify_role  # noqa: E402
from checks.models import summarize  # noqa: E402
from checks.run_all import CHECK_MODULES, posture_score, run_all  # noqa: E402
from export_evidence import export  # noqa: E402


def load_customer(path: Path) -> dict:
    data = json.loads(path.read_text())
    for key in ("customer_id", "role_arn", "external_id"):
        if not data.get(key):
            raise ValueError(f"Customer file missing required field: {key}")
    return data


def save_customer_scan(
    findings,
    errors,
    customer: dict,
    scan_path_override: Path | None = None,
) -> Path:
    from checks.models import summarize
    from datetime import datetime, timezone

    scans_dir = REPO_ROOT / "scans"
    scans_dir.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S")
    customer_id = customer["customer_id"]
    path = scan_path_override or scans_dir / f"{customer_id}-{stamp}.json"
    payload = {
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "customer_id": customer_id,
        "company": customer.get("company"),
        "contact_email": customer.get("contact_email"),
        "role_arn": customer["role_arn"],
        "scan_mode": "cross_account",
        "region": customer.get("region"),
        "all_regions": customer.get("all_regions", False),
        "summary": summarize(findings),
        "score": posture_score(findings),
        "errors": errors,
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2))
    return path


def cmd_verify(customer_path: Path) -> int:
    customer = load_customer(customer_path)
    try:
        identity = verify_role(
            customer["role_arn"],
            customer["external_id"],
            customer.get("operator_profile"),
        )
    except (NoCredentialsError, ProfileNotFound) as error:
        print(f"ERROR: operator credentials: {error}", file=sys.stderr)
        return 2
    except ClientError as error:
        print(f"ERROR: could not assume role: {error}", file=sys.stderr)
        print(
            "Check: trust policy Principal matches your operator account, "
            "external ID matches, SecurityAudit attached, role ARN correct.",
            file=sys.stderr,
        )
        return 1

    print(f"OK — assumed into customer account {identity['Account']}")
    print(f"    Arn: {identity['Arn']}")
    return 0


def cmd_scan(customer_path: Path) -> int:
    customer = load_customer(customer_path)
    operator = customer.get("operator_profile")
    all_regions = customer.get("all_regions", True)
    region = customer.get("region")

    print(
        f"Scanning {customer.get('company', customer['customer_id'])} "
        f"via cross-account role...\n"
    )

    try:
        with temporary_credentials(
            customer["role_arn"],
            customer["external_id"],
            operator,
        ):
            findings, errors = run_all(
                profile=None,
                region=region,
                all_regions=all_regions,
            )
    except (NoCredentialsError, ProfileNotFound) as error:
        print(f"ERROR: operator credentials: {error}", file=sys.stderr)
        return 2
    except ClientError as error:
        print(f"ERROR: assume role failed: {error}", file=sys.stderr)
        return 1

    score = posture_score(findings)
    failed = [f for f in findings if f.status == "fail"]
    stats = summarize(findings)

    for check_id, name, _, _ in CHECK_MODULES:
        check_findings = [f for f in findings if f.check_id.startswith(check_id)]
        check_fails = [f for f in check_findings if f.status == "fail"]
        marker = "FAIL" if check_fails else "PASS"
        print(
            f"[{marker}] {check_id} {name}: "
            f"{len(check_fails)} issue(s) across {len(check_findings)} finding(s)"
        )

    scan_path = save_customer_scan(findings, errors, customer)
    csv_path, md_path, pdf_path = export(scan_path)

    print(f"\nScore: {score}/100 — {stats['fail']} failing / {stats['total']} observations")
    print(f"Scan:     {scan_path}")
    print(f"Evidence: {csv_path}")
    print(f"          {md_path}")
    print(f"          {pdf_path}")
    print("\nSend the PDF + top failing findings to the customer. That's the free scan deliverable.")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Concierge customer scan via cross-account role.")
    parser.add_argument("customer_file", nargs="?", help="Path to customers/*.customer.json")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Only verify AssumeRole works (no scan)",
    )
    args = parser.parse_args()

    if not args.customer_file:
        parser.error("customer_file is required")
    path = Path(args.customer_file)
    if not path.exists():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 2

    if args.verify:
        return cmd_verify(path)
    return cmd_scan(path)


if __name__ == "__main__":
    raise SystemExit(main())
