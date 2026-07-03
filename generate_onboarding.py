#!/usr/bin/env python3
"""Generate a customer external ID and pre-filled IAM trust policy for onboarding.

Usage:
  python generate_onboarding.py --umber-account-id 202077713382
  python generate_onboarding.py --umber-account-id 202077713382 --customer acme --company "Acme Inc"
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
CUSTOMERS_DIR = REPO_ROOT / "customers"


def trust_policy(umber_account_id: str, external_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{umber_account_id}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate customer onboarding artifacts.")
    parser.add_argument(
        "--umber-account-id",
        required=True,
        help="Your AWS account ID (the operator account that will assume the customer role)",
    )
    parser.add_argument("--customer", default="customer", help="Short customer slug for filenames")
    parser.add_argument("--company", default="", help="Company name for the customer record")
    parser.add_argument("--email", default="", help="Contact email")
    args = parser.parse_args()

    external_id = secrets.token_urlsafe(24)
    policy = trust_policy(args.umber_account_id, external_id)

    CUSTOMERS_DIR.mkdir(exist_ok=True)
    policy_path = CUSTOMERS_DIR / f"{args.customer}.trust-policy.json"
    policy_path.write_text(json.dumps(policy, indent=2) + "\n")

    customer_record = {
        "customer_id": args.customer,
        "company": args.company or args.customer,
        "contact_email": args.email,
        "role_arn": "arn:aws:iam::CUSTOMER_ACCOUNT_ID:role/UmberCloudAudit",
        "external_id": external_id,
        "operator_profile": None,
        "region": "us-east-1",
        "all_regions": True,
    }
    customer_path = CUSTOMERS_DIR / f"{args.customer}.customer.json"
    customer_path.write_text(json.dumps(customer_record, indent=2) + "\n")

    print(f"External ID (give this to the customer, store it securely):\n  {external_id}\n")
    print(f"Trust policy written: {policy_path}")
    print("Customer sends this to their AWS console when creating role UmberCloudAudit.")
    print(f"\nCustomer record template: {customer_path}")
    print("After the customer creates the role, replace CUSTOMER_ACCOUNT_ID in role_arn,")
    print("then verify: python scan_customer.py --verify", customer_path)
    print("Then scan:  python scan_customer.py", customer_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
