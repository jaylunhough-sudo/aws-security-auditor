#!/usr/bin/env python3
"""Cross-account role assumption for concierge / customer scans.

Umber Cloud's operator credentials (your default AWS profile) call sts:AssumeRole
into the customer's read-only UmberCloudAudit role, protected by an external ID.
Temporary credentials are injected into the process environment so existing checks
keep working unchanged.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator

import boto3
from botocore.exceptions import ClientError

_CRED_KEYS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
)


def assume_role(
    role_arn: str,
    external_id: str,
    operator_profile: str | None = None,
    session_name: str = "umber-cloud-scan",
) -> dict[str, Any]:
    """Return STS AssumeRole response after verifying the role is reachable."""
    session = boto3.Session(profile_name=operator_profile) if operator_profile else boto3.Session()
    sts = session.client("sts")
    return sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        ExternalId=external_id,
    )


def verify_role(
    role_arn: str,
    external_id: str,
    operator_profile: str | None = None,
) -> dict[str, str]:
    """Assume the customer role and return caller identity (Account, Arn, UserId)."""
    with temporary_credentials(role_arn, external_id, operator_profile):
        sts = boto3.client("sts")
        return sts.get_caller_identity()


@contextmanager
def temporary_credentials(
    role_arn: str,
    external_id: str,
    operator_profile: str | None = None,
    session_name: str = "umber-cloud-scan",
) -> Iterator[dict[str, Any]]:
    """Inject assumed-role credentials into os.environ for the duration of the block."""
    response = assume_role(role_arn, external_id, operator_profile, session_name)
    creds = response["Credentials"]
    saved = {key: os.environ.get(key) for key in _CRED_KEYS}
    try:
        os.environ["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
        os.environ["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
        os.environ["AWS_SESSION_TOKEN"] = creds["SessionToken"]
        os.environ["AWS_SECURITY_TOKEN"] = creds["SessionToken"]
        yield response
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def customer_account_id(role_arn: str) -> str:
    """Extract account ID from arn:aws:iam::123456789012:role/Name."""
    parts = role_arn.split(":")
    if len(parts) >= 5 and parts[2] == "iam":
        return parts[4]
    raise ValueError(f"Not a valid IAM role ARN: {role_arn}")
