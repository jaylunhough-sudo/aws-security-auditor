#!/usr/bin/env python3
"""Shared session builder for all checks.

Cross-account customer scans do NOT go through here — they use
checks/cross_account.py, which assumes the customer's UmberCloudAudit role
and injects temporary credentials into the environment; the default boto3
credential chain below then picks them up automatically.
"""

from __future__ import annotations

from typing import Any

import boto3


def build_session(
    profile: str | None = None,
    region: str | None = None,
) -> boto3.Session:
    session_kwargs: dict[str, Any] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region
    return boto3.Session(**session_kwargs)
