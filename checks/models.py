#!/usr/bin/env python3
"""Shared finding model — every check emits these.

Three-output standard: detection + plain-English risk + exact fix.
Findings with status "pass" matter too: auditors need evidence a control
operates effectively, not just alerts when it fails. That is the SOC 2 wedge.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    check_id: str  # stable ID, e.g. "UC-001"
    check_name: str  # short human name, e.g. "S3 public access"
    resource: str  # bucket name, security group id, "root account", ...
    region: str
    severity: str  # one of SEVERITIES — the severity IF failing
    status: str  # "fail" or "pass"
    detection: str  # technical statement of what was observed
    plain_english_risk: str  # founder-readable consequence ("" when passing)
    fix_terraform: str  # Terraform snippet ("" when passing)
    fix_cli: str  # AWS CLI command or console steps ("" when passing)
    cis_refs: list[str] = field(default_factory=list)
    soc2_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def summarize(findings: list[Finding]) -> dict[str, int]:
    return {
        "total": len(findings),
        "fail": sum(1 for f in findings if f.status == "fail"),
        "pass": sum(1 for f in findings if f.status == "pass"),
    }


def print_findings(findings: list[Finding]) -> None:
    """Human-readable rendering shared by all check CLIs."""
    for finding in findings:
        marker = "FAIL" if finding.status == "fail" else "OK"
        print(f"[{marker}] {finding.check_id} {finding.check_name} — "
              f"{finding.resource} ({finding.region})")
        print(f"  Detected: {finding.detection}")
        if finding.status == "fail":
            print(f"  Risk:     {finding.plain_english_risk}")
            if finding.fix_cli:
                print(f"  Fix (CLI): {finding.fix_cli}")
            if finding.fix_terraform:
                first_line = finding.fix_terraform.strip().splitlines()[0]
                print(f"  Fix (Terraform): {first_line} ... (see JSON output)")
        print()
