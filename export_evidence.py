#!/usr/bin/env python3
"""Export the latest scan as auditor-ready SOC 2 evidence (CSV + Markdown).

This is the wedge: a dated evidence table mapping AWS findings to SOC 2
controls, in a format an auditor can sample directly. Free scanners print
findings; Umber Cloud produces evidence.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
SCANS_DIR = REPO_ROOT / "scans"
EVIDENCE_DIR = REPO_ROOT / "evidence"
SOC2_MAP_PATH = REPO_ROOT / "compliance" / "soc2_map.json"


def latest_scan() -> Path | None:
    if not SCANS_DIR.exists():
        return None
    scans = sorted(SCANS_DIR.glob("*.json"))
    return scans[-1] if scans else None


def load_soc2_map() -> dict:
    return json.loads(SOC2_MAP_PATH.read_text())


def export(scan_path: Path) -> tuple[Path, Path]:
    scan = json.loads(scan_path.read_text())
    soc2_map = load_soc2_map()
    scanned_at = scan.get("scanned_at_utc", "unknown")
    findings = scan.get("findings", [])

    EVIDENCE_DIR.mkdir(exist_ok=True)
    stem = scan_path.stem
    csv_path = EVIDENCE_DIR / f"evidence-{stem}.csv"
    md_path = EVIDENCE_DIR / f"evidence-{stem}.md"

    rows = []
    for finding in findings:
        mapping = soc2_map.get(finding["check_id"], {})
        rows.append(
            {
                "soc2_controls": ", ".join(finding.get("soc2_refs", [])),
                "control_statement": mapping.get("control_statement", ""),
                "check_id": finding["check_id"],
                "check_name": finding["check_name"],
                "resource": finding["resource"],
                "region": finding["region"],
                "result": "EFFECTIVE" if finding["status"] == "pass" else "EXCEPTION",
                "observation": finding["detection"],
                "scanned_at_utc": scanned_at,
            }
        )

    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else [])
        writer.writeheader()
        writer.writerows(rows)

    # Markdown grouped by SOC 2 control for human review.
    by_control: dict[str, list[dict]] = {}
    for row in rows:
        for control in (row["soc2_controls"] or "unmapped").split(", "):
            by_control.setdefault(control, []).append(row)

    lines = [
        "# SOC 2 Evidence — Cloud Configuration Controls",
        "",
        f"Scan timestamp (UTC): {scanned_at}",
        f"Source scan: `scans/{scan_path.name}`",
        "",
        "Result legend: **EFFECTIVE** = control operating as intended · "
        "**EXCEPTION** = control failure requiring remediation.",
        "",
    ]
    for control in sorted(by_control):
        control_rows = by_control[control]
        statement = next((r["control_statement"] for r in control_rows if r["control_statement"]), "")
        lines.append(f"## {control}")
        if statement:
            lines.append(f"*{statement}*")
        lines.append("")
        lines.append("| Check | Resource | Region | Result | Observation |")
        lines.append("|-------|----------|--------|--------|-------------|")
        for row in control_rows:
            lines.append(
                f"| {row['check_id']} {row['check_name']} | {row['resource']} "
                f"| {row['region']} | {row['result']} | {row['observation']} |"
            )
        lines.append("")

    exceptions = [r for r in rows if r["result"] == "EXCEPTION"]
    lines.append("## Summary")
    lines.append("")
    lines.append(
        f"{len(rows)} control observations · {len(rows) - len(exceptions)} effective · "
        f"{len(exceptions)} exception(s)."
    )
    md_path.write_text("\n".join(lines) + "\n")

    return csv_path, md_path


def main() -> int:
    scan_path = latest_scan()
    if scan_path is None:
        print(
            "No scans found. Run `python checks/run_all.py` first to produce scans/*.json.",
            file=sys.stderr,
        )
        return 2

    csv_path, md_path = export(scan_path)
    print(f"Evidence exported from {scan_path.name}:")
    print(f"  CSV:      {csv_path}")
    print(f"  Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
