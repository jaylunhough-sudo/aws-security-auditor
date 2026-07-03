#!/usr/bin/env python3
"""Export scan JSON as auditor-ready SOC 2 evidence (CSV + Markdown + PDF).

The PDF is what customers and auditors treat as "official". CSV/Markdown are
for spreadsheets and version control.
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


def build_rows(scan: dict, soc2_map: dict) -> list[dict]:
    scanned_at = scan.get("scanned_at_utc", "unknown")
    rows = []
    for finding in scan.get("findings", []):
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
    return rows


def export_markdown(scan_path: Path, scan: dict, rows: list[dict], md_path: Path) -> None:
    scanned_at = scan.get("scanned_at_utc", "unknown")
    by_control: dict[str, list[dict]] = {}
    for row in rows:
        for control in (row["soc2_controls"] or "unmapped").split(", "):
            by_control.setdefault(control, []).append(row)

    lines = [
        "# SOC 2 Evidence — Cloud Configuration Controls",
        "",
        f"Scan timestamp (UTC): {scanned_at}",
        f"Source scan: `scans/{scan_path.name}`",
    ]
    if scan.get("customer_id"):
        lines.append(f"Customer: {scan.get('company') or scan['customer_id']}")
    if scan.get("score") is not None:
        lines.append(f"Posture score: {scan['score']}/100")
    lines += [
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


def _pdf_text(text: str) -> str:
    """Core PDF fonts only cover latin-1; swap common unicode punctuation."""
    replacements = {"—": "-", "–": "-", "·": " / ", "’": "'", "‘": "'", "“": '"', "”": '"', "→": "->"}
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    return text.encode("latin-1", "replace").decode("latin-1")


def export_pdf(scan_path: Path, scan: dict, rows: list[dict], pdf_path: Path) -> None:
    from fpdf import FPDF

    scanned_at = scan.get("scanned_at_utc", "unknown")[:19]
    score = scan.get("score")
    customer = scan.get("company") or scan.get("customer_id")
    exceptions = [r for r in rows if r["result"] == "EXCEPTION"]

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "Umber Cloud - SOC 2 Evidence Report", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Scan (UTC): {scanned_at}", ln=True)
    if customer:
        pdf.cell(0, 7, _pdf_text(f"Account: {customer}"), ln=True)
    if score is not None:
        pdf.cell(0, 7, f"Audit-readiness score: {score}/100", ln=True)
    pdf.cell(0, 7, f"Source: {scan_path.name}", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Summary", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(
        0,
        6,
        f"{len(rows)} control observations / "
        f"{len(rows) - len(exceptions)} EFFECTIVE / "
        f"{len(exceptions)} EXCEPTION(s). "
        "EFFECTIVE = control operating as intended. "
        "EXCEPTION = failure requiring remediation.",
    )
    pdf.ln(4)

    by_control: dict[str, list[dict]] = {}
    for row in rows:
        for control in (row["soc2_controls"] or "unmapped").split(", "):
            by_control.setdefault(control, []).append(row)

    for control in sorted(by_control):
        control_rows = by_control[control]
        statement = next((r["control_statement"] for r in control_rows if r["control_statement"]), "")

        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, f"SOC 2 {control}", ln=True)
        if statement:
            pdf.set_font("Helvetica", "I", 10)
            pdf.multi_cell(0, 5, _pdf_text(statement[:500]))
        pdf.ln(2)

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(240, 240, 240)
        col_w = (22, 38, 18, 22, 90)
        headers = ("Check", "Resource", "Region", "Result", "Observation")
        for i, header in enumerate(headers):
            pdf.cell(col_w[i], 7, header, border=1, fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 8)
        for row in control_rows:
            cells = (
                _pdf_text(f"{row['check_id']}"),
                _pdf_text(row["resource"][:40]),
                _pdf_text(row["region"][:12]),
                row["result"],
                _pdf_text(row["observation"][:120]),
            )
            if pdf.get_y() > 260:
                pdf.add_page()
                pdf.set_font("Helvetica", "B", 9)
                for i, header in enumerate(headers):
                    pdf.cell(col_w[i], 7, header, border=1, fill=True)
                pdf.ln()
                pdf.set_font("Helvetica", "", 8)
            for i, text in enumerate(cells):
                pdf.cell(col_w[i], 6, text, border=1)
            pdf.ln()
        pdf.ln(3)

    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(
        0,
        4,
        "Generated by Umber Cloud. Maps AWS configuration checks to SOC 2 Trust "
        "Services Criteria for auditor sampling. Verify control language against "
        "the current AICPA TSC before customer-facing use.",
    )
    pdf.output(str(pdf_path))


def export(scan_path: Path) -> tuple[Path, Path, Path]:
    scan = json.loads(scan_path.read_text())
    soc2_map = load_soc2_map()
    rows = build_rows(scan, soc2_map)

    EVIDENCE_DIR.mkdir(exist_ok=True)
    stem = scan_path.stem
    csv_path = EVIDENCE_DIR / f"evidence-{stem}.csv"
    md_path = EVIDENCE_DIR / f"evidence-{stem}.md"
    pdf_path = EVIDENCE_DIR / f"evidence-{stem}.pdf"

    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else [])
        writer.writeheader()
        writer.writerows(rows)

    export_markdown(scan_path, scan, rows, md_path)
    export_pdf(scan_path, scan, rows, pdf_path)

    return csv_path, md_path, pdf_path


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Export scan evidence (CSV + Markdown + PDF).")
    parser.add_argument("--scan", help="Path to a specific scans/*.json file")
    args = parser.parse_args()

    if args.scan:
        scan_path = Path(args.scan)
        if not scan_path.exists():
            print(f"ERROR: scan not found: {scan_path}", file=sys.stderr)
            return 2
    else:
        scan_path = latest_scan()
        if scan_path is None:
            print(
                "No scans found. Run `python checks/run_all.py` first.",
                file=sys.stderr,
            )
            return 2

    csv_path, md_path, pdf_path = export(scan_path)
    print(f"Evidence exported from {scan_path.name}:")
    print(f"  CSV:      {csv_path}")
    print(f"  Markdown: {md_path}")
    print(f"  PDF:      {pdf_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
