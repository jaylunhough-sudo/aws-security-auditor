# Umber Cloud

**SOC 2 evidence and remediation for AWS startups.** Agentless scanning is the sensor — auditor-ready evidence and plain-English fixes are the product.

Working repo for the Umber Cloud engine (umbercloud.com). Currently: 6 of 10 checks live with the three-output standard, scan runner, SOC 2 mapping, and evidence export. Next: checks 7–10, landing page, dashboard.

## What this becomes

| Layer | What it does | Status |
|-------|--------------|--------|
| Check engine | Agentless AWS scans via read-only IAM (10 checks, CIS-aligned) | 6 of 10 done |
| Findings translation | Plain-English risk statements + Terraform/CLI fix snippets | Done — built into every check (`checks/models.py`) |
| Compliance mapping | Each finding mapped to SOC 2 controls (CC6.1, CC6.6, ...) with exportable evidence | Done v0 — `compliance/soc2_map.json` + `export_evidence.py` |
| Dashboard | Connect account in 15 minutes, see what an auditor will ask about | Planned |

Positioning: startups facing a SOC 2 deadline don't need 300 raw findings (Prowler OSS does that for free). They need to know what's exposed, what the auditor needs, and the exact fix — in language a founder can act on.

## The three-output standard

Every finding ships with three outputs (`checks/models.py`), because raw detections are free everywhere:

1. **Detection** — the technical observation (e.g. `Inbound ports 22 open to 0.0.0.0/0`)
2. **Plain-English risk** — what a founder needs to hear ("Anyone on the internet can attempt to connect to SSH...")
3. **Fix** — the exact AWS CLI command and/or Terraform snippet

Passing findings are recorded too — a dated record of a control passing is SOC 2 evidence, not noise.

## Live checks (6 of 10)

| ID | Check | SOC 2 |
|----|-------|-------|
| UC-001 | S3 public access | CC6.1, CC6.6 |
| UC-002 | Security groups open to internet (SSH/RDP/DB) | CC6.6 |
| UC-003 | Root MFA disabled / root access keys | CC6.1 |
| UC-004 | IAM policy grants `*:*` full admin | CC6.1, CC6.3 |
| UC-005 | CloudTrail off or not multi-region | CC7.2 |
| UC-006 | Access keys older than 90 days | CC6.1 |

Full backlog and conventions: `CHECKS.md`.

## Requirements

- Python 3.9+ (3.10+ recommended)
- AWS credentials with read-only access (recommended: `SecurityAudit` managed policy — see `docs/aws-onboarding.md`)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
aws configure
```

## Run

```bash
# Everything: scan, save timestamped JSON to scans/, print summary
python checks/run_all.py --profile my-profile

# Turn the latest scan into auditor-ready evidence (CSV + Markdown in evidence/)
python export_evidence.py

# Single check, machine-readable
python checks/sg_open.py --profile my-profile --json
```

Exit code `0` = clean. `1` = at least one failing finding. `2` = credentials problem.

## Tests (no AWS account needed)

```bash
pip install -r requirements-dev.txt
pytest
```

Nine moto-mocked tests cover fail and pass paths for every check.

## Roadmap

See `CHECKS.md` for the check backlog with compliance mappings, and the build phases below.

1. **Phase 1** — 10 checks + plain-English findings (beat free tools on clarity, not count)
2. **Phase 2** — SOC 2 control mapping + evidence export (the reason startups pay)
3. **Phase 3** — Dashboard + 15-minute cross-account IAM role onboarding
4. **Phase 4** — Remediation snippets (Terraform / AWS CLI) per finding
5. **Phase 5** — Vanta/Drata integration, AWS Marketplace listing, MSP white-label
