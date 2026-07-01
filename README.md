# Umber Cloud

**SOC 2 evidence and remediation for AWS startups.** Agentless scanning is the sensor — auditor-ready evidence and plain-English fixes are the product.

Working repo for the Umber Cloud engine (umbercloud.com). Currently: check engine v0. Next: findings-to-controls mapping, evidence export, dashboard.

## What this becomes

| Layer | What it does | Status |
|-------|--------------|--------|
| Check engine | Agentless AWS scans via read-only IAM (10 checks, CIS-aligned) | Check 1 of 10 done |
| Findings translation | Plain-English risk statements + Terraform/CLI fix snippets | Planned |
| Compliance mapping | Each finding mapped to SOC 2 controls (CC6.1, CC6.6, ...) with exportable evidence | Planned — the wedge |
| Dashboard | Connect account in 15 minutes, see what an auditor will ask about | Planned |

Positioning: startups facing a SOC 2 deadline don't need 300 raw findings (Prowler OSS does that for free). They need to know what's exposed, what the auditor needs, and the exact fix — in language a founder can act on.

## Check 1: S3 public access

Flags buckets where any of these are true:

- Bucket-level public access block is missing or not fully enabled
- Bucket ACL grants access to `AllUsers` or `AuthenticatedUsers`
- Bucket policy allows `Principal: *` or `Principal.AWS: *`

Maps to: CIS AWS 2.1.x, SOC 2 CC6.1 (logical access) / CC6.6 (boundary protection).

## Requirements

- Python 3.10+
- AWS credentials with read-only access (recommended: `SecurityAudit` managed policy)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
aws configure
```

## Run

```bash
python checks/s3_public.py
```

Optional flags:

```bash
python checks/s3_public.py --profile my-profile
python checks/s3_public.py --json
```

## Example output

```
Scanned 3 bucket(s)

[OK] s3://my-private-backups (us-east-1)
  - No public access indicators found

[PUBLIC RISK] s3://marketing-assets (us-east-1)
  - BlockPublicPolicy is disabled
  - ACL grants READ to AllUsers (public internet)

[OK] s3://logs-internal (us-west-2)
  - No public access indicators found

Summary: 1 bucket(s) with public access risk
```

Exit code `0` = no public risk found. Exit code `1` = at least one bucket flagged.

## Roadmap

See `CHECKS.md` for the check backlog with compliance mappings, and the build phases below.

1. **Phase 1** — 10 checks + plain-English findings (beat free tools on clarity, not count)
2. **Phase 2** — SOC 2 control mapping + evidence export (the reason startups pay)
3. **Phase 3** — Dashboard + 15-minute cross-account IAM role onboarding
4. **Phase 4** — Remediation snippets (Terraform / AWS CLI) per finding
5. **Phase 5** — Vanta/Drata integration, AWS Marketplace listing, MSP white-label
