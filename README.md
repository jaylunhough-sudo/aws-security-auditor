# aws-security-auditor

Agentless AWS security checks for common misconfigurations. Check #1: public S3 bucket risk.

## Check 1: S3 public access

Flags buckets where any of these are true:

- Bucket-level public access block is missing or not fully enabled
- Bucket ACL grants access to `AllUsers` or `AuthenticatedUsers`
- Bucket policy allows `Principal: *` or `Principal.AWS: *`

## Requirements

- Python 3.10+
- AWS credentials with read-only S3 access (recommended: `SecurityAudit` managed policy)

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

See `CHECKS.md` for the full check backlog (CIS AWS Foundations aligned).
