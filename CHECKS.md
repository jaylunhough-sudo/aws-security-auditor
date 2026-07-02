# Check backlog

CIS AWS Foundations aligned, with SOC 2 control mapping — because findings that map to controls are evidence, and evidence is what customers pay for. Build in order.

Every check must ship with three outputs, not one:

1. **Detection** — the raw finding (what free tools already do)
2. **Plain-English risk** — one sentence a founder understands ("Your database backups are reachable from the public internet")
3. **Fix** — exact Terraform or AWS CLI snippet to remediate

| # | Check | Status | Module | CIS | SOC 2 |
|---|-------|--------|--------|-----|-------|
| 1 | S3 public access (ACL, policy, public access block) | done* | `checks/s3_public.py` | 2.1.x | CC6.1, CC6.6 |
| 2 | Security group open to 0.0.0.0/0 (SSH/RDP/DB ports) | done | `checks/sg_open.py` | 5.2–5.3 | CC6.6 |
| 3 | Root account MFA disabled | planned | `checks/root_mfa.py` | 1.5–1.6 | CC6.1 |
| 4 | IAM policy allows `*:*` admin access | planned | `checks/iam_admin.py` | 1.16 | CC6.1, CC6.3 |
| 5 | CloudTrail disabled or not multi-region | planned | `checks/cloudtrail.py` | 3.1 | CC7.2 (monitoring) |
| 6 | Access keys older than 90 days | planned | `checks/stale_keys.py` | 1.14 | CC6.1 |
| 7 | EBS volumes unencrypted | planned | `checks/ebs_encryption.py` | 2.2.1 | CC6.7 (data at rest) |
| 8 | RDS snapshot public | planned | `checks/rds_public.py` | 2.3.x | CC6.1, CC6.6 |
| 9 | EC2 IMDSv1 enabled | planned | `checks/imdsv1.py` | 5.6 | CC6.6 |
| 10 | Lambda over-privileged execution role | planned | `checks/lambda_iam.py` | — | CC6.3 (least privilege) |

*Check 1 has detection only — needs plain-English risk + fix snippet outputs retrofitted to match the three-output standard.

## After the 10 (Phase 2+)

- Findings → SOC 2 evidence export (PDF/CSV an auditor can sample)
- Scan history for Type 2 "controls effective over time" evidence
- Vanta / Drata push integration
- Multi-account via cross-account IAM role (the 15-minute onboarding)

## Notes

- SOC 2 mappings are to Trust Services Criteria (Security / Common Criteria). Verify exact criteria wording against the current TSC before shipping evidence-export language — do not let marketing text drift ahead of what the check actually proves.
- CIS references are to AWS Foundations Benchmark; re-verify section numbers against the current benchmark version when building each check.
