# Check backlog

CIS AWS Foundations aligned, with SOC 2 control mapping — because findings that map to controls are evidence, and evidence is what customers pay for. Build in order.

Every check must ship with three outputs, not one:

1. **Detection** — the raw finding (what free tools already do)
2. **Plain-English risk** — one sentence a founder understands ("Your database backups are reachable from the public internet")
3. **Fix** — exact Terraform or AWS CLI snippet to remediate

All checks emit the shared `Finding` model in `checks/models.py` (check_id, resource, region, severity, status pass/fail, detection, plain_english_risk, fix_terraform, fix_cli, cis_refs, soc2_refs). Check IDs are UC-001 through UC-010.

| # | ID | Check | Status | Module | CIS | SOC 2 |
|---|----|-------|--------|--------|-----|-------|
| 1 | UC-001 | S3 public access (ACL, policy, public access block) | done | `checks/s3_public.py` | 2.1.x | CC6.1, CC6.6 |
| 2 | UC-002 | Security group open to 0.0.0.0/0 (SSH/RDP/DB + 1433, 9200, 5601) | done | `checks/sg_open.py` | 5.2–5.3 | CC6.6 |
| 3 | UC-003/b | Root account MFA disabled / root access keys exist | done | `checks/root_mfa.py` | 1.4–1.5 | CC6.1 |
| 4 | UC-004 | IAM policy allows `*:*` admin access | done | `checks/iam_admin.py` | 1.16 | CC6.1, CC6.3 |
| 5 | UC-005 | CloudTrail disabled or not multi-region | done | `checks/cloudtrail.py` | 3.1 | CC7.2 (monitoring) |
| 6 | UC-006 | Access keys older than 90 days | done | `checks/stale_keys.py` | 1.14 | CC6.1 |
| 7 | UC-007 | EBS volumes unencrypted | planned | `checks/ebs_encryption.py` | 2.2.1 | CC6.7 (data at rest) |
| 8 | UC-008 | RDS snapshot public | planned | `checks/rds_public.py` | 2.3.x | CC6.1, CC6.6 |
| 9 | UC-009 | EC2 IMDSv1 enabled | planned | `checks/imdsv1.py` | 5.6 | CC6.6 |
| 10 | UC-010 | Lambda over-privileged execution role | planned | `checks/lambda_iam.py` | — | CC6.3 (least privilege) |

Run everything: `python checks/run_all.py --profile <profile>` (writes `scans/<timestamp>.json`).
Export evidence: `python export_evidence.py` (reads latest scan, writes CSV + Markdown to `evidence/`).
Tests (no AWS needed): `pytest` (moto-mocked, see `tests/test_checks.py`).

## After the 10 (Phase 2+)

- ~~Findings → SOC 2 evidence export (CSV/Markdown an auditor can sample)~~ shipped: `export_evidence.py` + `compliance/soc2_map.json` (PDF later)
- Scan history for Type 2 "controls effective over time" evidence (scans/ already accumulates timestamped JSON — needs trend view)
- Vanta / Drata push integration
- Multi-account via cross-account IAM role (the 15-minute onboarding)

## Notes

- SOC 2 mappings are to Trust Services Criteria (Security / Common Criteria). Verify exact criteria wording against the current TSC before shipping evidence-export language — do not let marketing text drift ahead of what the check actually proves.
- CIS references are to AWS Foundations Benchmark; re-verify section numbers against the current benchmark version when building each check.
