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
| 7 | UC-007 | EBS volumes unencrypted (+ default encryption off) | done | `checks/ebs_encryption.py` | 2.2.1 | CC6.7 (data at rest) |
| 8 | UC-008 | RDS instance public / snapshot shared publicly | done | `checks/rds_public.py` | 2.3.x | CC6.1, CC6.6 |
| 9 | UC-009 | EC2 IMDSv1 enabled | done | `checks/imdsv1.py` | 5.6 | CC6.6 |
| 10 | UC-010 | Lambda over-privileged execution role | done | `checks/lambda_iam.py` | — | CC6.3 (least privilege) |

## AI-agent security pack (UC-020+)

The innovation spear: audit the cloud blast radius of AI agents — a new class of identity that is provisioned fast, over-privileged by default, and covered by nobody's checklist. Same Finding model, same evidence pipeline.

| # | ID | Check | Status | Module | SOC 2 |
|---|----|-------|--------|--------|-------|
| 20 | UC-020 | AI/agent execution role with full admin (Bedrock/SageMaker trust or agent-named) | done | `checks/ai_agent_roles.py` | CC6.3 |
| 21 | UC-021 | Machine/agent identity on long-lived access keys | done | `checks/agent_keys.py` | CC6.1 |
| 22 | UC-022 | Secrets in Lambda environment variables (names/shapes only, values never read) | done | `checks/lambda_secrets.py` | CC6.1 |
| 23 | UC-023 | Agent role that can edit its own IAM policies (self-escalation) | planned | `checks/agent_self_escalation.py` | CC6.3 |
| 24 | UC-024 | Bedrock model invocation logging disabled | planned | `checks/bedrock_logging.py` | CC7.2 |
| 25 | UC-025 | SageMaker/Bedrock endpoints publicly accessible | planned | `checks/ai_endpoints.py` | CC6.6 |

Run everything: `python checks/run_all.py --profile <profile>` (writes `scans/<timestamp>.json`). Add `--all-regions` to fan regional checks across every enabled region.
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
