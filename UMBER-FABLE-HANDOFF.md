# Umber Cloud — build map and session handoff

**Repo:** `/Users/jaylunhough/Projects/aws-security-auditor`
**Remote:** https://github.com/jaylunhough-sudo/aws-security-auditor
**Brand:** Umber Cloud · umbercloud.com (domain not yet configured — do not touch DNS)
**Founder:** Jaylun — solo builder, ~$300–500/mo budget, no security credential yet (building one in public code instead).

This document is written so any capable model can pick up the build cold. Read it, read `CHECKS.md`, skim `checks/s3_public.py` for the house style, then execute the next unfinished item. Do not re-litigate architecture. Do not dumb anything down — the logic standard is: every design choice traceable to a customer or auditor need.

---

## 1. Product thesis (why every line of code exists)

Umber Cloud is **SOC 2 evidence and plain-English remediation for AWS startups** — not a scanner. Prowler OSS gives away 300 raw findings for free; nobody pays for detection alone. Startups pay when a compliance deadline (SOC 2 for an enterprise deal) forces them to answer: *what's exposed, what will the auditor ask, and what exactly do I type to fix it?*

Therefore the **three-output standard** is non-negotiable. Every check emits, per finding:

1. **Detection** — the technical observation (parity with free tools)
2. **Plain-English risk** — one sentence a non-security founder acts on
3. **Fix** — exact AWS CLI command and/or Terraform snippet

And every finding — **including passing ones** — maps to SOC 2 Trust Services Criteria, because a dated record of a control *passing* is auditor evidence ("control operating effectively"). Failing findings are alerts; passing findings are the product.

## 2. Current state (verified by live scan + tests, this session)

| Asset | State |
|-------|-------|
| `checks/models.py` | Shared `Finding` dataclass + `summarize` + `print_findings`. **The contract every check obeys.** |
| `checks/s3_public.py` (UC-001) | Done, three-output, tested (moto + live) |
| `checks/sg_open.py` (UC-002) | Done. Ports 22, 3389, 3306, 5432, 27017, 6379, 1433, 9200, 5601 + protocol `-1`. Skips 80/443 (noise). Tested |
| `checks/root_mfa.py` (UC-003, UC-003b) | Done. Root MFA + root access keys via `get_account_summary`. Tested |
| `checks/iam_admin.py` (UC-004) | Done. Customer-managed policies with `*:*` Allow. Tested |
| `checks/cloudtrail.py` (UC-005) | Done. Fails unless a multi-region trail is actively logging. Tested |
| `checks/stale_keys.py` (UC-006) | Done. Active keys > 90 days. Tested |
| `checks/run_all.py` | Runs all six, writes `scans/<UTC timestamp>.json`, prints summary, exit 1 on any fail |
| `compliance/soc2_map.json` | UC-001…UC-010 → CIS + SOC 2 refs + auditor-style control statements |
| `export_evidence.py` | Latest scan → `evidence/evidence-<ts>.csv` + `.md` grouped by SOC 2 control, EFFECTIVE/EXCEPTION language |
| `docs/aws-onboarding.md` | Customer onboarding: IAM-user quick start + cross-account role w/ external ID (the product path) |
| `tests/test_checks.py` | 9 moto tests, all passing, no live AWS needed. Run: `.venv/bin/python -m pytest tests/ -q` |
| Live AWS | Jaylun's account connected via profile `security-auditor` (SecurityAudit policy). Last scan: 1 failing finding (no CloudTrail) — real, not a bug |
| Dashboard, landing page, Stripe, Vanta, Marketplace, MSP | **Not started** |

## 3. Architecture and conventions (follow exactly)

- **One check = one module** in `checks/`, exposing `run_check(profile=None, region=None) -> list[Finding]` plus a standalone `main()` with `--profile / --region / --json`. Exit codes: 0 clean, 1 findings, 2 credential error.
- **Import shim** at top of each check (`try: from checks.models import … except ImportError: from models import …`) so modules run both as scripts and as package imports. Keep it.
- **Check IDs are stable API**: UC-001…UC-010 per `CHECKS.md`. Sub-findings get a letter suffix (UC-003b). Never renumber.
- Emit **pass findings, not silence**, when a control is clean (see any existing check for the pattern).
- **Noise discipline**: do not flag things founders do intentionally (80/443 open, etc.). A tool that cries wolf gets uninstalled.
- Python 3.9-compatible today (`from __future__ import annotations` everywhere); stdlib + boto3 only in product code; moto + pytest in `requirements-dev.txt` only.
- Every new check needs: entry in `CHECKS.md` table, entry in `compliance/soc2_map.json`, registration in `checks/run_all.py` `CHECK_MODULES`, and at least one fail-path + one pass-path moto test.
- Plain-English risk sentences: concrete consequence, no jargon, no fear-mongering filler. Read the existing ones and match the register.
- CIS/SOC 2 refs: use what `CHECKS.md` says; verify against the current CIS benchmark / AICPA TSC before customer-facing use. Never invent control language stronger than what the check proves.

## 4. Build map — remaining items in value order

### Item A — Checks UC-007…UC-010 (finish the sensor)
- `checks/ebs_encryption.py` (UC-007): `ec2.describe_volumes`, flag `Encrypted=False`; also check account default via `get_ebs_encryption_by_default`. Fix: enable default encryption + note that existing volumes need snapshot-copy-restore.
- `checks/rds_public.py` (UC-008): `rds.describe_db_snapshots` + `describe_db_snapshot_attributes` for `restore` attribute containing `all`; also `describe_db_instances` `PubliclyAccessible=True`. Severity critical.
- `checks/imdsv1.py` (UC-009): `ec2.describe_instances`, flag `MetadataOptions.HttpTokens != "required"`. Fix: `aws ec2 modify-instance-metadata-options --http-tokens required`.
- `checks/lambda_iam.py` (UC-010): `lambda.list_functions` → role → attached+inline policies → flag `*:*` or `AdministratorAccess`. Reuse the statement parser from `iam_admin.py` (extract to `checks/policy_utils.py` if shared).
- Acceptance: registered in `run_all.py`, mapped in `soc2_map.json`, `CHECKS.md` updated, moto tests pass (note: moto's RDS/Lambda coverage has gaps — if a moto API is unsupported, test the pure decision function directly on dict fixtures instead; do not skip testing).

### Item B — Landing page (static only)
- `site/index.html`, single file, no framework, no build step. Headline = the wedge ("Know what your SOC 2 auditor will ask about your AWS — and the exact fix — in 15 minutes"). Sections: problem, 3-output example finding (real one from a scan, redacted), how onboarding works (link the read-only trust model), email capture (Formspree or `mailto:` placeholder — no backend). Do NOT configure DNS or deploy; Jaylun ships it to umbercloud.com himself.

### Item C — Dashboard v0 (local, read-only)
- Only after A and B. Flask or FastAPI, one page: reads `scans/*.json`, renders findings grouped by SOC 2 control with pass/fail chips and fix snippets, trend line of failing count across scans (Type 2 story). No auth, no DB — files are the database until there are customers. Do not add React/build tooling yet.

### Item D — Scheduling + Type 2 evidence
- `cron` or launchd doc for nightly `run_all.py`; extend `export_evidence.py` with `--range` to emit "control effective over period" tables from multiple scans. This is the Type 2 differentiator and it is cheap — scans/ already accumulates.

### Item E — Deferred (do not build without Jaylun's explicit go)
Stripe $99 tier (needs his account), Vanta/Drata push, AWS Marketplace listing, MSP white-label tier, AI-agent security pack, multi-account fan-out. These are business-gated, not code-gated.

## 5. Verification protocol (every session, before claiming done)

1. `.venv/bin/python -m pytest tests/ -q` — all green, no live AWS.
2. `.venv/bin/python checks/run_all.py --profile security-auditor` — clean run or real findings; a credentials error is acceptable and must be reported as such.
3. `.venv/bin/python export_evidence.py` — evidence files regenerate without error.
4. Report actual output. Never fabricate scan results.

## 6. Boundaries (unchanged, permanent)

- Never create, store, or commit AWS credentials, `.env` secrets, or real account IDs in code/docs.
- No DNS, no deploys to umbercloud.com, no spending money, no `git push` unless Jaylun explicitly asks.
- No K8s, microservices, auth systems, or paid infra. The moat right now is check quality and evidence language, not architecture.
- `scans/` and `evidence/` contain account-specific data — they are gitignored; keep them out of commits.

## 7. Operating instructions for the model

Act autonomously through the build map top-to-bottom. Pause only for: destructive git operations, spending money, or decisions only Jaylun can make. Final message format: what shipped (files + purpose), what Jaylun must do manually, recommended next session. Plain sentences, no arrow chains, no hype.
