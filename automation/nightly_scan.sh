#!/bin/zsh
# Umber Cloud nightly scan — run by launchd (see com.umbercloud.nightly-scan.plist).
# Each run appends a timestamped scan to scans/ and regenerates evidence/.
# Months of these = SOC 2 Type 2 "controls effective over time" evidence.

REPO="/Users/jaylunhough/Projects/aws-security-auditor"
PROFILE="security-auditor"
LOG_DIR="$REPO/automation/logs"
LOG_FILE="$LOG_DIR/nightly-$(date +%Y-%m).log"

mkdir -p "$LOG_DIR"
cd "$REPO" || exit 1

{
  echo ""
  echo "=== Umber Cloud nightly scan: $(date) ==="
  .venv/bin/python checks/run_all.py --profile "$PROFILE"
  scan_exit=$?
  .venv/bin/python export_evidence.py
  echo "=== done (scan exit code: $scan_exit; 0=clean, 1=findings, 2=creds error) ==="
} >> "$LOG_FILE" 2>&1
