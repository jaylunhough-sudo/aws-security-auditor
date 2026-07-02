#!/usr/bin/env python3
"""Umber Cloud dashboard v0 — local, read-only, no auth, no database.

Reads scans/*.json (the files ARE the database) and renders:
- headline posture (failing / total findings, per latest scan)
- trend of failing findings across scan history (the Type 2 story)
- findings grouped by SOC 2 control with risk + fix

Run: .venv/bin/python dashboard/app.py  ->  http://127.0.0.1:5077
"""

from __future__ import annotations

import json
from pathlib import Path

from flask import Flask, render_template_string

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANS_DIR = REPO_ROOT / "scans"
SOC2_MAP_PATH = REPO_ROOT / "compliance" / "soc2_map.json"

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Umber Cloud — Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #060a13; --glass: rgba(255,255,255,0.035); --glass-strong: rgba(255,255,255,0.06);
  --border: rgba(255,255,255,0.09); --border-soft: rgba(255,255,255,0.06);
  --text: #eef1f6; --dim: #9aa3b2; --faint: #626c7d;
  --amber: #f5a524; --teal: #2dd4bf; --red: #f87171; --green: #4ade80;
  --mono: "JetBrains Mono", monospace;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { background:var(--bg); color:var(--text); font-family:"Inter",sans-serif; font-size:15px; line-height:1.6; }
.container { max-width:1060px; margin:0 auto; padding:0 24px 80px; }
header { display:flex; align-items:center; justify-content:space-between; padding:22px 0; border-bottom:1px solid var(--border-soft); margin-bottom:36px; }
.logo { display:flex; align-items:center; gap:10px; font-weight:700; font-size:17px; }
.logo-mark { width:24px; height:24px; border-radius:7px; background:linear-gradient(135deg,#f5a524,#b45309); box-shadow:0 0 16px rgba(245,165,36,0.3); }
.meta { font-family:var(--mono); font-size:12px; color:var(--faint); }
.cards { display:grid; grid-template-columns:repeat(5,1fr); gap:14px; margin-bottom:36px; }
@media (max-width:800px) { .cards { grid-template-columns:repeat(2,1fr); } }
.stat { background:var(--glass); border:1px solid var(--border-soft); border-radius:14px; padding:20px 22px; }
.stat .n { font-size:34px; font-weight:800; letter-spacing:-0.03em; }
.stat .l { font-size:12.5px; color:var(--dim); margin-top:2px; }
.stat.bad .n { color:var(--red); } .stat.good .n { color:var(--green); } .stat.brand .n { color:var(--amber); }
h2 { font-size:19px; font-weight:700; letter-spacing:-0.01em; margin:36px 0 14px; }
.trend { background:var(--glass); border:1px solid var(--border-soft); border-radius:14px; padding:20px 22px; }
.trend svg { width:100%; height:90px; display:block; }
.trend .cap { font-size:12.5px; color:var(--faint); margin-top:8px; }
.control { background:var(--glass); border:1px solid var(--border-soft); border-radius:14px; margin-bottom:14px; overflow:hidden; }
.control-head { display:flex; align-items:baseline; gap:12px; padding:15px 22px; border-bottom:1px solid var(--border-soft); background:var(--glass-strong); }
.control-head .cid { font-family:var(--mono); font-weight:700; color:var(--amber); font-size:14px; }
.control-head .cs { font-size:13px; color:var(--dim); }
.frow { display:flex; gap:14px; padding:13px 22px; border-bottom:1px solid var(--border-soft); align-items:flex-start; }
.frow:last-child { border-bottom:none; }
.chip { flex-shrink:0; font-family:var(--mono); font-size:10.5px; font-weight:700; padding:3px 10px; border-radius:999px; margin-top:3px; }
.chip.pass { background:rgba(74,222,128,0.12); color:var(--green); border:1px solid rgba(74,222,128,0.28); }
.chip.fail { background:rgba(248,113,113,0.12); color:var(--red); border:1px solid rgba(248,113,113,0.3); }
.fbody { min-width:0; }
.fres { font-family:var(--mono); font-size:13px; }
.fdet { font-size:13.5px; color:var(--dim); }
.frisk { font-size:13.5px; color:var(--amber); margin-top:4px; }
details { margin-top:6px; }
summary { cursor:pointer; font-size:12.5px; color:var(--teal); font-weight:600; }
pre { font-family:var(--mono); font-size:12px; background:rgba(0,0,0,0.35); border:1px solid var(--border-soft); border-radius:8px; padding:12px; margin-top:8px; overflow-x:auto; color:#cdd6e3; }
.empty { text-align:center; padding:80px 0; color:var(--dim); }
.empty code { font-family:var(--mono); color:var(--amber); }
</style>
</head>
<body>
<div class="container">
<header>
  <div class="logo"><span class="logo-mark"></span>Umber Cloud <span style="color:var(--faint);font-weight:500">dashboard</span></div>
  {% if scan %}<div class="meta">scan: {{ scan_name }} · {{ scan.scanned_at_utc[:19] }} UTC</div>{% endif %}
</header>

{% if not scan %}
  <div class="empty">No scans yet. Run <code>python checks/run_all.py --profile security-auditor</code> first.</div>
{% else %}
  {% set score = scan.get('score', (scan.summary.pass / scan.summary.total * 100)|round|int if scan.summary.total else 100) %}
  <div class="cards">
    <div class="stat {{ 'good' if score >= 90 else ('brand' if score >= 70 else 'bad') }}"><div class="n">{{ score }}</div><div class="l">posture score / 100</div></div>
    <div class="stat brand"><div class="n">{{ scan.summary.total }}</div><div class="l">control observations</div></div>
    <div class="stat good"><div class="n">{{ scan.summary.pass }}</div><div class="l">effective (passing)</div></div>
    <div class="stat {{ 'bad' if scan.summary.fail else 'good' }}"><div class="n">{{ scan.summary.fail }}</div><div class="l">exceptions (failing)</div></div>
    <div class="stat"><div class="n">{{ history|length }}</div><div class="l">scans on record</div></div>
  </div>

  <div class="trend">
    <svg viewBox="0 0 1000 90" preserveAspectRatio="none">
      {% set maxf = history|map(attribute=1)|max or 1 %}
      {% set n = history|length %}
      <polyline fill="none" stroke="#f87171" stroke-width="2.5"
        points="{% for ts, f in history %}{{ (loop.index0 / (n - 1 if n > 1 else 1) * 980 + 10)|round(1) }},{{ (80 - (f / (maxf if maxf else 1)) * 65)|round(1) }} {% endfor %}"/>
      {% for ts, f in history %}
      <circle cx="{{ (loop.index0 / (n - 1 if n > 1 else 1) * 980 + 10)|round(1) }}" cy="{{ (80 - (f / (maxf if maxf else 1)) * 65)|round(1) }}" r="3.5" fill="#f87171"/>
      {% endfor %}
    </svg>
    <div class="cap">Failing findings per scan, oldest to newest — a line that goes down and stays down is your Type 2 evidence story. ({{ history[0][0][:10] }} → {{ history[-1][0][:10] }})</div>
  </div>

  <h2>Findings by SOC 2 control</h2>
  {% for control, items in by_control.items() %}
  <div class="control">
    <div class="control-head">
      <span class="cid">{{ control }}</span>
      <span class="cs">{{ statements.get(control, '') }}</span>
    </div>
    {% for f in items %}
    <div class="frow">
      <span class="chip {{ f.status }}">{{ 'PASS' if f.status == 'pass' else 'FAIL' }}</span>
      <div class="fbody">
        <div class="fres">{{ f.check_id }} · {{ f.resource }} <span style="color:var(--faint)">({{ f.region }})</span></div>
        <div class="fdet">{{ f.detection }}</div>
        {% if f.status == 'fail' %}
        <div class="frisk">{{ f.plain_english_risk }}</div>
        <details><summary>Show fix</summary>
          {% if f.fix_cli %}<pre>{{ f.fix_cli }}</pre>{% endif %}
          {% if f.fix_terraform %}<pre>{{ f.fix_terraform }}</pre>{% endif %}
        </details>
        {% endif %}
      </div>
    </div>
    {% endfor %}
  </div>
  {% endfor %}
{% endif %}
</div>
</body>
</html>
"""


def load_scans() -> list[Path]:
    if not SCANS_DIR.exists():
        return []
    return sorted(SCANS_DIR.glob("*.json"))


@app.route("/")
def index():
    scan_paths = load_scans()
    if not scan_paths:
        return render_template_string(TEMPLATE, scan=None)

    latest = scan_paths[-1]
    scan = json.loads(latest.read_text())

    history = []
    for path in scan_paths:
        try:
            data = json.loads(path.read_text())
            history.append((data.get("scanned_at_utc", path.stem), data["summary"]["fail"]))
        except (json.JSONDecodeError, KeyError):
            continue

    soc2_map = json.loads(SOC2_MAP_PATH.read_text()) if SOC2_MAP_PATH.exists() else {}
    statements = {}
    for meta in soc2_map.values():
        if not isinstance(meta, dict):
            continue
        for control in meta.get("soc2", []):
            statements.setdefault(control, meta.get("control_statement", ""))

    by_control: dict[str, list[dict]] = {}
    for finding in scan.get("findings", []):
        for control in finding.get("soc2_refs") or ["unmapped"]:
            by_control.setdefault(control, []).append(finding)
    # failing findings first inside each control, controls sorted by name
    by_control = {
        control: sorted(items, key=lambda f: f["status"])  # "fail" < "pass"
        for control, items in sorted(by_control.items())
    }

    return render_template_string(
        TEMPLATE,
        scan=scan,
        scan_name=latest.name,
        history=history,
        by_control=by_control,
        statements=statements,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5077, debug=False)
