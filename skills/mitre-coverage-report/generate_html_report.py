#!/usr/bin/env python3
"""
MITRE ATT&CK Coverage Report — HTML Report Generator

Reads the scratchpad markdown produced by invoke_mitre_scan.py
and generates a self-contained, styled HTML report.

Usage:
    python3 generate_html_report.py <scratchpad_path> [--output-dir reports/mitre-coverage/]
"""

import argparse
import html as html_mod
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════
# BADGE MAPPING (emoji → HTML)
# ═══════════════════════════════════════════════════════════════════

BADGE_MAP = {
    '🔴': ('<span class="badge bg-red">', '</span>'),
    '🟠': ('<span class="badge bg-orange">', '</span>'),
    '🟡': ('<span class="badge bg-yellow">', '</span>'),
    '🔵': ('<span class="badge bg-blue">', '</span>'),
    '🟢': ('<span class="badge bg-green">', '</span>'),
    '✅': ('<span class="badge bg-green">✓</span>', ''),
    '❌': ('<span class="badge bg-red">✗</span>', ''),
    '⚠️': ('<span class="badge bg-orange">⚠</span>', ''),
    '⬜': ('<span class="badge bg-gray">—</span>', ''),
    '🚫': ('<span class="badge bg-red">⊘</span>', ''),
}

SCORE_COLORS = {
    (80, 101): ('#2ecc71', 'Strong'),
    (60, 80):  ('#3498db', 'Good'),
    (40, 60):  ('#f1c40f', 'Moderate'),
    (20, 40):  ('#f39c12', 'Developing'),
    (0, 20):   ('#e74c3c', 'Critical'),
}


def score_color(val: float) -> tuple[str, str]:
    for (lo, hi), (color, label) in SCORE_COLORS.items():
        if lo <= val < hi:
            return color, label
    return '#e74c3c', 'Critical'


# ═══════════════════════════════════════════════════════════════════
# SCRATCHPAD PARSER
# ═══════════════════════════════════════════════════════════════════

def parse_scratchpad(text: str) -> dict:
    """Parse scratchpad into structured sections."""
    data: dict = {}
    current_h2 = None
    current_h3 = None
    current_h4 = None

    for line in text.splitlines():
        stripped = line.strip()

        # H2 sections
        if stripped.startswith('## ') and not stripped.startswith('## #'):
            current_h2 = stripped[3:].strip()
            data.setdefault(current_h2, {'_kv': {}, '_lines': [], '_sub': {}})
            current_h3 = None
            current_h4 = None
            continue

        # H3 subsections
        if stripped.startswith('### ') and current_h2:
            current_h3 = stripped[4:].strip()
            data[current_h2]['_sub'].setdefault(current_h3, {'_kv': {}, '_lines': [], '_sub': {}})
            current_h4 = None
            continue

        # H4 sub-subsections
        if stripped.startswith('#### ') and current_h2 and current_h3:
            current_h4 = stripped[5:].strip()
            data[current_h2]['_sub'][current_h3]['_sub'].setdefault(current_h4, [])
            continue

        if not current_h2:
            continue

        # Key:value parsing
        kv_match = re.match(r'^([A-Za-z_][\w_.]*)\s*:\s*(.+)$', stripped)

        if current_h4 and current_h3:
            data[current_h2]['_sub'][current_h3]['_sub'][current_h4].append(line)
        elif current_h3:
            sub = data[current_h2]['_sub'][current_h3]
            sub['_lines'].append(line)
            if kv_match:
                sub['_kv'][kv_match.group(1)] = kv_match.group(2).strip()
        else:
            data[current_h2]['_lines'].append(line)
            if kv_match:
                data[current_h2]['_kv'][kv_match.group(1)] = kv_match.group(2).strip()

    return data


def get_kv(data: dict, section: str, key: str, default: str = '') -> str:
    s = data.get(section, {})
    return s.get('_kv', {}).get(key, default)


def get_sub_kv(data: dict, section: str, subsection: str, key: str, default: str = '') -> str:
    s = data.get(section, {}).get('_sub', {}).get(subsection, {})
    return s.get('_kv', {}).get(key, default)


def get_sub_lines(data: dict, section: str, subsection: str) -> list[str]:
    return data.get(section, {}).get('_sub', {}).get(subsection, {}).get('_lines', [])


def get_sub_sub_lines(data: dict, section: str, subsection: str, h4: str) -> list[str]:
    return (data.get(section, {}).get('_sub', {}).get(subsection, {})
            .get('_sub', {}).get(h4, []))


# ═══════════════════════════════════════════════════════════════════
# MARKDOWN TABLE → HTML TABLE
# ═══════════════════════════════════════════════════════════════════

def _convert_emoji(text: str) -> str:
    """Replace emoji with styled HTML spans."""
    for emoji, (open_tag, close_tag) in BADGE_MAP.items():
        if emoji in text:
            if close_tag:
                text = text.replace(emoji, open_tag + emoji + close_tag)
            else:
                text = text.replace(emoji, open_tag)
    return text


def md_table_to_html(lines: list[str], table_class: str = '') -> str:
    """Convert markdown table lines to an HTML <table>."""
    rows: list[list[str]] = []
    for line in lines:
        line = line.strip()
        if not line.startswith('|'):
            continue
        cells = [c.strip() for c in line.split('|')[1:-1]]
        # Skip separator rows
        if all(re.match(r'^[-:]+$', c) for c in cells if c):
            continue
        rows.append(cells)

    if not rows:
        return ''

    cls = f' class="{table_class}"' if table_class else ''
    out = [f'<table{cls}>']

    # First row = header
    out.append('<thead><tr>')
    for cell in rows[0]:
        out.append(f'<th>{_convert_emoji(html_mod.escape(cell))}</th>')
    out.append('</tr></thead>')

    # Remaining rows = body
    out.append('<tbody>')
    for row in rows[1:]:
        is_total = any('TOTAL' in c or '**' in c for c in row)
        cls_row = ' class="total-row"' if is_total else ''
        out.append(f'<tr{cls_row}>')
        for cell in row:
            cell_clean = cell.replace('**', '')
            out.append(f'<td>{_convert_emoji(html_mod.escape(cell_clean))}</td>')
        out.append('</tr>')
    out.append('</tbody></table>')

    return '\n'.join(out)


def collect_md_tables(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Collect markdown tables with their preceding header (#### or text)."""
    tables: list[tuple[str, list[str]]] = []
    current_header = ''
    current_table: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith('####'):
            if current_table:
                tables.append((current_header, current_table))
                current_table = []
            current_header = stripped.lstrip('#').strip()
        elif stripped.startswith('|'):
            current_table.append(stripped)
        elif stripped.startswith('SectionTitle:'):
            current_header = stripped.split(':', 1)[1].strip()
        else:
            if current_table and stripped and not stripped.startswith('<!--') and not stripped.startswith('...'):
                tables.append((current_header, current_table))
                current_table = []

    if current_table:
        tables.append((current_header, current_table))

    return tables


# ═══════════════════════════════════════════════════════════════════
# HTML RENDERING
# ═══════════════════════════════════════════════════════════════════

CSS = """
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;font-size:13.5px;line-height:1.5;color:#e0e0e0;background:#111820;padding:16px}
.ctr{max-width:1700px;margin:0 auto;background:#161f2b;border-radius:8px;box-shadow:0 4px 24px rgba(0,0,0,0.5)}
.wm{position:fixed;top:0;left:0;right:0;background:linear-gradient(135deg,#0078d4,#005a9e);color:white;padding:10px 24px;z-index:9999;box-shadow:0 2px 8px rgba(0,0,0,0.4);font-size:13px;font-weight:600;display:flex;justify-content:space-between;align-items:center}
.hdr{background:linear-gradient(135deg,#0078d4,#00b7c3);color:white;padding:20px 28px;border-radius:8px 8px 0 0}
.hdr h1{font-size:1.8em;margin:0}
.hdr .meta{font-size:0.85em;opacity:0.9;margin-top:6px}
.content{padding:16px 20px}

/* Score gauge */
.score-card{display:flex;align-items:center;gap:24px;background:#1c2836;border-radius:8px;padding:20px 28px;margin-bottom:16px;border-left:4px solid var(--score-color,#3498db)}
.score-ring{position:relative;width:120px;height:120px;flex-shrink:0}
.score-ring svg{transform:rotate(-90deg)}
.score-ring .bg{fill:none;stroke:#2a3a4a;stroke-width:10}
.score-ring .fg{fill:none;stroke:var(--score-color,#3498db);stroke-width:10;stroke-linecap:round;transition:stroke-dashoffset .5s}
.score-val{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.score-val .num{font-size:2em;font-weight:700;color:var(--score-color,#3498db)}
.score-val .lbl{font-size:0.75em;color:#aaa;text-transform:uppercase;letter-spacing:1px}
.dim-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;flex:1}
.dim{background:#1a2532;border-radius:6px;padding:12px;text-align:center}
.dim .dv{font-size:1.5em;font-weight:700}.dim .dl{font-size:0.75em;color:#aaa;margin-top:2px}
.dim .dw{font-size:0.7em;color:#666;margin-top:2px}

/* Metrics row */
.metrics{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-bottom:16px}
.metric{background:#1c2836;border-radius:6px;padding:14px;text-align:center;border-top:3px solid #0078d4}
.metric .mv{font-size:1.5em;font-weight:700;color:white}.metric .ml{font-size:0.8em;color:#aaa;margin-top:2px}

/* Sections */
.section{background:#1c2836;border-radius:6px;padding:16px 20px;margin-bottom:14px;border-left:3px solid #0078d4}
.section h2{font-size:1.2em;color:#00b7c3;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid #2a3a4a}
.section h3{font-size:1.05em;color:#e0e0e0;margin:12px 0 8px}
.section h4{font-size:0.95em;color:#aaa;margin:10px 0 6px}
.section p,.section li{color:#c0c0c0;margin:4px 0}
.section ul{padding-left:20px}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:0.9em;margin:8px 0 12px}
th{background:#243447;color:#00b7c3;padding:8px 10px;text-align:left;font-weight:600;border-bottom:2px solid #2a3a4a;white-space:nowrap}
td{padding:6px 10px;border-bottom:1px solid #1f2f3f;vertical-align:top}
tr:nth-child(even){background:rgba(255,255,255,0.02)}
tr:hover{background:rgba(0,183,195,0.05)}
tr.total-row{background:#243447;font-weight:600}
td:first-child{white-space:nowrap}

/* Badges */
.badge{display:inline-block;padding:1px 6px;border-radius:3px;font-size:0.85em;font-weight:600;line-height:1.4}
.bg-red{background:#e74c3c;color:white}.bg-orange{background:#f39c12;color:#1a1a1a}
.bg-yellow{background:#f1c40f;color:#1a1a1a}.bg-blue{background:#3498db;color:white}
.bg-green{background:#2ecc71;color:#1a1a1a}.bg-gray{background:#555;color:#ddd}

/* Collapsible */
details{margin:6px 0}
details summary{cursor:pointer;font-weight:600;color:#00b7c3;padding:6px 0;user-select:none}
details summary:hover{color:#00d4e0}
details[open] summary{margin-bottom:8px}

/* Footer */
.ftr{background:#1c2836;padding:12px 24px;text-align:center;font-size:0.8em;color:#555;border-top:1px solid #2a3a4a;border-radius:0 0 8px 8px}

/* Responsive */
@media(max-width:900px){.dim-grid{grid-template-columns:repeat(3,1fr)}.metrics{grid-template-columns:repeat(2,1fr)}}
@media print{body{background:white;color:#222}.ctr{box-shadow:none}th{background:#eee;color:#222}td{border-color:#ddd}
.wm{display:none}.section{background:#f9f9f9;border-left-color:#0078d4}}
"""


def render_score_section(data: dict) -> str:
    """Render the MITRE Coverage Score card with gauge and dimensions."""
    score_str = get_kv(data, 'SCORE', 'MITRE_Score', '0')
    score = float(score_str)
    color, label = score_color(score)

    # SVG ring calculation
    r = 50
    circ = 2 * 3.14159 * r
    offset = circ * (1 - score / 100)

    dims = [
        ('Breadth', get_kv(data, 'SCORE', 'Breadth', '0'), '25%'),
        ('Balance', get_kv(data, 'SCORE', 'Balance', '0'), '10%'),
        ('Operational', get_kv(data, 'SCORE', 'Operational', '0'), '30%'),
        ('Tagging', get_kv(data, 'SCORE', 'Tagging', '0'), '15%'),
        ('SOC Align', get_kv(data, 'SCORE', 'SOC_Alignment', '0'), '20%'),
    ]

    dim_html = ''
    for name, val, weight in dims:
        v = float(val)
        c, _ = score_color(v)
        dim_html += f'''<div class="dim">
            <div class="dv" style="color:{c}">{val}</div>
            <div class="dl">{name}</div>
            <div class="dw">Weight: {weight}</div>
        </div>'''

    return f'''<div class="score-card" style="--score-color:{color}">
        <div class="score-ring">
            <svg viewBox="0 0 120 120" width="120" height="120">
                <circle class="bg" cx="60" cy="60" r="{r}"/>
                <circle class="fg" cx="60" cy="60" r="{r}"
                    stroke-dasharray="{circ:.1f}" stroke-dashoffset="{offset:.1f}"
                    style="stroke:{color}"/>
            </svg>
            <div class="score-val">
                <div class="num">{score:.0f}</div>
                <div class="lbl">{label}</div>
            </div>
        </div>
        <div class="dim-grid">{dim_html}</div>
    </div>'''


def render_inventory_metrics(data: dict) -> str:
    """Render detection inventory as metric cards."""
    p1 = data.get('PHASE_1 — Rule Inventory & MITRE Extraction', {}).get('_sub', {})
    ar = p1.get('AR_Summary', {}).get('_kv', {})
    cd = p1.get('CD_Summary', {}).get('_kv', {})

    ar_total = ar.get('AR_Total', '0')
    ar_enabled = ar.get('AR_Enabled', '0')
    cd_total = cd.get('CD_Total', '0')
    cd_enabled = cd.get('CD_Enabled', '0')
    cd_status = cd.get('CD_Status', 'OK')

    # Combined
    try:
        combined = int(ar_enabled) + int(cd_enabled)
    except ValueError:
        combined = ar_enabled

    # Techniques from SCORE
    cov = get_kv(data, 'SCORE', 'RuleBasedPlusPlatform_Coverage', '0 / 0 (0%)')

    # Platform tiers
    t1 = get_kv(data, 'SCORE', 'Platform_Tier1', '0')
    t2 = get_kv(data, 'SCORE', 'Platform_Tier2', '0')
    readiness = get_kv(data, 'SCORE', 'DataReadiness_Pct', '0')

    cd_display = f'{cd_enabled}/{cd_total}' if cd_status == 'OK' else 'SKIPPED'

    items = [
        (f'{ar_enabled}/{ar_total}', 'Analytic Rules', '#0078d4'),
        (cd_display, 'Custom Detections', '#9b59b6'),
        (str(combined), 'Combined Enabled', '#00b7c3'),
        (cov.split('(')[0].strip() if '(' in cov else cov, 'Combined Coverage', '#2ecc71'),
        (t1, 'Tier 1 (Alert-Proven)', '#2ecc71'),
        (t2, 'Tier 2 (Deployed)', '#3498db'),
        (f'{readiness}%', 'Data Readiness', '#f39c12' if float(readiness) < 80 else '#2ecc71'),
    ]

    html_parts = ['<div class="metrics">']
    for val, label, color in items:
        html_parts.append(f'''<div class="metric" style="border-top-color:{color}">
            <div class="mv" style="color:{color}">{html_mod.escape(str(val))}</div>
            <div class="ml">{html_mod.escape(label)}</div>
        </div>''')
    html_parts.append('</div>')
    return '\n'.join(html_parts)


def render_prerendered_section(data: dict, subsection: str, title: str, icon: str = '📊') -> str:
    """Render a PRERENDERED subsection as HTML."""
    pre = data.get('PRERENDERED', {}).get('_sub', {})
    sub = pre.get(subsection, {})
    lines = sub.get('_lines', [])
    h4_subs = sub.get('_sub', {})

    if not lines and not h4_subs:
        return ''

    parts = [f'<div class="section"><h2>{icon} {html_mod.escape(title)}</h2>']

    # Main table from _lines
    tables = collect_md_tables(lines)
    if tables:
        for hdr, tbl_lines in tables:
            if hdr:
                parts.append(f'<h3>{_convert_emoji(html_mod.escape(hdr))}</h3>')
            parts.append(md_table_to_html(tbl_lines))
    elif lines:
        # Check for inline table
        tbl_lines = [l for l in lines if l.strip().startswith('|')]
        if tbl_lines:
            parts.append(md_table_to_html(tbl_lines))

    # H4 sub-tables
    for h4_name, h4_lines in h4_subs.items():
        parts.append(f'<h3>{_convert_emoji(html_mod.escape(h4_name))}</h3>')
        tbl = [l for l in h4_lines if l.strip().startswith('|')]
        if tbl:
            parts.append(md_table_to_html(tbl))
        other = [l.strip() for l in h4_lines if l.strip() and not l.strip().startswith('|') and not l.strip().startswith('<!--')]
        for o in other:
            parts.append(f'<p>{_convert_emoji(html_mod.escape(o))}</p>')

    parts.append('</div>')
    return '\n'.join(parts)


def render_technique_tables(data: dict) -> str:
    """Render per-tactic technique tables as collapsible sections."""
    pre = data.get('PRERENDERED', {}).get('_sub', {})
    tt = pre.get('TechniqueTables', {})
    lines = tt.get('_lines', [])
    h4_subs = tt.get('_sub', {})

    if not h4_subs and not lines:
        return ''

    parts = ['<div class="section"><h2>🔬 Technique Deep Dive</h2>']

    for tactic_header, tactic_lines in h4_subs.items():
        tbl = [l for l in tactic_lines if l.strip().startswith('|')]
        extra = [l.strip() for l in tactic_lines
                 if l.strip() and not l.strip().startswith('|')
                 and not l.strip().startswith('<!--')]

        parts.append(f'<details><summary>{_convert_emoji(html_mod.escape(tactic_header))}</summary>')
        if tbl:
            parts.append(md_table_to_html(tbl))
        for e in extra:
            parts.append(f'<p style="color:#888;font-size:0.9em;">{_convert_emoji(html_mod.escape(e))}</p>')
        parts.append('</details>')

    parts.append('</div>')
    return '\n'.join(parts)


def render_html(data: dict) -> str:
    """Render full HTML report from parsed scratchpad data."""
    meta = data.get('META', {}).get('_kv', {})
    workspace = meta.get('Workspace', 'Unknown')
    ws_id = meta.get('WorkspaceId', '')
    days = meta.get('Days', '30')
    generated = meta.get('Generated', datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
    attack_ver = meta.get('ATT\u0027CK_Version', meta.get('ATT_CK_Version', meta.get('ATT&CK_Version', '16.1')))
    techs = meta.get('ATT\u0027CK_Techniques', meta.get('ATT_CK_Techniques', meta.get('ATT&CK_Techniques', '216')))

    score_str = get_kv(data, 'SCORE', 'MITRE_Score', '0')
    score_color_val, score_label = score_color(float(score_str))

    # Defanged workspace for display
    safe_ws = html_mod.escape(workspace)

    # Build sections
    score_html = render_score_section(data)
    inventory_html = render_inventory_metrics(data)
    tactic_html = render_prerendered_section(data, 'TacticCoverageMatrix', 'Tactic Coverage Matrix', '🎯')
    combined_html = render_prerendered_section(data, 'CombinedTacticCoverage', 'Combined Tactic Coverage (Rule + Platform)', '🛡️')
    technique_html = render_technique_tables(data)
    scenarios_html = render_prerendered_section(data, 'ThreatScenarios', 'Threat Scenario Alignment (SOC Optimization)', '⚡')
    incidents_html = render_prerendered_section(data, 'IncidentsByTactic', 'Incidents by Tactic', '📋')
    active_tagged_html = render_prerendered_section(data, 'ActiveVsTagged', 'Active vs Tagged Tactic Coverage', '🔍')
    alert_firing_html = render_prerendered_section(data, 'AlertFiring', 'Alert-Producing Rules', '🚨')
    readiness_html = render_prerendered_section(data, 'DataReadiness', 'Data Readiness', '💾')
    connector_html = render_prerendered_section(data, 'ConnectorHealth', 'Connector Health', '🔌')

    # Untagged rules from Phase 1
    untagged_lines = get_sub_lines(data, 'PHASE_1 — Rule Inventory & MITRE Extraction', 'UntaggedRules')
    untagged_html = ''
    if untagged_lines:
        pipe_rows = [l for l in untagged_lines if '|' in l and not l.strip().startswith('<!--')]
        if pipe_rows:
            # Convert pipe-delimited to markdown table
            headers = ['Rule Name', 'Rule ID', 'Enabled', 'Kind', 'Severity', 'Source']
            md = ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join(['---'] * len(headers)) + ' |']
            for row in pipe_rows:
                cells = [c.strip() for c in row.split('|') if c.strip()]
                if cells:
                    md.append('| ' + ' | '.join(cells) + ' |')
            untagged_html = f'''<div class="section"><h2>🏷️ Untagged Rules ({len(pipe_rows)})</h2>
                <p style="color:#f39c12;margin-bottom:8px;">Rules without MITRE ATT&CK tags — excluded from coverage analysis.</p>
                {md_table_to_html(md)}</div>'''

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MITRE ATT&CK Coverage Report — {safe_ws}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wm">
    <div>🛡️ <strong>MITRE ATT&CK COVERAGE REPORT</strong></div>
    <div style="font-size:12px;">Generated {html_mod.escape(generated)} | Lookback {html_mod.escape(days)}d</div>
</div>
<div class="ctr" style="margin-top:50px;">
    <div class="hdr">
        <div>
            <h1>🛡️ MITRE ATT&CK Coverage Report</h1>
            <div class="meta">
                <strong>Workspace:</strong> {safe_ws} &nbsp;|&nbsp;
                <strong>ATT&CK:</strong> Enterprise v{html_mod.escape(str(attack_ver))} ({html_mod.escape(str(techs))} techniques) &nbsp;|&nbsp;
                <strong>Lookback:</strong> {html_mod.escape(days)} days
            </div>
        </div>
    </div>
    <div class="content">
        <div class="section"><h2>🎯 MITRE Coverage Score</h2>
            {score_html}
        </div>
        <div class="section"><h2>📊 Detection Inventory</h2>
            {inventory_html}
        </div>
        {tactic_html}
        {combined_html}
        {technique_html}
        {untagged_html}
        {scenarios_html}
        {alert_firing_html}
        {active_tagged_html}
        {incidents_html}
        {readiness_html}
        {connector_html}
    </div>
    <div class="ftr">
        <strong>MITRE ATT&CK Coverage Report</strong> — {safe_ws} — {html_mod.escape(generated)}<br>
        <span style="color:#666;">Generated by mitre-coverage-report skill | ATT&CK Enterprise v{html_mod.escape(str(attack_ver))}</span>
    </div>
</div>
</body>
</html>'''


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='MITRE ATT&CK Coverage Report — HTML Generator')
    parser.add_argument('scratchpad', help='Path to scratchpad .md file')
    parser.add_argument('--output-dir', default='reports/mitre-coverage/',
                        help='Output directory for HTML report')
    args = parser.parse_args()

    sp_path = Path(args.scratchpad)
    if not sp_path.exists():
        print(f'❌ Scratchpad not found: {sp_path}', file=sys.stderr)
        sys.exit(1)

    text = sp_path.read_text(encoding='utf-8')
    data = parse_scratchpad(text)

    if 'SCORE' not in data:
        print('❌ No SCORE section found in scratchpad — is this a valid scratchpad file?', file=sys.stderr)
        sys.exit(1)

    html_out = render_html(data)

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M%S')
    meta = data.get('META', {}).get('_kv', {})
    ws = meta.get('Workspace', 'workspace').replace(' ', '_')
    outfile = outdir / f'MITRE_Coverage_{ws}_{ts}.html'
    outfile.write_text(html_out, encoding='utf-8')

    size_kb = round(outfile.stat().st_size / 1024, 1)
    print(f'\n✅ HTML report generated: {outfile} ({size_kb} KB)')


if __name__ == '__main__':
    main()
