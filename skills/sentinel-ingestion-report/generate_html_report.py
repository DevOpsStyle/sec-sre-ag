#!/usr/bin/env python3
"""
Sentinel Ingestion Report — HTML Report Generator

Reads the scratchpad markdown produced by invoke_ingestion_scan.py
and generates a self-contained, styled HTML report.

Usage:
    python3 generate_html_report.py <scratchpad_path> [--output-dir reports/sentinel/]
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
    '🟣': ('<span class="badge bg-purple">', '</span>'),
    '⬜': ('<span class="badge bg-gray">', '</span>'),
    '⬛': ('<span class="badge bg-dark">', '</span>'),
    '✅': ('<span class="badge bg-green">\u2713</span>', ''),
    '❌': ('<span class="badge bg-red">\u2717</span>', ''),
    '⚠️': ('<span class="badge bg-orange">\u26a0</span>', ''),
    '🔥': ('<span class="badge bg-red">\U0001f525</span>', ''),
    '📊': ('<span class="badge bg-blue">\U0001f4ca</span>', ''),
    '💤': ('<span class="badge bg-gray">\U0001f4a4</span>', ''),
    '🛡️': ('<span class="badge bg-blue">\U0001f6e1\ufe0f</span>', ''),
    '❗': ('<span class="badge bg-red">\u2757</span>', ''),
    '📕': ('<span class="badge bg-orange">\U0001f4d5</span>', ''),
    '❓': ('<span class="badge bg-gray">\u2753</span>', ''),
    '🔒': ('<span class="badge bg-blue">\U0001f512</span>', ''),
    '⚙️': ('<span class="badge bg-gray">\u2699\ufe0f</span>', ''),
    '📡': ('<span class="badge bg-cyan">\U0001f4e1</span>', ''),
    '⏰': ('<span class="badge bg-yellow">\u23f0</span>', ''),
    '📬': ('<span class="badge bg-green">\U0001f4ec</span>', ''),
    '📝': ('<span class="badge bg-gray">\U0001f4dd</span>', ''),
}


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

        if stripped.startswith('## ') and not stripped.startswith('## #'):
            current_h2 = stripped[3:].strip()
            data.setdefault(current_h2, {'_kv': {}, '_lines': [], '_sub': {}})
            current_h3 = None
            current_h4 = None
            continue

        if stripped.startswith('### ') and current_h2:
            current_h3 = stripped[4:].strip()
            data[current_h2]['_sub'].setdefault(current_h3, {'_kv': {}, '_lines': [], '_sub': {}})
            current_h4 = None
            continue

        if stripped.startswith('#### ') and current_h2 and current_h3:
            current_h4 = stripped[5:].strip()
            data[current_h2]['_sub'][current_h3]['_sub'].setdefault(current_h4, [])
            continue

        if not current_h2:
            continue

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


def get_pre_lines(data: dict, subsection: str) -> list[str]:
    """Shortcut: get lines from a PRERENDERED subsection."""
    return get_sub_lines(data, 'PRERENDERED', subsection)


def get_pre_h4(data: dict, subsection: str) -> dict:
    """Get H4 sub-sections under a PRERENDERED subsection."""
    return (data.get('PRERENDERED', {}).get('_sub', {})
            .get(subsection, {}).get('_sub', {}))


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
        if all(re.match(r'^[-:]+$', c) for c in cells if c):
            continue
        rows.append(cells)

    if not rows:
        return ''

    cls = f' class="{table_class}"' if table_class else ''
    out = [f'<table{cls}>']

    out.append('<thead><tr>')
    for cell in rows[0]:
        out.append(f'<th>{_convert_emoji(html_mod.escape(cell))}</th>')
    out.append('</tr></thead>')

    out.append('<tbody>')
    for row in rows[1:]:
        is_total = any('TOTAL' in c.upper() or '**' in c for c in row)
        cls_row = ' class="total-row"' if is_total else ''
        out.append(f'<tr{cls_row}>')
        for cell in row:
            cell_clean = cell.replace('**', '')
            out.append(f'<td>{_convert_emoji(html_mod.escape(cell_clean))}</td>')
        out.append('</tr>')
    out.append('</tbody></table>')

    return '\n'.join(out)


def collect_md_tables(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Collect markdown tables with their preceding header."""
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
        else:
            if current_table and stripped and not stripped.startswith('<!--'):
                tables.append((current_header, current_table))
                current_table = []
                if not stripped.startswith('#'):
                    current_header = ''

    if current_table:
        tables.append((current_header, current_table))

    return tables


# ═══════════════════════════════════════════════════════════════════
# CSS — Dark theme matching the MITRE report style
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

/* Metrics row */
.metrics{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:10px;margin-bottom:16px}
.metric{background:#1c2836;border-radius:6px;padding:14px;text-align:center;border-top:3px solid #0078d4}
.metric .mv{font-size:1.5em;font-weight:700;color:white}.metric .ml{font-size:0.8em;color:#aaa;margin-top:2px}

/* Sections */
.section{background:#1c2836;border-radius:6px;padding:16px 20px;margin-bottom:14px;border-left:3px solid #0078d4}
.section h2{font-size:1.2em;color:#00b7c3;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid #2a3a4a}
.section h3{font-size:1.05em;color:#e0e0e0;margin:12px 0 8px}
.section h4{font-size:0.95em;color:#aaa;margin:10px 0 6px}
.section p,.section li{color:#c0c0c0;margin:4px 0}
.section ul{padding-left:20px}

/* Code blocks (for CostWaterfall + DailyChart) */
.section pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:14px;font-family:'Cascadia Code','Consolas',monospace;font-size:12px;line-height:1.45;color:#e0e0e0;overflow-x:auto;margin:8px 0 12px;white-space:pre}

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
.bg-green{background:#2ecc71;color:#1a1a1a}.bg-purple{background:#9b59b6;color:white}
.bg-gray{background:#555;color:#ddd}.bg-dark{background:#333;color:#aaa}
.bg-cyan{background:#00b7c3;color:#1a1a1a}

/* Collapsible */
details{margin:6px 0}
details summary{cursor:pointer;font-weight:600;color:#00b7c3;padding:6px 0;user-select:none}
details summary:hover{color:#00d4e0}
details[open] summary{margin-bottom:8px}

/* Legend */
.legend{font-size:0.85em;color:#888;margin:6px 0 10px;padding:6px 10px;background:#0d1117;border-radius:4px;border:1px solid #1f2f3f}

/* Footer */
.ftr{background:#1c2836;padding:12px 24px;text-align:center;font-size:0.8em;color:#555;border-top:1px solid #2a3a4a;border-radius:0 0 8px 8px}

/* Responsive */
@media(max-width:900px){.metrics{grid-template-columns:repeat(2,1fr)}}
@media print{body{background:white;color:#222}.ctr{box-shadow:none}th{background:#eee;color:#222}td{border-color:#ddd}
.wm{display:none}.section{background:#f9f9f9;border-left-color:#0078d4}pre{background:#f5f5f5;color:#222}}
"""


# ═══════════════════════════════════════════════════════════════════
# RENDERING HELPERS
# ═══════════════════════════════════════════════════════════════════

def render_metrics(data: dict) -> str:
    """Render KPI metric cards from PHASE_1 Metrics."""
    phase1_sections = {
        'PHASE_1 \u2014 Usage Summary',
        'PHASE_1 — Usage Summary',
    }
    kv = {}
    for key in phase1_sections:
        sub = data.get(key, {}).get('_sub', {}).get('Metrics', {})
        if sub.get('_kv'):
            kv = sub['_kv']
            break

    if not kv:
        return ''

    items = [
        (kv.get('AvgDailyGB', '—'), 'Avg Daily (GB)', '#0078d4'),
        (kv.get('TotalGB', '—'), f'Total Ingestion (GB)', '#3498db'),
        (kv.get('BillableGB', '—'), 'Billable (GB)', '#f39c12'),
        (kv.get('NonBillableGB', '—'), 'Non-Billable (GB)', '#2ecc71'),
        (kv.get('BillableTables', '—'), 'Billable Tables', '#00b7c3'),
        (kv.get('TotalTables', '—'), 'Total Tables', '#9b59b6'),
    ]

    peak_gb = kv.get('PeakGB', '')
    peak_date = kv.get('PeakDate', '')
    if peak_gb:
        items.append((peak_gb, f'Peak ({peak_date})', '#e74c3c'))

    min_gb = kv.get('MinGB', '')
    min_date = kv.get('MinDate', '')
    if min_gb:
        items.append((min_gb, f'Min ({min_date})', '#2ecc71'))

    html_parts = ['<div class="metrics">']
    for val, label, color in items:
        html_parts.append(f'''<div class="metric" style="border-top-color:{color}">
            <div class="mv" style="color:{color}">{html_mod.escape(str(val))}</div>
            <div class="ml">{html_mod.escape(label)}</div>
        </div>''')
    html_parts.append('</div>')
    return '\n'.join(html_parts)


def render_prerendered_block(data: dict, block_name: str, title: str,
                             icon: str = '\U0001f4ca', collapsible: bool = False) -> str:
    """Render a PRERENDERED subsection as an HTML section with tables."""
    pre_lines = get_pre_lines(data, block_name)
    h4_subs = get_pre_h4(data, block_name)

    if not pre_lines and not h4_subs:
        return ''

    # Check for EMPTY/NONE/UNAVAILABLE
    stripped_all = ' '.join(l.strip() for l in pre_lines if l.strip() and not l.strip().startswith('<!--'))
    if stripped_all in ('EMPTY', 'NONE', 'UNAVAILABLE') and not h4_subs:
        return ''

    parts = [f'<div class="section"><h2>{icon} {html_mod.escape(title)}</h2>']

    # Separate table lines from non-table content
    tbl_lines = [l for l in pre_lines if l.strip().startswith('|')]
    non_tbl = [l.strip() for l in pre_lines
               if l.strip() and not l.strip().startswith('|') and not l.strip().startswith('<!--')]

    # Code blocks (CostWaterfall, DailyChart)
    in_code = False
    code_buf: list[str] = []
    other_lines: list[str] = []
    for l in pre_lines:
        s = l.strip()
        if s.startswith('```'):
            if in_code:
                parts.append(f'<pre>{html_mod.escape(chr(10).join(code_buf))}</pre>')
                code_buf = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_buf.append(l.rstrip())
        elif s.startswith('|'):
            pass  # handled separately
        elif s and not s.startswith('<!--'):
            other_lines.append(s)
    if in_code and code_buf:
        parts.append(f'<pre>{html_mod.escape(chr(10).join(code_buf))}</pre>')

    # Markdown tables from main lines
    if tbl_lines:
        parts.append(md_table_to_html(tbl_lines))

    # Non-table, non-code content (legends, notes)
    for o in other_lines:
        if o.startswith('**') and o.endswith('**'):
            parts.append(f'<p><strong>{_convert_emoji(html_mod.escape(o.strip("*")))}</strong></p>')
        elif o.startswith('**'):
            parts.append(f'<p>{_convert_emoji(html_mod.escape(o))}</p>')
        elif o.startswith('*') and o.endswith('*'):
            parts.append(f'<p><em>{_convert_emoji(html_mod.escape(o.strip("*")))}</em></p>')
        elif '·' in o or '—' in o:
            parts.append(f'<div class="legend">{_convert_emoji(html_mod.escape(o))}</div>')
        elif o.startswith('>'):
            parts.append(f'<blockquote style="border-left:3px solid #f39c12;padding:8px 12px;margin:8px 0;color:#c0c0c0;background:#1a2532">{_convert_emoji(html_mod.escape(o.lstrip("> ")))}</blockquote>')
        else:
            parts.append(f'<p>{_convert_emoji(html_mod.escape(o))}</p>')

    # H4 sub-sections (e.g. Migration sub-tables, HealthAlerts sub-sections)
    for h4_name, h4_lines in h4_subs.items():
        safe_name = _convert_emoji(html_mod.escape(h4_name))
        if collapsible:
            parts.append(f'<details><summary>{safe_name}</summary>')
        else:
            parts.append(f'<h3>{safe_name}</h3>')

        tbl = [l for l in h4_lines if l.strip().startswith('|')]
        if tbl:
            parts.append(md_table_to_html(tbl))

        other = [l.strip() for l in h4_lines
                 if l.strip() and not l.strip().startswith('|') and not l.strip().startswith('<!--')]
        for o in other:
            if o.startswith('*') and not o.startswith('**'):
                parts.append(f'<p><em>{_convert_emoji(html_mod.escape(o.strip("*")))}</em></p>')
            else:
                parts.append(f'<p>{_convert_emoji(html_mod.escape(o))}</p>')

        if collapsible:
            parts.append('</details>')

    parts.append('</div>')
    return '\n'.join(parts)


def render_phase_kv_section(data: dict, phase_name: str, sub_name: str,
                            title: str, icon: str = '\U0001f4ca') -> str:
    """Render a Phase subsection with key-value data as a small table."""
    phase_keys = [k for k in data if phase_name in k]
    kv = {}
    for pk in phase_keys:
        sub = data[pk].get('_sub', {}).get(sub_name, {})
        if sub.get('_kv'):
            kv = sub['_kv']
            break

    if not kv:
        return ''

    parts = [f'<div class="section"><h2>{icon} {html_mod.escape(title)}</h2>']
    parts.append('<table>')
    parts.append('<thead><tr><th>Metric</th><th>Value</th></tr></thead>')
    parts.append('<tbody>')
    for k, v in kv.items():
        parts.append(f'<tr><td>{html_mod.escape(k)}</td><td>{_convert_emoji(html_mod.escape(v))}</td></tr>')
    parts.append('</tbody></table>')
    parts.append('</div>')
    return '\n'.join(parts)


# ═══════════════════════════════════════════════════════════════════
# HTML ASSEMBLY
# ═══════════════════════════════════════════════════════════════════

def render_html(data: dict) -> str:
    """Render full HTML report from parsed scratchpad data."""
    meta = data.get('META', {}).get('_kv', {})
    workspace = meta.get('Workspace', 'Unknown')
    ws_id = meta.get('WorkspaceId', '')
    days = meta.get('Days', '30')
    report_period = meta.get('ReportPeriod', meta.get('Period', ''))
    generated = meta.get('Generated', datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
    phases = meta.get('Phases', '1,2,3,4,5')
    elapsed = meta.get('ExecutionTime', '')
    query_count = meta.get('QueryCount', '')

    safe_ws = html_mod.escape(workspace)

    # Build each section
    metrics_html = render_metrics(data)

    cost_html = render_prerendered_block(
        data, 'CostWaterfall', '\U0001f4b0 Cost Waterfall')

    posture_html = render_prerendered_block(
        data, 'DetectionPosture', '\U0001f6e1\ufe0f Detection Posture')

    top_tables_html = render_prerendered_block(
        data, 'TopTables', '\U0001f4ca Top Tables by Volume')

    daily_html = render_prerendered_block(
        data, 'DailyChart', '\U0001f4c8 Daily Ingestion Trend')

    anomaly_html = render_prerendered_block(
        data, 'AnomalyTable', '\u26a0\ufe0f Anomaly Detection')

    crossref_html = render_prerendered_block(
        data, 'CrossReference', '\U0001f50d Detection Coverage — Table Cross-Reference')

    se_computer_html = render_prerendered_block(
        data, 'SE_Computer', '\U0001f5a5\ufe0f SecurityEvent — By Computer')

    se_eventid_html = render_prerendered_block(
        data, 'SE_EventID', '\U0001f50e SecurityEvent — By EventID')

    syslog_host_html = render_prerendered_block(
        data, 'SyslogHost', '\U0001f4e1 Syslog — By Source Host')

    syslog_fac_html = render_prerendered_block(
        data, 'SyslogFacility', '\U0001f512 Syslog — By Facility')

    syslog_facsev_html = render_prerendered_block(
        data, 'SyslogFacSev', '\U0001f512 Syslog — Facility \u00d7 Severity',
        collapsible=False)

    syslog_proc_html = render_prerendered_block(
        data, 'SyslogProcess', '\u2699\ufe0f Syslog — By Process')

    csl_vendor_html = render_prerendered_block(
        data, 'CSL_Vendor', '\U0001f310 CommonSecurityLog — By Vendor')

    csl_activity_html = render_prerendered_block(
        data, 'CSL_Activity', '\U0001f4cb CommonSecurityLog — By Activity')

    migration_html = render_prerendered_block(
        data, 'Migration', '\U0001f504 Data Lake Migration Candidates',
        collapsible=True)

    health_html = render_prerendered_block(
        data, 'HealthAlerts', '\U0001f3e5 Rule Health & Alerts')

    benefit_html = render_prerendered_block(
        data, 'BenefitSummary', '\U0001f4b5 License Benefit Summary')

    dfsp2_html = render_prerendered_block(
        data, 'DfSP2Detail', '\U0001f6e1\ufe0f Defender for Servers P2 — Pool Detail')

    e5_html = render_prerendered_block(
        data, 'E5Tables', '\U0001f4e6 E5 / Defender XDR Eligible Tables')

    # Phase key-value sections
    health_kv = render_phase_kv_section(data, 'PHASE_4', 'Health',
                                        '\u2764\ufe0f Rule Health Metrics')
    cross_val = render_phase_kv_section(data, 'PHASE_4', 'CrossValidation',
                                         '\U0001f50d Cross-Validation (Q11 vs Q9)')

    # Appendix
    query_table_html = render_prerendered_block(
        data, 'QueryTable', '\U0001f4d6 Query Reference')

    footer_lines = get_pre_lines(data, 'Footer')
    footer_text = ' '.join(l.strip().strip('*') for l in footer_lines if l.strip())
    if not footer_text:
        footer_text = f'Report generated {generated}'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Sentinel Ingestion Report \u2014 {safe_ws}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wm">
    <div>\U0001f4ca <strong>SENTINEL INGESTION REPORT</strong></div>
    <div style="font-size:12px;">Generated {html_mod.escape(generated)} | Lookback {html_mod.escape(days)}d | {html_mod.escape(query_count)} queries in {html_mod.escape(elapsed)}</div>
</div>
<div class="ctr" style="margin-top:50px;">
    <div class="hdr">
        <div>
            <h1>\U0001f4ca Sentinel Ingestion Report</h1>
            <div class="meta">
                <strong>Workspace:</strong> {safe_ws} &nbsp;|&nbsp;
                <strong>Period:</strong> {html_mod.escape(report_period)} &nbsp;|&nbsp;
                <strong>Lookback:</strong> {html_mod.escape(days)} days &nbsp;|&nbsp;
                <strong>Phases:</strong> {html_mod.escape(phases)}
            </div>
        </div>
    </div>
    <div class="content">
        <div class="section"><h2>\U0001f4ca \u00a71 Executive Summary</h2>
            {metrics_html}
        </div>
        {cost_html}
        {posture_html}
        {top_tables_html}
        {daily_html}
        {anomaly_html}
        {crossref_html}
        {se_computer_html}
        {se_eventid_html}
        {syslog_host_html}
        {syslog_fac_html}
        {syslog_facsev_html}
        {syslog_proc_html}
        {csl_vendor_html}
        {csl_activity_html}
        {health_html}
        {health_kv}
        {cross_val}
        {benefit_html}
        {dfsp2_html}
        {e5_html}
        {migration_html}
        {query_table_html}
    </div>
    <div class="ftr">
        <strong>Sentinel Ingestion Report</strong> \u2014 {safe_ws} \u2014 {html_mod.escape(generated)}<br>
        <span style="color:#666;">{html_mod.escape(footer_text)}</span>
    </div>
</div>
</body>
</html>'''


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Sentinel Ingestion Report \u2014 HTML Generator')
    parser.add_argument('scratchpad', help='Path to scratchpad .md file')
    parser.add_argument('--output-dir', default='reports/sentinel/',
                        help='Output directory for HTML report')
    args = parser.parse_args()

    sp_path = Path(args.scratchpad)
    if not sp_path.exists():
        print(f'\u274c Scratchpad not found: {sp_path}', file=sys.stderr)
        sys.exit(1)

    text = sp_path.read_text(encoding='utf-8')
    data = parse_scratchpad(text)

    if 'META' not in data:
        print('\u274c No META section found in scratchpad \u2014 is this a valid scratchpad file?',
              file=sys.stderr)
        sys.exit(1)

    html_out = render_html(data)

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M%S')
    ws = data.get('META', {}).get('_kv', {}).get('Workspace', 'workspace').replace(' ', '_')
    outfile = outdir / f'Sentinel_Ingestion_{ws}_{ts}.html'
    outfile.write_text(html_out, encoding='utf-8')

    size_kb = round(outfile.stat().st_size / 1024, 1)
    print(f'\n\u2705 HTML report generated: {outfile} ({size_kb} KB)')


if __name__ == '__main__':
    main()
