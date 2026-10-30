"""
Incident Statistics HTML Report Generator
==========================================
Self-contained HTML report generator for SOC incident statistics.
Zero external dependencies — Python 3 stdlib only.

Usage:
    python3 generate_html_report.py <query_results.json> [--output-dir DIR] [--lookback LABEL]

Reads the same query_results.json as generate_charts.py:
    q1: Incidents by Title (Rank, Title, Severity, Total, New, Active, Closed, Tactics, Techniques)
    q2: MITRE Tactics & Techniques (Tactic, Technique, IncidentCount)
    q3: MTTA (Period, AvgMTTA, MedianMTTA, P90_MTTA, P99_MTTA, TotalIncidents)
    q4: MTTR (Period, AvgMTTR, MedianMTTR, P90_MTTR, P99_MTTR, TotalIncidents)
    q5: By Assignee (Assignee, IncidentCount)
    q6: Top 5 Users (UserName, IncidentCount)
    q7: Top 5 Devices (DeviceName, IncidentCount)

Generates a styled HTML report with dark theme, inline CSS visualizations.
"""

import json
import sys
import os
import re
import socket
from datetime import datetime, timezone, timedelta
from html import escape

# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

def get_user():
    try: return os.getlogin().upper()
    except Exception: return os.environ.get('USERNAME', 'AGENT').upper()

def get_host():
    try: return socket.gethostname().upper()
    except Exception: return 'UNKNOWN'

def esc(v): return escape(str(v)) if v else ''

def severity_color(sev):
    return {'high': '#f65314', 'medium': '#ffbb00', 'low': '#7cbb00', 'informational': '#00a1f1'}.get((sev or '').lower(), '#737373')

def severity_badge(sev):
    c = severity_color(sev)
    tc = '#1a1a1a' if (sev or '').lower() in ('medium', 'low') else 'white'
    return f'<span style="background:{c};color:{tc};padding:2px 8px;border-radius:3px;font-size:0.85em;font-weight:600;">{esc(sev)}</span>'

def tactic_pill(tactic):
    colors = {
        'initialaccess': '#e74c3c', 'execution': '#e67e22', 'persistence': '#f1c40f',
        'privilegeescalation': '#9b59b6', 'defenseevasion': '#1abc9c', 'credentialaccess': '#e74c3c',
        'discovery': '#3498db', 'lateralmovement': '#2ecc71', 'collection': '#e67e22',
        'exfiltration': '#c0392b', 'commandandcontrol': '#8e44ad', 'impact': '#c0392b',
    }
    key = re.sub(r'[^a-z]', '', (tactic or '').lower())
    bg = colors.get(key, '#555')
    return f'<span style="background:{bg};color:white;padding:2px 7px;border-radius:12px;font-size:0.78em;margin:1px;">{esc(tactic)}</span>'

def bar_html(value, max_val, color, width_px=120):
    pct = (value / max_val * 100) if max_val > 0 else 0
    w = max(2, int(width_px * pct / 100))
    return f'<div style="display:flex;align-items:center;gap:6px;"><div style="background:#333;border-radius:3px;width:{width_px}px;height:14px;"><div style="background:{color};height:14px;border-radius:3px;width:{w}px;"></div></div><span style="font-weight:600;font-size:0.9em;">{value}</span></div>'

def delta_arrow(current, previous):
    if previous == 0: return ''
    d = ((current - previous) / previous) * 100
    if d < 0:
        return f'<span style="color:#7cbb00;font-weight:600;">▼ {abs(d):.0f}%</span>'
    elif d > 0:
        return f'<span style="color:#f65314;font-weight:600;">▲ {d:.0f}%</span>'
    return '<span style="color:#737373;">— 0%</span>'


# ═══════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════

class StatsReportGenerator:
    def __init__(self, data, lookback):
        self.data = data
        self.lookback = lookback
        self.q1 = data.get('q1', [])
        self.q2 = data.get('q2', [])
        self.q3 = data.get('q3', [])
        self.q4 = data.get('q4', [])
        self.q5 = data.get('q5', [])
        self.q6 = data.get('q6', [])
        self.q7 = data.get('q7', [])

    # ─── Key Metrics ──────────────────────────────────────────────
    def _metrics(self):
        total = sum(int(r.get('Total', 0)) for r in self.q1)
        high = sum(int(r.get('Total', 0)) for r in self.q1 if (r.get('Severity', '') or '').lower() == 'high')
        closed = sum(int(r.get('Closed', 0)) for r in self.q1)
        active = sum(int(r.get('Active', 0)) for r in self.q1)
        new = sum(int(r.get('New', 0)) for r in self.q1)
        unique_titles = len(self.q1)
        # MTTA/MTTR current
        mtta_cur = next((r for r in self.q3 if r.get('Period') == 'Current'), None)
        mttr_cur = next((r for r in self.q4 if r.get('Period') == 'Current'), None)
        mtta_val = f"{float(mtta_cur['AvgMTTA']):.1f}h" if mtta_cur else '—'
        mttr_val = f"{float(mttr_cur['AvgMTTR']):.1f}h" if mttr_cur else '—'

        def mc(v, l, c='#00a1f1'):
            return f'<div class="metric" style="background:linear-gradient(135deg,{c},{c}cc);"><div class="mv">{v}</div><div class="ml">{l}</div></div>'

        return f'''<div class="section"><h2>📊 Key Metrics</h2><div class="metrics">
{mc(total, 'Total Incidents')}{mc(high, 'High Severity', '#f65314' if high > 0 else '#7cbb00')}
{mc(closed, 'Closed', '#7cbb00')}{mc(active + new, 'Open (Active+New)', '#ffbb00' if (active+new) > 0 else '#7cbb00')}
{mc(mtta_val, 'Avg MTTA', '#3498db')}{mc(mttr_val, 'Avg MTTR', '#9b59b6')}
</div></div>'''

    # ─── Q1: Incidents by Title ───────────────────────────────────
    def _q1_table(self):
        if not self.q1:
            return '<div class="section"><h2>📋 Incidents by Title</h2><p style="color:#7cbb00;">✅ No incidents in period</p></div>'
        max_total = max(int(r.get('Total', 0)) for r in self.q1) or 1
        rows = ''
        for r in self.q1:
            total = int(r.get('Total', 0))
            new = int(r.get('New', 0))
            active = int(r.get('Active', 0))
            closed = int(r.get('Closed', 0))
            sev = r.get('Severity', '')
            title = r.get('Title', '?')
            tactics = r.get('Tactics', '')
            # Heatmap cell colors
            t_int = min(255, int(total / max_total * 200)) if max_total > 0 else 0
            t_bg = f'rgba(231,76,60,{t_int/255:.2f})'
            rows += f'''<tr>
<td style="text-align:center;color:#737373;">{r.get("Rank", "")}</td>
<td style="max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{esc(title)}</td>
<td style="text-align:center;">{severity_badge(sev)}</td>
<td style="text-align:center;background:{t_bg};font-weight:600;">{total}</td>
<td style="text-align:center;">{new or ""}</td>
<td style="text-align:center;">{active or ""}</td>
<td style="text-align:center;">{closed or ""}</td>
<td style="font-size:0.8em;">{esc(tactics)}</td></tr>'''
        return f'''<div class="section"><h2>📋 Incidents by Title ({len(self.q1)} types)</h2>
<table><thead><tr><th style="width:35px;">#</th><th>Title</th><th style="text-align:center;">Severity</th>
<th style="text-align:center;color:#e74c3c;">Total</th><th style="text-align:center;color:#e67e22;">New</th>
<th style="text-align:center;color:#3498db;">Active</th><th style="text-align:center;color:#27ae60;">Closed</th>
<th>Tactics</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── Q2: MITRE ────────────────────────────────────────────────
    def _q2_mitre(self):
        if not self.q2:
            return '<div class="section"><h2>🎯 MITRE ATT&CK</h2><p style="color:#ffbb00;">⚠️ No TruePositive incidents with MITRE mapping</p></div>'
        tactics = sorted(set(r.get('Tactic', '') for r in self.q2))
        techniques = sorted(set(r.get('Technique', '') for r in self.q2))
        matrix = {}
        max_count = 0
        for r in self.q2:
            key = (r.get('Tactic', ''), r.get('Technique', ''))
            val = int(r.get('IncidentCount', 0))
            matrix[key] = val
            if val > max_count: max_count = val
        # Build HTML table
        th = '<th style="font-size:0.8em;writing-mode:vertical-rl;text-orientation:mixed;min-width:30px;padding:4px;">—</th>'
        th = ''.join(f'<th style="font-size:0.75em;min-width:35px;padding:4px;text-align:center;">{esc(t)}</th>' for t in techniques)
        rows = ''
        for tac in tactics:
            cells = ''
            for tech in techniques:
                val = matrix.get((tac, tech), 0)
                if val > 0:
                    intensity = min(1.0, val / max(max_count, 1))
                    bg = f'rgba(231,76,60,{intensity:.2f})'
                    tc = 'white' if intensity > 0.5 else '#e0e0e0'
                    cells += f'<td style="text-align:center;background:{bg};color:{tc};font-weight:600;font-size:0.9em;">{val}</td>'
                else:
                    cells += '<td style="text-align:center;color:#555;">·</td>'
            tac_pill = tactic_pill(tac)
            rows += f'<tr><td style="white-space:nowrap;">{tac_pill}</td>{cells}</tr>'
        return f'''<div class="section"><h2>🎯 MITRE ATT&CK — TruePositive Incidents</h2>
<div style="overflow-x:auto;"><table style="font-size:0.9em;"><thead><tr><th>Tactic</th>{th}</tr></thead><tbody>{rows}</tbody></table></div></div>'''

    # ─── Q3/Q4: MTTA/MTTR ────────────────────────────────────────
    def _mtta_mttr(self, q_data, prefix, title, sla, color):
        if not q_data:
            return f'<div class="section"><h2>{title}</h2><p style="color:#ffbb00;">⚠️ No data</p></div>'
        cur = next((r for r in q_data if r.get('Period') == 'Current'), None)
        prev = next((r for r in q_data if r.get('Period') == 'Previous'), None)
        avg_k, med_k, p90_k, p99_k = f'Avg{prefix}', f'Median{prefix}', f'P90_{prefix}', f'P99_{prefix}'
        metrics_names = ['Average', 'Median (P50)', 'P90', 'P99']
        keys = [avg_k, med_k, p90_k, p99_k]
        rows = ''
        max_val = 0
        for name, key in zip(metrics_names, keys):
            c_val = float(cur[key]) if cur else None
            p_val = float(prev[key]) if prev else None
            if c_val is not None and c_val > max_val: max_val = c_val
            if p_val is not None and p_val > max_val: max_val = p_val
        max_val = max(max_val, sla) or 1
        for name, key in zip(metrics_names, keys):
            c_val = float(cur[key]) if cur else None
            p_val = float(prev[key]) if prev else None
            c_html = f'{c_val:.2f}h' if c_val is not None else '—'
            p_html = f'{p_val:.2f}h' if p_val is not None else '—'
            delta = delta_arrow(c_val, p_val) if c_val is not None and p_val is not None else ''
            c_bar = bar_html(round(c_val, 2), max_val, color, 100) if c_val is not None else '—'
            sla_warn = f' <span style="color:#f65314;">⚠ &gt;SLA</span>' if c_val is not None and c_val > sla else ''
            rows += f'<tr><td style="font-weight:600;">{name}</td><td style="text-align:right;">{p_html}</td><td>{c_bar}{sla_warn}</td><td style="text-align:center;">{delta}</td></tr>'
        inc_str = ''
        if cur: inc_str += f'Current: {cur.get("TotalIncidents", "?")} incidents'
        if prev: inc_str += f' | Previous: {prev.get("TotalIncidents", "?")} incidents'
        return f'''<div class="section"><h2>{title}</h2>
<div style="font-size:0.85em;color:#b0b0b0;margin-bottom:8px;">{inc_str} | SLA Target: {sla}h</div>
<table><thead><tr><th>Metric</th><th style="text-align:right;">Previous</th><th>Current</th><th style="text-align:center;">Δ</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── Q5: Assignees ────────────────────────────────────────────
    def _q5_assignees(self):
        if not self.q5:
            return '<div class="section"><h2>👤 Incidents by Assignee</h2><p style="color:#ffbb00;">⚠️ No data</p></div>'
        total = sum(int(r.get('IncidentCount', 0)) for r in self.q5)
        max_c = max(int(r.get('IncidentCount', 0)) for r in self.q5) or 1
        rows = ''
        for r in self.q5:
            name = r.get('Assignee', '?')
            cnt = int(r.get('IncidentCount', 0))
            pct = cnt / total * 100 if total > 0 else 0
            c = '#bdc3c7' if name == 'Unassigned' else '#3498db'
            rows += f'<tr><td>{esc(name)}</td><td>{bar_html(cnt, max_c, c, 150)}</td><td style="text-align:right;font-size:0.85em;color:#b0b0b0;">{pct:.1f}%</td></tr>'
        return f'''<div class="section"><h2>👤 Incidents by Assignee</h2>
<table><thead><tr><th>Assignee</th><th>Count</th><th style="text-align:right;">%</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── Q6/Q7: Top 5 ─────────────────────────────────────────────
    def _top5(self, q_data, name_key, title, icon, colors):
        if not q_data:
            return f'<div class="section"><h2>{icon} {title}</h2><p style="color:#ffbb00;">⚠️ No data</p></div>'
        total = sum(int(r.get('IncidentCount', 0)) for r in q_data)
        max_c = max(int(r.get('IncidentCount', 0)) for r in q_data) or 1
        rows = ''
        for i, r in enumerate(q_data[:5]):
            name = r.get(name_key, '?')
            cnt = int(r.get('IncidentCount', 0))
            pct = cnt / total * 100 if total > 0 else 0
            c = colors[i % len(colors)]
            rows += f'<tr><td style="text-align:center;color:#737373;">{i+1}</td><td>{esc(name)}</td><td>{bar_html(cnt, max_c, c, 130)}</td><td style="text-align:right;font-size:0.85em;color:#b0b0b0;">{pct:.1f}%</td></tr>'
        return f'''<div class="section"><h2>{icon} {title}</h2>
<table><thead><tr><th style="width:30px;">#</th><th>Name</th><th>Count</th><th style="text-align:right;">%</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── Severity Breakdown ───────────────────────────────────────
    def _severity_breakdown(self):
        if not self.q1: return ''
        sev_counts = {}
        for r in self.q1:
            s = r.get('Severity', 'Unknown')
            sev_counts[s] = sev_counts.get(s, 0) + int(r.get('Total', 0))
        total = sum(sev_counts.values()) or 1
        items = ''
        for sev in ['High', 'Medium', 'Low', 'Informational']:
            cnt = sev_counts.get(sev, 0)
            if cnt == 0: continue
            pct = cnt / total * 100
            c = severity_color(sev)
            w = max(3, int(pct))
            items += f'<div style="margin-bottom:6px;"><div style="display:flex;justify-content:space-between;font-size:0.85em;"><span>{severity_badge(sev)}</span><span style="font-weight:600;">{cnt} ({pct:.0f}%)</span></div><div style="background:#333;border-radius:3px;height:10px;margin-top:3px;"><div style="background:{c};height:10px;border-radius:3px;width:{w}%;"></div></div></div>'
        return f'<div class="section"><h2>📊 Severity Distribution</h2>{items}</div>'

    # ─── Full HTML ────────────────────────────────────────────────
    def generate(self, output_path):
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        total = sum(int(r.get('Total', 0)) for r in self.q1)
        high = sum(int(r.get('Total', 0)) for r in self.q1 if (r.get('Severity', '') or '').lower() == 'high')
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        left = '\n'.join(filter(None, [
            self._metrics(), self._severity_breakdown(),
            self._mtta_mttr(self.q3, 'MTTA', '⏱️ MTTA — Mean Time To Acknowledge', 4.0, '#3498db'),
            self._mtta_mttr(self.q4, 'MTTR', '⏱️ MTTR — Mean Time To Resolve', 12.0, '#9b59b6'),
            self._q5_assignees()]))
        right = '\n'.join(filter(None, [
            self._q1_table(), self._q2_mitre(),
            self._top5(self.q6, 'UserName', 'Top 5 Affected Users', '👤', ['#e74c3c', '#9b59b6', '#e67e22', '#2ecc71', '#3498db']),
            self._top5(self.q7, 'DeviceName', 'Top 5 Affected Devices', '💻', ['#e74c3c', '#9b59b6', '#e67e22', '#2ecc71', '#3498db'])]))

        html = f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Incident Statistics — Last {esc(self.lookback)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,sans-serif;font-size:13.5px;line-height:1.4;color:#e0e0e0;background:#1a1a1a;padding:12px}}
.ctr{{max-width:1600px;margin:0 auto;background:#1e1e1e;border-radius:7px;box-shadow:0 4px 20px rgba(0,0,0,0.5)}}
.wm{{position:fixed;top:0;left:0;right:0;background:linear-gradient(135deg,#dc3545,#c82333);color:white;padding:10px 20px;z-index:9999;box-shadow:0 2px 8px rgba(0,0,0,0.4);font-size:13px;font-weight:600;border-bottom:2px solid #ff6b6b;display:flex;justify-content:space-between;align-items:center}}
.hdr{{background:linear-gradient(135deg,#00a1f1,#0078d4);color:white;padding:18px 24px;display:flex;justify-content:space-between;align-items:center}}
.hdr h1{{font-size:1.7em;margin:0}}
.hdr .meta{{font-size:0.85em;text-align:right}}
.cnt{{display:grid;grid-template-columns:1.7fr 3.3fr;gap:12px;padding:12px}}
.section{{background:#252525;border-radius:5px;padding:14px;border-left:3px solid #00a1f1}}
.section h2{{font-size:1.15em;color:#00a1f1;margin-bottom:10px;padding-bottom:5px;border-bottom:1px solid #3a3a3a}}
.metrics{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}}
.metric{{padding:10px;border-radius:5px;text-align:center}}
.mv{{font-size:1.8em;font-weight:bold;color:white}}.ml{{font-size:0.85em;color:rgba(255,255,255,0.9);margin-top:2px}}
table{{width:100%;border-collapse:collapse;font-size:0.92em}}
th{{background:#2a2a2a;color:#00a1f1;padding:7px 10px;text-align:left;font-weight:600;border-bottom:2px solid #3a3a3a}}
td{{padding:5px 10px;border-bottom:1px solid #2a2a2a}}tr:hover{{background:#2a2a2a}}
.l{{color:#b0b0b0;font-weight:500}}
.ftr{{background:#252525;padding:10px 20px;text-align:center;font-size:0.85em;color:#737373;border-top:1px solid #3a3a3a}}
</style></head><body>
<div class="wm"><div>🔒 <strong>CONFIDENTIAL — SOC INCIDENT STATISTICS</strong></div><div style="font-size:12px;">Generated by <strong>{get_user()}</strong> on <strong>{get_host()}</strong> | {now_str}</div></div>
<div class="ctr" style="margin-top:50px;">
  <div class="hdr"><div><h1>📊 Incident Statistics <span style="color:rgba(255,255,255,0.5);font-weight:300;">|</span> <span style="font-size:0.6em;font-weight:400;opacity:0.9;">Last {esc(self.lookback)}</span></h1>
    <div style="font-size:1em;opacity:0.9;margin-top:4px;">
      <span style="background:rgba(255,255,255,0.2);padding:3px 8px;border-radius:10px;font-size:0.8em;margin-right:6px;">🔔 {total} incidents</span>
      <span style="background:{'#f65314' if high > 0 else 'rgba(255,255,255,0.2)'};padding:3px 8px;border-radius:10px;font-size:0.8em;margin-right:6px;">🔴 {high} high</span>
      <span style="background:rgba(255,255,255,0.2);padding:3px 8px;border-radius:10px;font-size:0.8em;">{len(self.q1)} types</span>
    </div></div>
    <div class="meta"><div><strong>Generated:</strong> {now_str}</div><div><strong>Period:</strong> Last {esc(self.lookback)}</div></div></div>
  <div class="cnt"><div style="display:flex;flex-direction:column;gap:12px;">{left}</div><div style="display:flex;flex-direction:column;gap:12px;">{right}</div></div>
  <div class="ftr"><strong style="color:#f65314;">⚠️ CONFIDENTIAL</strong> — SOC Incident Statistics | Last {esc(self.lookback)} | {now_str}</div>
</div></body></html>'''

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return output_path


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_html_report.py <query_results.json> [--output-dir DIR] [--lookback LABEL]")
        sys.exit(1)

    json_file = sys.argv[1]
    output_dir = '.'
    lookback = '90d'
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--output-dir' and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]; i += 2
        elif sys.argv[i] == '--lookback' and i + 1 < len(sys.argv):
            lookback = sys.argv[i + 1]; i += 2
        else:
            i += 1

    with open(json_file, encoding='utf-8') as f:
        data = json.load(f)

    ts = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    output_path = os.path.join(output_dir, f'Incident_Statistics_{lookback}_{ts}.html')

    gen = StatsReportGenerator(data, lookback)
    path = gen.generate(output_path)
    print(f"✅ Report: {path}")


if __name__ == '__main__':
    main()
