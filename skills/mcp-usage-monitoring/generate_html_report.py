"""
MCP Usage Monitoring HTML Report Generator
============================================
Self-contained HTML report generator for MCP Server usage monitoring.
Zero external dependencies — Python 3 stdlib only.

Usage:
    python3 generate_html_report.py <mcp_usage_report.json> [--output-dir DIR]

Reads the JSON export from mcp-usage-monitoring and generates a styled HTML report.
Covers: Graph MCP, Sentinel Triage MCP, Data Lake MCP, Azure MCP, workspace governance,
        cross-server user analysis, MCP Usage Score, security assessment.
"""

import json
import sys
import os
import socket
from datetime import datetime, timezone
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
    return {'critical': '#dc3545', 'high': '#f65314', 'medium': '#ffbb00',
            'low': '#7cbb00', 'informational': '#00a1f1', 'healthy': '#7cbb00',
            'elevated': '#ffbb00', 'concerning': '#f65314'}.get((sev or '').lower(), '#737373')

def score_rating(score):
    if score <= 25: return ('Healthy', '#7cbb00')
    if score <= 50: return ('Elevated', '#ffbb00')
    if score <= 75: return ('Concerning', '#f65314')
    return ('Critical', '#dc3545')

def bar_html(value, max_val, color, width_px=120):
    pct = (value / max_val * 100) if max_val > 0 else 0
    w = max(2, int(width_px * pct / 100))
    return f'<div style="display:flex;align-items:center;gap:6px;"><div style="background:#333;border-radius:3px;width:{width_px}px;height:14px;"><div style="background:{color};height:14px;border-radius:3px;width:{w}px;"></div></div><span style="font-weight:600;font-size:0.9em;">{value}</span></div>'

def pct_bar(pct, color='#00a1f1', width_px=100):
    w = max(1, int(width_px * min(pct, 100) / 100))
    return f'<div style="display:flex;align-items:center;gap:6px;"><div style="background:#333;border-radius:3px;width:{width_px}px;height:12px;"><div style="background:{color};height:12px;border-radius:3px;width:{w}px;"></div></div><span style="font-size:0.85em;">{pct:.1f}%</span></div>'

MCP_COLORS = {
    'Graph MCP': '#00a1f1',
    'Triage MCP': '#9b59b6',
    'Data Lake MCP': '#2ecc71',
    'Azure MCP/CLI': '#e67e22',
}

def server_badge(name):
    c = MCP_COLORS.get(name, '#737373')
    return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:12px;font-size:0.8em;font-weight:600;">{esc(name)}</span>'


# ═══════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════

class MCPUsageReportGenerator:
    def __init__(self, data):
        self.data = data
        self.meta = data.get('report_metadata', {})
        self.graph = data.get('graph_mcp', {})
        self.triage = data.get('triage_mcp', {})
        self.datalake = data.get('datalake_mcp', {})
        self.azure = data.get('azure_mcp', {})
        self.governance = data.get('workspace_governance', {})
        self.users = data.get('top_mcp_users', [])
        self.score = data.get('mcp_usage_score', {})
        self.assessment = data.get('security_assessment', {})
        self.recommendations = data.get('recommendations', [])
        self.daily_trend = data.get('daily_trend', [])
        self.summary = data.get('executive_summary', '')
        self.footprint = data.get('mcp_footprint', {})

    # ─── Key Metrics ──────────────────────────────────────────────
    def _kpi_cards(self):
        total = self.score.get('total_score', 0)
        rating, color = score_rating(total)
        servers = self.footprint.get('servers_detected', 0)
        total_calls = self.footprint.get('total_calls', 0)
        unique_users = self.footprint.get('unique_users', 0)
        error_rate = self.footprint.get('error_rate', 0)
        period = self.meta.get('analysis_period', '30 days')

        def mc(v, l, c='#00a1f1'):
            return f'<div class="metric" style="background:linear-gradient(135deg,{c},{c}cc);"><div class="mv">{v}</div><div class="ml">{l}</div></div>'

        err_color = '#dc3545' if error_rate > 5 else '#ffbb00' if error_rate > 1 else '#7cbb00'

        return f'''<div class="section"><h2>📊 MCP Footprint — {esc(period)}</h2><div class="metrics">
{mc(f'<span style="color:{color};font-weight:800;font-size:1.2em;">{total}/100</span><br><span style="font-size:0.6em;">{rating}</span>', 'MCP Usage Score', color)}
{mc(servers, 'MCP Servers Detected', '#9b59b6')}
{mc(f'{total_calls:,}', 'Total API Calls', '#00a1f1')}
{mc(unique_users, 'Unique Users', '#2ecc71')}
{mc(f'{error_rate:.1f}%', 'Error Rate', err_color)}
</div></div>'''

    # ─── Score Breakdown ──────────────────────────────────────────
    def _score_breakdown(self):
        total = self.score.get('total_score', 0)
        dims = self.score.get('dimensions', {})
        rating, color = score_rating(total)

        rows = ''
        dim_labels = {
            'user_diversity': ('👥 User Diversity', 20),
            'endpoint_sensitivity': ('🔒 Endpoint Sensitivity', 20),
            'error_rate': ('❌ Error Rate', 20),
            'volume_anomaly': ('📈 Volume Anomaly', 20),
            'off_hours_activity': ('🌙 Off-Hours Activity', 20),
        }
        for key, (label, max_pts) in dim_labels.items():
            d = dims.get(key, {})
            pts = d.get('score', 0)
            detail = d.get('detail', '')
            zone = d.get('zone', 'green')
            zc = {'green': '#7cbb00', 'yellow': '#ffbb00', 'red': '#dc3545'}.get(zone, '#737373')
            rows += f'''<tr>
<td>{label}</td>
<td style="text-align:center;"><span style="color:{zc};font-weight:700;">{pts}</span>/{max_pts}</td>
<td>{bar_html(pts, max_pts, zc, 100)}</td>
<td style="font-size:0.85em;color:#b0b0b0;">{esc(detail)}</td>
</tr>'''

        return f'''<div class="section"><h2>🎯 MCP Usage Score: <span style="color:{color};">{total}/100 — {rating}</span></h2>
<table><thead><tr><th>Dimension</th><th style="text-align:center;">Score</th><th>Bar</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── Daily Trend ──────────────────────────────────────────────
    def _daily_trend(self):
        if not self.daily_trend:
            return ''
        # Group by server
        servers = {}
        for row in self.daily_trend:
            srv = row.get('Server', row.get('server', 'Unknown'))
            if srv not in servers:
                servers[srv] = []
            servers[srv].append(row)

        parts = ''
        for srv, rows in servers.items():
            max_calls = max((r.get('Calls', r.get('calls', 0)) for r in rows), default=1) or 1
            color = MCP_COLORS.get(srv, '#737373')
            trend_rows = ''
            for r in rows[:14]:  # last 14 days max
                day = r.get('Day', r.get('day', ''))
                calls = r.get('Calls', r.get('calls', 0))
                errors = r.get('Errors', r.get('errors', 0))
                trend_rows += f'<tr><td style="font-size:0.85em;">{esc(day)}</td><td>{bar_html(calls, max_calls, color, 80)}</td><td style="color:{"#dc3545" if errors > 0 else "#7cbb00"};">{errors}</td></tr>'
            parts += f'<h3>{server_badge(srv)} Daily Trend</h3><table><thead><tr><th>Day</th><th>Calls</th><th>Errors</th></tr></thead><tbody>{trend_rows}</tbody></table>'

        return f'<div class="section"><h2>📈 Daily Activity Trends</h2>{parts}</div>' if parts else ''

    # ─── Graph MCP ────────────────────────────────────────────────
    def _graph_mcp(self):
        if not self.graph:
            return '<div class="section"><h2>🔵 Graph MCP Server</h2><div style="color:#ffbb00;">⚠️ No Graph MCP data available</div></div>'

        total = self.graph.get('total_calls', 0)
        unique_ep = self.graph.get('unique_endpoints', 0)
        sensitive_pct = self.graph.get('sensitive_endpoint_pct', 0)
        top_endpoints = self.graph.get('top_endpoints', [])
        callers = self.graph.get('caller_attribution', [])

        ep_rows = ''
        max_c = max((e.get('Calls', e.get('calls', 0)) for e in top_endpoints), default=1) or 1
        for ep in top_endpoints[:15]:
            calls = ep.get('Calls', ep.get('calls', 0))
            sens = ep.get('IsSensitive', ep.get('is_sensitive', False))
            name = ep.get('Endpoint', ep.get('endpoint', ''))
            users = ep.get('Users', ep.get('users', ''))
            sens_badge = '<span style="background:#dc3545;color:white;padding:1px 5px;border-radius:3px;font-size:0.75em;">SENSITIVE</span>' if sens else ''
            ep_rows += f'<tr><td style="font-family:monospace;font-size:0.85em;">{esc(name)} {sens_badge}</td><td>{bar_html(calls, max_c, "#00a1f1", 80)}</td><td style="font-size:0.85em;">{esc(users)}</td></tr>'

        caller_rows = ''
        for c in callers[:10]:
            ctype = c.get('CallerType', c.get('caller_type', ''))
            name = c.get('CallerName', c.get('caller_name', ''))
            calls = c.get('Calls', c.get('calls', 0))
            type_badge = f'<span style="background:{"#2ecc71" if ctype == "User" else "#e67e22"};color:white;padding:1px 5px;border-radius:3px;font-size:0.75em;">{esc(ctype)}</span>'
            caller_rows += f'<tr><td>{type_badge}</td><td>{esc(name)}</td><td style="font-weight:600;">{calls}</td></tr>'

        sens_color = '#dc3545' if sensitive_pct > 30 else '#ffbb00' if sensitive_pct > 0 else '#7cbb00'

        parts = f'''<div style="display:flex;gap:16px;margin-bottom:10px;flex-wrap:wrap;">
<div><strong>{total:,}</strong> API calls</div>
<div><strong>{unique_ep}</strong> unique endpoints</div>
<div>Sensitive: <span style="color:{sens_color};font-weight:700;">{sensitive_pct:.1f}%</span></div>
</div>'''
        if ep_rows: parts += f'<h3 style="color:#00a1f1;">Top Endpoints</h3><table><thead><tr><th>Endpoint</th><th>Calls</th><th>Users</th></tr></thead><tbody>{ep_rows}</tbody></table>'
        if caller_rows: parts += f'<h3 style="color:#00a1f1;margin-top:10px;">Caller Attribution</h3><table><thead><tr><th>Type</th><th>Caller</th><th>Calls</th></tr></thead><tbody>{caller_rows}</tbody></table>'

        return f'<div class="section"><h2>{server_badge("Graph MCP")} Graph MCP Server</h2>{parts}</div>'

    # ─── Sentinel Triage MCP ──────────────────────────────────────
    def _triage_mcp(self):
        if not self.triage:
            return '<div class="section"><h2>🟣 Sentinel Triage MCP</h2><div style="color:#ffbb00;">⚠️ No Triage MCP data available</div></div>'

        total = self.triage.get('total_calls', 0)
        auth_events = self.triage.get('auth_events', [])
        api_calls = self.triage.get('api_calls', [])
        users = self.triage.get('users', [])

        api_rows = ''
        max_c = max((a.get('Calls', a.get('calls', 0)) for a in api_calls), default=1) or 1
        for a in api_calls[:10]:
            endpoint = a.get('Endpoint', a.get('endpoint', ''))
            calls = a.get('Calls', a.get('calls', 0))
            api_rows += f'<tr><td style="font-family:monospace;font-size:0.85em;">{esc(endpoint)}</td><td>{bar_html(calls, max_c, "#9b59b6", 80)}</td></tr>'

        user_pills = ' '.join(f'<span style="background:#9b59b6;color:white;padding:2px 8px;border-radius:12px;font-size:0.8em;">{esc(u)}</span>' for u in users[:8])

        parts = f'<div style="margin-bottom:8px;"><strong>{total:,}</strong> API calls | Users: {user_pills if user_pills else "—"}</div>'
        if api_rows: parts += f'<table><thead><tr><th>API Endpoint</th><th>Calls</th></tr></thead><tbody>{api_rows}</tbody></table>'

        return f'<div class="section"><h2>{server_badge("Triage MCP")} Sentinel Triage MCP</h2>{parts}</div>'

    # ─── Data Lake MCP ────────────────────────────────────────────
    def _datalake_mcp(self):
        if not self.datalake:
            return '<div class="section"><h2>🟢 Data Lake MCP</h2><div style="color:#ffbb00;">⚠️ No Data Lake MCP data available</div></div>'

        mcp_queries = self.datalake.get('mcp_queries', 0)
        direct_queries = self.datalake.get('direct_queries', 0)
        total = mcp_queries + direct_queries
        tools = self.datalake.get('tool_breakdown', [])
        errors = self.datalake.get('errors', [])
        error_rate = self.datalake.get('error_rate', 0)

        # MCP vs Direct KQL
        mcp_pct = (mcp_queries / total * 100) if total > 0 else 0
        delineation = f'''<div style="display:flex;gap:20px;margin-bottom:10px;">
<div style="flex:1;background:#2a2a2a;padding:8px;border-radius:4px;border-left:3px solid #2ecc71;">
<div style="font-size:0.85em;color:#b0b0b0;">MCP-driven</div>
<div style="font-size:1.3em;font-weight:700;color:#2ecc71;">{mcp_queries:,}</div>
<div style="font-size:0.8em;">{mcp_pct:.1f}% of total</div></div>
<div style="flex:1;background:#2a2a2a;padding:8px;border-radius:4px;border-left:3px solid #e67e22;">
<div style="font-size:0.85em;color:#b0b0b0;">Direct KQL</div>
<div style="font-size:1.3em;font-weight:700;color:#e67e22;">{direct_queries:,}</div>
<div style="font-size:0.8em;">{100 - mcp_pct:.1f}% of total</div></div>
</div>'''

        tool_rows = ''
        max_c = max((t.get('Calls', t.get('calls', 0)) for t in tools), default=1) or 1
        for t in tools[:10]:
            name = t.get('Tool', t.get('tool', ''))
            calls = t.get('Calls', t.get('calls', 0))
            tool_rows += f'<tr><td>{esc(name)}</td><td>{bar_html(calls, max_c, "#2ecc71", 80)}</td></tr>'

        err_rows = ''
        for e in errors[:5]:
            err_rows += f'<tr><td>{esc(e.get("Error", e.get("error", "")))}</td><td>{e.get("Count", e.get("count", 0))}</td></tr>'

        parts = delineation
        if tool_rows: parts += f'<h3 style="color:#2ecc71;">Tool Breakdown</h3><table><thead><tr><th>Tool</th><th>Calls</th></tr></thead><tbody>{tool_rows}</tbody></table>'
        if err_rows: parts += f'<h3 style="color:#dc3545;margin-top:10px;">Errors (rate: {error_rate:.1f}%)</h3><table><thead><tr><th>Error</th><th>Count</th></tr></thead><tbody>{err_rows}</tbody></table>'

        return f'<div class="section"><h2>{server_badge("Data Lake MCP")} Data Lake MCP</h2>{parts}</div>'

    # ─── Azure MCP ────────────────────────────────────────────────
    def _azure_mcp(self):
        if not self.azure:
            return '<div class="section"><h2>🟠 Azure MCP Server</h2><div style="color:#ffbb00;">⚠️ No Azure MCP data available</div></div>'

        auth_events = self.azure.get('auth_events', 0)
        workspace_queries = self.azure.get('workspace_queries', 0)
        users = self.azure.get('users', [])
        query_details = self.azure.get('query_details', [])

        user_pills = ' '.join(f'<span style="background:#e67e22;color:white;padding:2px 8px;border-radius:12px;font-size:0.8em;">{esc(u)}</span>' for u in users[:8])

        parts = f'''<div style="display:flex;gap:20px;margin-bottom:10px;">
<div><strong>{auth_events:,}</strong> auth events</div>
<div><strong>{workspace_queries:,}</strong> workspace queries</div>
<div>Users: {user_pills if user_pills else "—"}</div>
</div>'''

        if query_details:
            qd_rows = ''
            for q in query_details[:10]:
                qd_rows += f'<tr><td style="font-size:0.85em;">{esc(q.get("RequestClientApp", q.get("client_app", "")))}</td><td>{q.get("Calls", q.get("calls", 0))}</td><td style="font-size:0.85em;">{esc(q.get("User", q.get("user", "")))}</td></tr>'
            parts += f'<table><thead><tr><th>Client App</th><th>Queries</th><th>User</th></tr></thead><tbody>{qd_rows}</tbody></table>'

        return f'<div class="section"><h2>{server_badge("Azure MCP/CLI")} Azure MCP Server</h2>{parts}</div>'

    # ─── Workspace Governance ─────────────────────────────────────
    def _governance(self):
        if not self.governance:
            return ''
        analytics = self.governance.get('analytics_tier', [])
        datalake_gov = self.governance.get('datalake_tier', [])

        rows = ''
        max_c = max((s.get('Calls', s.get('calls', 0)) for s in analytics), default=1) or 1
        for s in analytics[:15]:
            name = s.get('Source', s.get('source', ''))
            calls = s.get('Calls', s.get('calls', 0))
            is_mcp = s.get('IsMCP', s.get('is_mcp', False))
            label = '<span style="background:#00a1f1;color:white;padding:1px 4px;border-radius:3px;font-size:0.7em;">MCP</span>' if is_mcp else '<span style="background:#555;color:white;padding:1px 4px;border-radius:3px;font-size:0.7em;">Platform</span>'
            rows += f'<tr><td>{esc(name)} {label}</td><td>{bar_html(calls, max_c, "#00a1f1" if is_mcp else "#555", 80)}</td></tr>'

        parts = ''
        if rows: parts += f'<h3>Analytics Tier (LAQueryLogs)</h3><table><thead><tr><th>Source</th><th>Queries</th></tr></thead><tbody>{rows}</tbody></table>'

        return f'<div class="section"><h2>🏛️ Workspace Query Governance</h2>{parts}</div>' if parts else ''

    # ─── Top MCP Users ────────────────────────────────────────────
    def _top_users(self):
        if not self.users:
            return ''
        rows = ''
        for i, u in enumerate(self.users[:15], 1):
            name = u.get('User', u.get('user', ''))
            servers = u.get('Servers', u.get('servers', 0))
            total = u.get('TotalCalls', u.get('total_calls', 0))
            server_list = u.get('ServerList', u.get('server_list', []))
            badges = ' '.join(server_badge(s) for s in (server_list if isinstance(server_list, list) else []))
            rows += f'<tr><td style="text-align:center;font-weight:600;">{i}</td><td>{esc(name)}</td><td style="text-align:center;">{servers}</td><td style="font-weight:600;">{total:,}</td><td>{badges}</td></tr>'

        return f'''<div class="section"><h2>👥 Top MCP Users (Cross-Server Breadth)</h2>
<table><thead><tr><th style="text-align:center;">#</th><th>User</th><th style="text-align:center;">Servers</th><th>Total Calls</th><th>Server Types</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── Security Assessment ──────────────────────────────────────
    def _assessment(self):
        findings = self.assessment.get('findings', [])
        overall = self.assessment.get('overall_rating', 'Unknown')

        rows = ''
        for f in findings:
            sev = f.get('severity', 'info')
            icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢', 'info': 'ℹ️'}.get(sev, 'ℹ️')
            rows += f'<tr><td style="text-align:center;font-size:1.2em;">{icon}</td><td>{esc(f.get("finding", ""))}</td><td style="font-size:0.85em;color:#b0b0b0;">{esc(f.get("detail", ""))}</td></tr>'

        if not rows:
            rows = '<tr><td colspan="3" style="color:#7cbb00;">✅ No security findings</td></tr>'

        return f'''<div class="section"><h2>🛡️ Security Assessment</h2>
<table><thead><tr><th style="text-align:center;">⚠️</th><th>Finding</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── Recommendations ──────────────────────────────────────────
    def _recommendations(self):
        if not self.recommendations:
            return ''
        items = ''.join(f'<li style="margin:4px 0;">{esc(r.get("action", r) if isinstance(r, dict) else r)}</li>' for r in self.recommendations[:10])
        return f'<div class="section"><h2>📋 Recommendations</h2><ul>{items}</ul></div>'

    # ─── Executive Summary ────────────────────────────────────────
    def _exec_summary(self):
        workspace = self.meta.get('workspace', 'Unknown')
        period = self.meta.get('analysis_period', '30 days')
        data_sources = self.meta.get('data_sources_checked', [])
        ds_html = ', '.join(f'<code>{esc(d)}</code>' for d in data_sources) if data_sources else '—'

        rows = f'''<tr><td class="l">Workspace</td><td style="font-weight:600;color:#00a1f1;">{esc(workspace)}</td></tr>
<tr><td class="l">Analysis Period</td><td>{esc(period)}</td></tr>
<tr><td class="l">Data Sources</td><td style="font-size:0.85em;">{ds_html}</td></tr>'''

        summary = f'<div style="margin-top:8px;padding:8px;background:#2a2a2a;border-radius:4px;border-left:3px solid #00a1f1;">{esc(self.summary)}</div>' if self.summary else ''

        return f'<div class="section"><h2>📝 Executive Summary</h2><table>{rows}</table>{summary}</div>'

    # ─── Server Landscape ─────────────────────────────────────────
    def _server_landscape(self):
        landscape = self.footprint.get('server_landscape', [])
        if not landscape:
            return ''
        rows = ''
        for s in landscape:
            name = s.get('Server', s.get('server', ''))
            status = s.get('Status', s.get('status', ''))
            calls = s.get('Calls', s.get('calls', 0))
            users = s.get('Users', s.get('users', 0))
            status_icon = '✅' if status == 'Active' else '⚠️' if status == 'Gap' else '❌'
            rows += f'<tr><td>{server_badge(name)}</td><td>{status_icon} {esc(status)}</td><td style="font-weight:600;">{calls:,}</td><td>{users}</td></tr>'

        return f'''<div class="section"><h2>🗺️ Server Landscape</h2>
<table><thead><tr><th>MCP Server</th><th>Status</th><th>Calls</th><th>Users</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── Full HTML ────────────────────────────────────────────────
    def generate(self, output_path):
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        workspace = self.meta.get('workspace', 'Unknown')
        period = self.meta.get('analysis_period', '30 days')
        total_score = self.score.get('total_score', 0)
        rating, rating_color = score_rating(total_score)

        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        # Left column: summary, KPIs, score, server landscape, users
        left = '\n'.join(filter(None, [
            self._exec_summary(), self._kpi_cards(),
            self._score_breakdown(), self._server_landscape(),
            self._top_users()]))
        # Right column: per-server analysis, governance, assessment, recommendations
        right = '\n'.join(filter(None, [
            self._graph_mcp(), self._triage_mcp(),
            self._datalake_mcp(), self._azure_mcp(),
            self._governance(), self._daily_trend(),
            self._assessment(), self._recommendations()]))

        html = f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MCP Usage Report — {esc(workspace)}</title>
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
.section h3{{font-size:1em;margin:8px 0 5px;color:#e0e0e0}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px}}
.metric{{padding:10px;border-radius:5px;text-align:center}}
.mv{{font-size:1.6em;font-weight:bold;color:white}}.ml{{font-size:0.85em;color:rgba(255,255,255,0.9);margin-top:2px}}
table{{width:100%;border-collapse:collapse;font-size:0.92em}}
th{{background:#2a2a2a;color:#00a1f1;padding:7px 10px;text-align:left;font-weight:600;border-bottom:2px solid #3a3a3a}}
td{{padding:5px 10px;border-bottom:1px solid #2a2a2a}}tr:hover{{background:#2a2a2a}}
ul{{margin:6px 0;padding-left:20px}}li{{margin:3px 0}}
.l{{color:#b0b0b0;font-weight:500;white-space:nowrap;width:130px}}
.ftr{{background:#252525;padding:10px 20px;text-align:center;font-size:0.85em;color:#737373;border-top:1px solid #3a3a3a}}
code{{background:#333;padding:1px 4px;border-radius:3px;font-size:0.9em;color:#e0e0e0}}
</style></head><body>
<div class="wm"><div>🔒 <strong>CONFIDENTIAL — MCP USAGE MONITORING</strong></div><div style="font-size:12px;">Generated by <strong>{get_user()}</strong> on <strong>{get_host()}</strong> | {now_str}</div></div>
<div class="ctr" style="margin-top:50px;">
  <div class="hdr"><div><h1>🔌 MCP Usage Report <span style="color:rgba(255,255,255,0.5);font-weight:300;">|</span> <span style="font-size:0.55em;font-weight:400;">{esc(workspace)}</span></h1>
    <div style="font-size:1em;opacity:0.9;margin-top:4px;">
      <span style="background:rgba(255,255,255,0.2);padding:3px 8px;border-radius:10px;font-size:0.8em;margin-right:6px;">{esc(period)}</span>
      <span style="background:{rating_color};color:white;padding:3px 8px;border-radius:10px;font-size:0.8em;">Score: {total_score}/100 — {rating}</span>
    </div></div>
    <div class="meta"><div><strong>Generated:</strong> {now_str}</div><div><strong>Workspace:</strong> {esc(workspace)}</div></div></div>
  <div class="cnt"><div style="display:flex;flex-direction:column;gap:12px;">{left}</div><div style="display:flex;flex-direction:column;gap:12px;">{right}</div></div>
  <div class="ftr"><strong style="color:#f65314;">⚠️ CONFIDENTIAL</strong> — MCP Usage Report: {esc(workspace)} | {now_str}</div>
</div></body></html>'''

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return output_path


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_html_report.py <mcp_usage_report.json> [--output-dir DIR]")
        sys.exit(1)

    json_file = sys.argv[1]
    output_dir = '.'
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--output-dir' and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]; i += 2
        else:
            i += 1

    with open(json_file, encoding='utf-8') as f:
        data = json.load(f)

    meta = data.get('report_metadata', {})
    workspace = meta.get('workspace', 'unknown').replace(' ', '_')[:40]
    ts = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    output_path = os.path.join(output_dir, f'MCP_Usage_Report_{workspace}_{ts}.html')

    gen = MCPUsageReportGenerator(data)
    path = gen.generate(output_path)
    print(f"✅ Report: {path}")


if __name__ == '__main__':
    main()
