"""
Computer Investigation HTML Report Generator
=============================================
Self-contained HTML report generator for computer/device security investigations.
Zero external dependencies — Python 3 stdlib only.

Usage:
    python3 generate_html_report.py <json_file_path>

Reads a pre-enriched device investigation JSON (produced by the agent) and generates
a styled HTML report with dark theme, two-column layout, IP intelligence cards,
process/network/file/registry activity sections, and timeline modal.
"""

import json
import sys
import os
import socket
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════
# DATACLASSES
# ═══════════════════════════════════════════════════════════════════

@dataclass
class DeviceProfile:
    display_name: str; operating_system: str; os_version: str
    trust_type: str; is_compliant: bool; is_managed: bool
    manufacturer: str; model: str; registration_date: str
    architecture: str = ""

@dataclass
class DefenderStatus:
    onboarding_status: str; sensor_health: str; exposure_level: str
    is_internet_facing: bool; public_ip: str; machine_group: str
    device_tags: List[str] = field(default_factory=list)

@dataclass
class SecurityAlert:
    time_generated: str; alert_name: str; severity: str; status: str
    provider: str; tactics: str; techniques: str; compromised_entity: str
    description: str = ""; remediation_steps: str = ""

@dataclass
class SecurityIncident:
    incident_id: str; title: str; severity: str; status: str
    classification: str; created_time: str; owner: str
    alert_count: int; portal_url: str; tactics: str = ""

@dataclass
class LogonEvent:
    account: str; domain: str; logon_type: str; logon_count: int
    success_count: int; failure_count: int; first_seen: str; last_seen: str
    remote_ips: str = ""

@dataclass
class ProcessEvent:
    process_name: str; folder_path: str; account: str; process_count: int
    suspicious_count: int; sample_commands: List[str] = field(default_factory=list)

@dataclass
class NetworkConnection:
    remote_ip: str; port: int; url: str; connection_count: int
    protocols: str; initiating_processes: str; first_seen: str; last_seen: str

@dataclass
class FileEvent:
    folder_path: str; initiating_process: str; total_events: int
    suspicious_count: int; created: int; modified: int; deleted: int
    extensions: str; first_seen: str; last_seen: str

@dataclass
class RegistryEvent:
    registry_key: str; value_name: str; initiating_process: str
    total_events: int; persistence_count: int; first_seen: str; last_seen: str

@dataclass
class IPIntelligence:
    ip: str; city: str; region: str; country: str; org: str; asn: str
    timezone: str; risk_level: str; assessment: str
    abuse_confidence_score: int = 0; is_whitelisted: bool = False
    total_reports: int = 0; is_vpn: bool = False
    is_proxy: bool = False; is_tor: bool = False; is_hosting: bool = False
    threat_detected: bool = False; threat_description: str = ""
    connection_count: int = 0; initiating_processes: str = ""
    first_seen: str = ""; last_seen: str = ""
    categories: list = None

@dataclass
class ThreatIntelMatch:
    ip: str; threat_description: str; confidence: int
    valid_until: str; is_active: bool

@dataclass
class DeviceInvestigationResult:
    device_name: str; device_id_defender: str; device_id_entra: str
    device_type: str; investigation_date: str; start_date: str; end_date: str
    device_profile: Optional[DeviceProfile]
    defender_status: Optional[DefenderStatus]
    device_owners: List[str]; device_users: List[str]
    security_alerts: List[SecurityAlert]
    incidents: List[SecurityIncident]
    logon_events: List[LogonEvent]
    signin_events: List[Dict]
    process_events: List[ProcessEvent]
    network_connections: List[NetworkConnection]
    file_events: List[FileEvent]
    registry_events: List[RegistryEvent]
    ip_intelligence: List[IPIntelligence]
    threat_intel_matches: List[ThreatIntelMatch]
    data_gaps: List[str]
    summary: Dict[str, Any] = field(default_factory=dict)
    risk_assessment: Dict = field(default_factory=dict)
    recommendations: Dict = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════

class CompactReportGenerator:
    """Generates compact HTML device investigation reports with two-column layout"""

    def generate(self, result, output_path=None):
        if not output_path:
            ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
            dev = result.device_name.replace(' ', '_')
            output_path = f"reports/computer-investigations/Investigation_Report_{dev}_{ts}.html"
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self._html(result))
        return output_path

    def _get_user(self):
        try: return os.getlogin().upper()
        except Exception: return os.environ.get('USERNAME', 'AGENT').upper()

    def _get_host(self):
        try: return socket.gethostname().upper()
        except Exception: return 'UNKNOWN'

    def _badge(self, level):
        m = {'CRITICAL': '#f65314', 'HIGH': '#f65314', 'MEDIUM': '#ffbb00', 'LOW': '#7cbb00', 'INFO': '#737373', 'INFORMATIONAL': '#737373'}
        bg = m.get((level or '').upper(), '#737373')
        tc = '#1a1a1a' if (level or '').upper() == 'MEDIUM' else 'white'
        return f'<span style="background:{bg};color:{tc};padding:2px 9px;border-radius:3px;font-size:0.9em;font-weight:600;">{level}</span>'

    def _cat_badges(self, cats):
        if not cats: return ''
        m = {'threat': ('#dc3545', '🚨 THREAT'), 'risky': ('#ff7f00', '⚠️ RISKY'),
             'external': ('#ffc107', 'EXTERNAL'), 'primary': ('#007bff', 'PRIMARY'),
             'ti_match': ('#dc3545', '🚨 TI MATCH')}
        html = ''
        for c in (cats or []):
            if c in m:
                bg, label = m[c]
                tc = '#1a1a1a' if c == 'external' else 'white'
                html += f' <span style="background:{bg};color:{tc};padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;">{label}</span>'
        return html

    def _ip_type_info(self, org):
        ol = (org or '').lower()
        if any(p in ol for p in ['microsoft', 'azure']): return ("☁️ Azure Cloud", "#00a1f1", True)
        if any(p in ol for p in ['amazon', 'aws']): return ("☁️ AWS", "#ff9900", True)
        if any(p in ol for p in ['google', 'gcp']): return ("☁️ GCP", "#4285f4", True)
        if any(p in ol for p in ['cloudflare', 'akamai', 'fastly']): return ("☁️ CDN", "#00a1f1", True)
        if any(p in ol for p in ['vpn', 'proxy']): return ("🔒 VPN/Proxy", "#ffc107", False)
        if any(p in ol for p in ['hosting', 'datacenter']): return ("🖥️ Hosting", "#ffc107", False)
        if any(p in ol for p in ['telecom', 'communications', 'mobile']): return ("📱 Telecom", "#7cbb00", False)
        if any(p in ol for p in ['rogers', 'telus', 'comcast', 'verizon', 'at&t', 'bell']): return ("🏠 ISP", "#7cbb00", False)
        return ("🌐 ISP", "#b0b0b0", False)

    def _table(self, headers, rows, id_attr=''):
        id_s = f' id="{id_attr}"' if id_attr else ''
        h = ''.join(f'<th style="{s}">{t}</th>' if s else f'<th>{t}</th>' for t, s in headers)
        r = ''.join(rows)
        return f'<table{id_s}><thead><tr>{h}</tr></thead><tbody>{r}</tbody></table>'

    def _section(self, title, body):
        return f'<div class="section"><h2>{title}</h2>{body}</div>'

    # ─── IP Card ───────────────────────────────────────────────────
    def _ip_card(self, ip):
        border_m = {'CRITICAL': '#f65314', 'HIGH': '#f65314', 'MEDIUM': '#ffbb00', 'LOW': '#7cbb00'}
        border = border_m.get(ip.risk_level, '#7cbb00')
        loc = f"{ip.city}, {ip.country}" if ip.city and ip.country else ip.country or "Unknown"
        ip_type, ip_tc, is_infra = self._ip_type_info(ip.org)
        vpn_i = "" if is_infra or not ip.is_vpn else " | <span style='color:#ffc107;font-weight:bold;'>🔒 VPN</span>"
        has_ti = bool(ip.threat_description)
        has_abuse = ip.abuse_confidence_score > 0
        if has_ti or (has_abuse and ip.abuse_confidence_score >= 25):
            status = '<span style="color:#f65314;font-weight:bold;">⚠️ THREAT</span>'
        else:
            status = '<span style="color:#7cbb00;font-weight:bold;">✓ Clean</span>'
        threat_color = '#f65314' if has_ti else '#7cbb00'
        threat_text = ip.threat_description if has_ti else '✓ None found'
        dates = ""
        if ip.first_seen and ip.last_seen:
            dates = f'<div style="display:flex;justify-content:space-between;"><span><span class="l">First:</span> {ip.first_seen}</span><span><span class="l">Last:</span> {ip.last_seen}</span></div>'
        elif ip.first_seen:
            dates = f'<div><span class="l">First:</span> {ip.first_seen}</div>'
        procs = f'<div><span class="l">Processes:</span> {ip.initiating_processes}</div>' if ip.initiating_processes else ''
        return f'''<div style="background:#2a2a2a;border-left:3px solid {border};padding:11px;border-radius:5px;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
    <span style="font-weight:600;color:#00a1f1;font-size:1.1em;">{ip.ip}{self._cat_badges(ip.categories or [])}</span>{self._badge(ip.risk_level)}
  </div>
  <div style="font-size:0.92em;">
    <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
      <span><span class="l">Location:</span> {loc}</span>
      <span><span class="l">Connections:</span> {ip.connection_count}</span>
    </div>{dates}
    <div style="margin-bottom:3px;">
      <span><span class="l">Type:</span> <span style="color:{ip_tc};">{ip_type}{vpn_i}</span></span>
    </div>{procs}
    <details style="margin-top:6px;"><summary style="cursor:pointer;color:#00a1f1;font-size:0.9em;background:#333;padding:4px 8px;border-radius:3px;">🔍 Details</summary>
      <div style="padding:6px;font-size:0.85em;color:#b0b0b0;margin-top:4px;">
        <div>Org: {ip.org}</div><div>ASN: {ip.asn}</div>
        <div>Type: <span style="color:{ip_tc};">{ip_type}{vpn_i}</span> | {status}</div>
        <div>Threat: <span style="color:{threat_color};">{threat_text}</span></div>
        <div>Abuse Score: {ip.abuse_confidence_score}% | Reports: {ip.total_reports}</div>
      </div>
    </details>
  </div></div>'''

    # ─── Left Column Sections ─────────────────────────────────────
    def _metrics(self, r):
        s = r.summary
        alerts = s.get('total_alerts', 0)
        susp = s.get('suspicious_processes', 0)
        users = s.get('unique_logged_on_users', 0)
        ti = s.get('threat_intel_hits', 0)
        def m(v, l): return f'<div class="metric"><div class="mv">{v}</div><div class="ml">{l}</div></div>'
        return f'<div class="section"><h2>📊 Key Metrics</h2><div class="metrics">{m(alerts, "Alerts")}{m(susp, "Suspicious Procs")}{m(users, "Logged-On Users")}{m(ti, "TI Matches")}</div></div>'

    def _defender_status(self, r):
        ds = r.defender_status
        if not ds:
            return self._section('🛡️ Defender Status', '<p class="l">No Defender for Endpoint data</p>')
        exp_m = {'High': '#f65314', 'Medium': '#ffbb00', 'Low': '#7cbb00', 'None': '#737373'}
        exp_c = exp_m.get(ds.exposure_level, '#737373')
        sensor_c = '#7cbb00' if ds.sensor_health == 'Active' else '#f65314'
        inet = '🌐 Yes' if ds.is_internet_facing else '🔒 No'
        inet_c = '#f65314' if ds.is_internet_facing else '#7cbb00'
        tags = ', '.join(ds.device_tags) if ds.device_tags else 'None'
        body = f'''<div style="margin-top:6px;font-size:0.92em;">
  <div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span class="l">Sensor:</span><span style="color:{sensor_c};font-weight:600;">{ds.sensor_health}</span></div>
  <div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span class="l">Exposure:</span><span style="color:{exp_c};font-weight:600;">{ds.exposure_level}</span></div>
  <div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span class="l">Internet-Facing:</span><span style="color:{inet_c};font-weight:600;">{inet}</span></div>
  <div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span class="l">Public IP:</span><span>{ds.public_ip or 'N/A'}</span></div>
  <div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span class="l">Machine Group:</span><span>{ds.machine_group or 'Default'}</span></div>
  <div style="margin-bottom:4px;"><span class="l">Tags:</span> {tags}</div>
</div>'''
        return self._section('🛡️ Defender Status', body)

    def _risk_assessment(self, r):
        ra = r.risk_assessment
        rl = ra.get('risk_level', 'UNKNOWN')
        rf = ra.get('risk_factors', [])
        mf = ra.get('mitigating_factors', [])
        rf_h = f'<details open><summary>Risk Factors ({len(rf)})</summary><ul>{"".join(f"<li>{f}</li>" for f in rf)}</ul></details>' if rf else ''
        mf_h = f'<details open><summary>Mitigating Factors ({len(mf)})</summary><ul>{"".join(f"<li>{f}</li>" for f in mf)}</ul></details>' if mf else ''
        return f'<div class="section"><h2>🎯 Risk Assessment</h2><div style="margin-bottom:10px;"><strong>Overall:</strong> {self._badge(rl)}</div>{rf_h}{mf_h}</div>'

    def _critical_actions(self, r):
        rec = r.recommendations
        crit = rec.get('critical_actions', [])
        high = rec.get('high_priority_actions', [])
        alerts = []
        for a in crit[:3]:
            alerts.append(f'<div class="alert alert-critical"><strong>🚨 CRITICAL:</strong> {a}</div>')
        for a in high[:2]:
            alerts.append(f'<div class="alert alert-high"><strong>⚠️ HIGH:</strong> {a}</div>')
        if not alerts:
            alerts.append('<div class="alert alert-medium"><strong>✓</strong> No critical actions</div>')
        return f'<div class="section"><h2>🎯 Critical Actions</h2>{"".join(alerts)}</div>'

    def _device_owners(self, r):
        owners = r.device_owners or []
        users = r.device_users or []
        if not owners and not users:
            return self._section('👤 Owners & Users', '<p class="l">No registered owners or users</p>')
        body = ''
        if owners:
            body += '<div style="margin-bottom:8px;"><span class="l">Owners:</span><div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:4px;">'
            body += ''.join(f'<span style="background:#0078d4;color:white;padding:3px 8px;border-radius:3px;font-size:0.85em;">{o}</span>' for o in owners)
            body += '</div></div>'
        if users:
            body += '<div><span class="l">Registered Users:</span><div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:4px;">'
            body += ''.join(f'<span style="background:#7cbb00;color:white;padding:3px 8px;border-radius:3px;font-size:0.85em;">{u}</span>' for u in users)
            body += '</div></div>'
        return self._section('👤 Owners & Users', body)

    def _logon_summary(self, r):
        events = r.logon_events
        if not events:
            return self._section('🔑 Logon Activity', '<p class="l">No logon events</p>')
        rows = ''
        for e in events[:8]:
            sc = f'<span style="color:#7cbb00;">✓{e.success_count}</span>'
            fc = f'<span style="color:#dc3545;">✗{e.failure_count}</span>' if e.failure_count > 0 else f'<span style="color:#737373;">✗0</span>'
            rows += f'<tr><td>{e.account}</td><td>{e.logon_type}</td><td style="text-align:center;">{e.logon_count}</td><td style="text-align:center;">{sc} {fc}</td></tr>'
        tbl = self._table([('Account', ''), ('Type', ''), ('Count', 'text-align:center'), ('S/F', 'text-align:center')], [rows])
        return self._section('🔑 Logon Activity', tbl)

    def _data_gaps(self, r):
        gaps = r.data_gaps
        if not gaps:
            return ''
        items = ''.join(f'<li style="color:#ffbb00;font-size:0.85em;">{g}</li>' for g in gaps)
        return f'<div class="section"><h2>⚠️ Data Gaps</h2><ul>{items}</ul></div>'

    # ─── Right Column Sections ────────────────────────────────────
    def _ip_intelligence(self, r):
        ips = r.ip_intelligence
        if not ips:
            return self._section('🌐 IP Intelligence', '<p class="l">No IP enrichment data</p>')
        cards = ''.join(self._ip_card(ip) for ip in sorted(ips, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x.risk_level, 4)))
        return f'<div class="section"><h2>🌐 IP Intelligence ({len(ips)} IPs)</h2><div class="ip-grid">{cards}</div></div>'

    def _security_alerts(self, r):
        alerts = r.security_alerts
        if not alerts:
            return self._section('🚨 Security Alerts', '<p style="color:#7cbb00;">✅ No security alerts detected</p>')
        rows = ''
        sev_m = {'High': '#f65314', 'Medium': '#ffbb00', 'Low': '#7cbb00', 'Informational': '#737373'}
        for a in alerts[:15]:
            sc = sev_m.get(a.severity, '#737373')
            t = a.time_generated[:16] if a.time_generated else ''
            rows += f'<tr><td style="white-space:nowrap;font-size:0.85em;">{t}</td><td><span style="background:{sc};color:white;padding:2px 6px;border-radius:3px;font-size:0.8em;">{a.severity}</span></td><td>{a.alert_name}</td><td style="font-size:0.85em;">{a.tactics}</td><td style="font-size:0.85em;">{a.status}</td></tr>'
        tbl = self._table([('Time', ''), ('Severity', ''), ('Alert', ''), ('Tactics', ''), ('Status', '')], [rows])
        return self._section(f'🚨 Security Alerts ({len(alerts)})', tbl)

    def _incidents(self, r):
        incs = r.incidents
        if not incs:
            return self._section('🛡️ Security Incidents', '<p style="color:#7cbb00;">✅ No incidents associated</p>')
        rows = ''
        sev_m = {'High': '#f65314', 'Medium': '#ffbb00', 'Low': '#7cbb00', 'Informational': '#737373'}
        for i in incs[:10]:
            sc = sev_m.get(i.severity, '#737373')
            t = i.created_time[:10] if i.created_time else ''
            title = i.title[:60] + ('...' if len(i.title) > 60 else '')
            link = f'<a href="{i.portal_url}" target="_blank" style="color:#00a1f1;">{title}</a>' if i.portal_url else title
            st_m = {'Active': '#f65314', 'New': '#ffbb00', 'Closed': '#7cbb00', 'Resolved': '#7cbb00'}
            st_c = st_m.get(i.status, '#737373')
            rows += f'<tr><td style="font-size:0.85em;">{t}</td><td><span style="background:{sc};color:white;padding:2px 6px;border-radius:3px;font-size:0.8em;">{i.severity}</span></td><td>{i.incident_id}</td><td>{link}</td><td><span style="color:{st_c};font-weight:500;">{i.status}</span></td><td style="font-size:0.85em;">{i.owner}</td></tr>'
        tbl = self._table([('Date', ''), ('Severity', ''), ('ID', ''), ('Title', ''), ('Status', ''), ('Owner', '')], [rows])
        return self._section(f'🛡️ Security Incidents ({len(incs)})', tbl)

    def _process_activity(self, r):
        procs = r.process_events
        if not procs:
            return self._section('⚙️ Process Activity', '<p style="color:#7cbb00;">✅ No suspicious processes detected</p>')
        rows = ''
        for p in procs[:15]:
            susp_badge = f' <span style="background:#f65314;color:white;padding:1px 5px;border-radius:3px;font-size:0.75em;">⚠️ {p.suspicious_count}</span>' if p.suspicious_count > 0 else ''
            cmds = ''
            if p.sample_commands:
                cmd_items = ''.join(f'<div style="background:#1a1a1a;padding:3px 6px;margin:2px 0;border-radius:3px;font-family:monospace;font-size:0.8em;word-break:break-all;">{c[:120]}</div>' for c in p.sample_commands[:3])
                cmds = f'<details style="margin-top:4px;"><summary style="cursor:pointer;color:#00a1f1;font-size:0.8em;background:#333;padding:2px 6px;border-radius:3px;">Commands ({len(p.sample_commands)})</summary><div style="margin-top:4px;">{cmd_items}</div></details>'
            rows += f'<tr><td>{p.process_name}{susp_badge}</td><td style="font-size:0.8em;color:#b0b0b0;">{p.folder_path}</td><td style="text-align:center;">{p.process_count}</td><td style="font-size:0.85em;">{p.account}</td></tr>'
            if cmds:
                rows += f'<tr><td colspan="4" style="padding:0 10px 6px;">{cmds}</td></tr>'
        susp_total = sum(p.suspicious_count for p in procs)
        title = f'⚙️ Process Activity ({len(procs)} processes, {susp_total} suspicious)'
        tbl = self._table([('Process', ''), ('Path', ''), ('Count', 'text-align:center'), ('Account', '')], [rows])
        return self._section(title, tbl)

    def _network_activity(self, r):
        conns = r.network_connections
        if not conns:
            return self._section('🌍 Network Connections', '<p style="color:#7cbb00;">✅ No external connections detected</p>')
        rows = ''
        for c in conns[:15]:
            rows += f'<tr><td style="color:#00a1f1;font-weight:500;">{c.remote_ip}</td><td style="text-align:center;">{c.port}</td><td style="text-align:center;">{c.connection_count}</td><td style="font-size:0.85em;">{c.protocols}</td><td style="font-size:0.85em;">{c.initiating_processes}</td></tr>'
        tbl = self._table([('Remote IP', ''), ('Port', 'text-align:center'), ('Count', 'text-align:center'), ('Protocols', ''), ('Processes', '')], [rows])
        # TI matches sub-section
        ti_html = ''
        if r.threat_intel_matches:
            ti_rows = ''
            for t in r.threat_intel_matches[:10]:
                conf_c = '#f65314' if t.confidence >= 80 else '#ffbb00' if t.confidence >= 50 else '#7cbb00'
                ti_rows += f'<tr style="background:rgba(246,83,20,0.1);"><td style="color:#f65314;font-weight:600;">{t.ip}</td><td>{t.threat_description}</td><td style="text-align:center;"><span style="color:{conf_c};font-weight:600;">{t.confidence}%</span></td><td style="font-size:0.85em;">{"✅ Active" if t.is_active else "❌ Expired"}</td></tr>'
            ti_tbl = self._table([('IP', ''), ('Threat', ''), ('Confidence', 'text-align:center'), ('Status', '')], [ti_rows])
            ti_html = f'<div style="margin-top:12px;padding:10px;background:rgba(246,83,20,0.05);border:1px solid #f65314;border-radius:5px;"><h3 style="color:#f65314;font-size:1em;margin-bottom:8px;">🚨 Threat Intelligence Matches</h3>{ti_tbl}</div>'
        return self._section(f'🌍 Network Connections ({len(conns)})', tbl + ti_html)

    def _file_activity(self, r):
        files = r.file_events
        if not files:
            return self._section('📁 File Activity', '<p style="color:#7cbb00;">✅ No suspicious file activity</p>')
        rows = ''
        for f in files[:12]:
            susp_badge = f' <span style="background:#f65314;color:white;padding:1px 5px;border-radius:3px;font-size:0.75em;">⚠️</span>' if f.suspicious_count > 0 else ''
            rows += f'<tr><td style="font-size:0.85em;">{f.folder_path}{susp_badge}</td><td style="font-size:0.85em;">{f.initiating_process}</td><td style="text-align:center;">{f.total_events}</td><td style="text-align:center;font-size:0.85em;"><span style="color:#7cbb00;">+{f.created}</span> <span style="color:#ffbb00;">~{f.modified}</span> <span style="color:#f65314;">-{f.deleted}</span></td></tr>'
        tbl = self._table([('Folder', ''), ('Process', ''), ('Events', 'text-align:center'), ('C/M/D', 'text-align:center')], [rows])
        return self._section(f'📁 File Activity ({len(files)} paths)', tbl)

    def _registry_activity(self, r):
        regs = r.registry_events
        if not regs:
            return self._section('🗝️ Registry Modifications', '<p style="color:#7cbb00;">✅ No persistence-related registry changes</p>')
        rows = ''
        for reg in regs[:12]:
            persist_badge = f' <span style="background:#f65314;color:white;padding:1px 5px;border-radius:3px;font-size:0.75em;">🔴 PERSIST</span>' if reg.persistence_count > 0 else ''
            key_short = reg.registry_key
            if len(key_short) > 60:
                key_short = '...' + key_short[-57:]
            rows += f'<tr><td style="font-size:0.82em;font-family:monospace;">{key_short}{persist_badge}</td><td style="font-size:0.85em;">{reg.initiating_process}</td><td style="text-align:center;">{reg.total_events}</td></tr>'
        tbl = self._table([('Registry Key', ''), ('Process', ''), ('Events', 'text-align:center')], [rows])
        return self._section(f'🗝️ Registry ({len(regs)} keys)', tbl)

    # ─── Recommendations ───────────────────────────────────────────
    def _recommendations(self, r):
        rec = r.recommendations
        def li_list(items, default='No actions required'):
            if not items: return f'<li>{default}</li>'
            return ''.join(f'<li>{a}</li>' for a in items)
        c = li_list(rec.get('critical_actions', []))
        h = li_list(rec.get('high_priority_actions', []))
        m = li_list(rec.get('monitoring_actions', []))
        return f'''<div style="padding:12px;"><div class="section"><h2>💡 Recommendations</h2>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;">
  <div><h3 style="color:#f65314;font-size:1em;margin-bottom:6px;">Critical</h3><ul style="font-size:0.85em;">{c}</ul></div>
  <div><h3 style="color:#ffbb00;font-size:1em;margin-bottom:6px;">High Priority</h3><ul style="font-size:0.85em;">{h}</ul></div>
  <div><h3 style="color:#00a1f1;font-size:1em;margin-bottom:6px;">Monitoring (14d)</h3><ul style="font-size:0.85em;">{m}</ul></div>
</div></div></div>'''

    # ─── Timeline Modal ────────────────────────────────────────────
    def _timeline(self, r):
        events = []
        for a in (r.security_alerts or []):
            events.append({'t': a.time_generated, 's': a.severity.lower() if a.severity else 'medium', 'i': '🚨',
                'title': f"Alert: {a.alert_name[:60]}", 'detail': f"Severity: {a.severity} | Provider: {a.provider} | Tactics: {a.tactics}"})
        for inc in (r.incidents or []):
            events.append({'t': inc.created_time, 's': inc.severity.lower() if inc.severity else 'medium', 'i': '🛡️',
                'title': f"Incident: {inc.title[:60]}", 'detail': f"Status: {inc.status} | Classification: {inc.classification} | Owner: {inc.owner}"})
        for t in (r.threat_intel_matches or []):
            events.append({'t': t.valid_until, 's': 'high', 'i': '⚠️',
                'title': f"TI Match: {t.ip}", 'detail': f"{t.threat_description} (confidence: {t.confidence}%)"})
        events.sort(key=lambda x: x['t'] or '', reverse=True)
        items = ''
        cur_date = None
        for e in events:
            if not e['t']: continue
            ed = e['t'][:10]
            et = e['t'][11:16] if len(e['t']) > 16 else ''
            if ed != cur_date:
                cur_date = ed
                items += f'<div style="margin:20px 0 15px;padding:8px 12px;background:#2d2020;border-left:4px solid #00a1f1;border-radius:4px;"><span style="color:#00a1f1;font-weight:600;font-size:1.1em;">{ed}</span></div>'
            mc = {'high': '#f65314', 'medium': '#ffbb00', 'low': '#7cbb00'}.get(e['s'], '#ffbb00')
            items += f'''<div style="position:relative;margin-bottom:20px;padding-left:30px;">
  <div style="position:absolute;left:-20px;width:24px;height:24px;border-radius:50%;background:{mc};display:flex;align-items:center;justify-content:center;border:2px solid #1e1e1e;font-size:12px;">{e['i']}</div>
  <div style="background:#252525;padding:12px;border-radius:6px;border-left:3px solid #00a1f1;">
    <div style="color:#b0b0b0;font-size:0.85em;">{et} UTC</div>
    <div style="font-weight:600;margin-bottom:5px;">{e['title']}</div>
    <div style="color:#b0b0b0;font-size:0.9em;">{e['detail']}</div>
  </div></div>'''
        if not items:
            items = '<p class="l">No timeline events</p>'
        return f'''<div id="tlModal" style="display:none;position:fixed;z-index:1000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,0.8);">
<div style="background:#1e1e1e;margin:5% auto;padding:20px;border:1px solid #00a1f1;border-radius:8px;width:60%;max-width:900px;max-height:80vh;overflow-y:auto;">
  <span onclick="document.getElementById('tlModal').style.display='none'" style="float:right;font-size:28px;cursor:pointer;color:#aaa;">&times;</span>
  <h2 style="color:#00a1f1;margin-bottom:20px;">📅 Investigation Timeline</h2>
  <div style="position:relative;padding-left:30px;margin-top:20px;">{items}</div>
</div></div>'''

    # ─── Full HTML ─────────────────────────────────────────────────
    def _html(self, r):
        dp = r.device_profile
        dev_name = dp.display_name if dp else r.device_name
        os_info = f"{dp.operating_system} {dp.os_version}" if dp else 'Unknown OS'
        trust = dp.trust_type if dp else r.device_type or 'Unknown'
        compliant = '✅ Compliant' if (dp and dp.is_compliant) else '❌ Non-Compliant'
        managed = '✅ Managed' if (dp and dp.is_managed) else '❌ Unmanaged'
        comp_c = '#7cbb00' if (dp and dp.is_compliant) else '#f65314'
        mgd_c = '#7cbb00' if (dp and dp.is_managed) else '#f65314'

        left = '\n'.join([
            self._metrics(r), self._defender_status(r), self._risk_assessment(r),
            self._critical_actions(r), self._device_owners(r),
            self._logon_summary(r), self._data_gaps(r)
        ])
        right = '\n'.join([
            self._security_alerts(r), self._incidents(r),
            self._process_activity(r), self._network_activity(r),
            self._file_activity(r), self._registry_activity(r),
            self._ip_intelligence(r)
        ])
        return f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Device Investigation - {dev_name}</title>
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
.section h2{{font-size:1.2em;color:#00a1f1;margin-bottom:10px;padding-bottom:5px;border-bottom:1px solid #3a3a3a;position:relative}}
.metrics{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}}
.metric{{background:linear-gradient(135deg,#00a1f1,#0078d4);padding:12px;border-radius:5px;text-align:center}}
.mv{{font-size:2em;font-weight:bold;color:white}}.ml{{font-size:0.95em;color:rgba(255,255,255,0.9);margin-top:2px}}
table{{width:100%;border-collapse:collapse;font-size:0.95em}}
th{{background:#2a2a2a;color:#00a1f1;padding:7px 10px;text-align:left;font-weight:600;border-bottom:2px solid #3a3a3a}}
td{{padding:6px 10px;border-bottom:1px solid #2a2a2a}}tr:hover{{background:#2a2a2a}}
.ip-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}}
.l{{color:#b0b0b0;font-weight:500}}
.alert{{padding:10px 14px;margin:7px 0;border-left:3px solid;border-radius:4px;font-size:0.95em}}
.alert-critical{{background:#3d1f1f;border-color:#f65314}}.alert-high{{background:#3d3520;border-color:#ffbb00}}.alert-medium{{background:#1f2f3d;border-color:#00a1f1}}
ul{{margin:7px 0 7px 24px;font-size:0.95em}}li{{margin:4px 0}}
details{{margin:10px 0}}summary{{cursor:pointer;padding:10px;background:#2a2a2a;border-radius:5px;font-weight:600;color:#00a1f1}}summary:hover{{background:#333}}details[open] summary{{margin-bottom:9px}}
.ftr{{background:#252525;padding:10px 20px;text-align:center;font-size:0.85em;color:#737373;border-top:1px solid #3a3a3a}}
.tb{{background:linear-gradient(135deg,#00a1f1,#0078d4);color:white;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:0.9em;font-weight:600;width:100%}}.tb:hover{{background:linear-gradient(135deg,#0078d4,#005a9e)}}
</style></head><body>
<div class="wm"><div>🔒 <strong>CONFIDENTIAL - INTERNAL USE ONLY</strong></div><div style="font-size:12px;">Generated by <strong>{self._get_user()}</strong> on <strong>{self._get_host()}</strong> | {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}</div></div>
<div class="ctr" style="margin-top:50px;">
  <div class="hdr"><div><h1>💻 {dev_name} <span style="color:rgba(255,255,255,0.7);font-weight:300;">|</span> <span style="font-size:0.6em;font-weight:400;opacity:0.9;">{os_info}</span></h1>
    <div style="font-size:1em;opacity:0.9;margin-top:4px;">
      <span style="background:rgba(255,255,255,0.2);padding:3px 8px;border-radius:10px;font-size:0.8em;margin-right:6px;">🔗 {trust}</span>
      <span style="color:{comp_c};margin-right:8px;">{compliant}</span>
      <span style="color:{mgd_c};">{managed}</span>
    </div></div>
    <div class="meta"><div><strong>Investigation:</strong> {r.investigation_date}</div><div><strong>Period:</strong> {r.start_date} → {r.end_date}</div>
    <div style="margin-top:8px;"><button class="tb" onclick="document.getElementById('tlModal').style.display='block'">📅 View Timeline</button></div></div></div>
  <div class="cnt"><div style="display:flex;flex-direction:column;gap:12px;">{left}</div><div style="display:flex;flex-direction:column;gap:12px;">{right}</div></div>
  {self._recommendations(r)}
  <div class="ftr"><strong style="color:#f65314;">⚠️ CONFIDENTIAL</strong> — Device Security Investigation Report | {r.investigation_date} | {r.start_date} → {r.end_date}</div>
</div>
{self._timeline(r)}
<script>
document.addEventListener('keydown',e=>{{if(e.key==='Escape')document.getElementById('tlModal').style.display='none'}});
window.onclick=e=>{{if(e.target.id==='tlModal')e.target.style.display='none'}};
</script></body></html>'''


# ═══════════════════════════════════════════════════════════════════
# MAIN: JSON → Dataclasses → HTML
# ═══════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_html_report.py <json_file>")
        sys.exit(1)
    json_file = Path(sys.argv[1])
    if not json_file.exists():
        print(f"Error: {json_file} not found"); sys.exit(1)

    print(f"Loading {json_file.name}...")
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Extract sections
    dp_data = data.get('device_profile')
    ds_data = data.get('defender_status')
    alerts_data = data.get('security_alerts', [])
    incidents_data = data.get('incidents', [])
    logon_data = data.get('logon_events', [])
    signin_data = data.get('signin_events', [])
    process_data = data.get('process_events', [])
    network_data = data.get('network_events', [])
    file_data = data.get('file_events', [])
    registry_data = data.get('registry_events', [])
    ip_enrich = data.get('ip_enrichment', [])
    ti_data = data.get('threat_intel_matches', [])
    ip_context = data.get('ip_context', [])
    summary_data = data.get('summary', {})

    # Build DeviceInvestigationResult
    result = DeviceInvestigationResult(
        device_name=data.get('device_name', 'Unknown'),
        device_id_defender=data.get('device_id_defender', ''),
        device_id_entra=data.get('device_id_entra_object', data.get('device_id_entra', '')),
        device_type=data.get('device_type', ''),
        investigation_date=data.get('investigation_date', datetime.now().strftime('%Y-%m-%d')),
        start_date=data.get('start_date', ''), end_date=data.get('end_date', ''),
        device_profile=DeviceProfile(
            display_name=dp_data.get('displayName', dp_data.get('display_name', data.get('device_name', ''))),
            operating_system=dp_data.get('operatingSystem', dp_data.get('operating_system', '')),
            os_version=dp_data.get('operatingSystemVersion', dp_data.get('os_version', '')),
            trust_type=dp_data.get('trustType', dp_data.get('trust_type', '')),
            is_compliant=dp_data.get('isCompliant', dp_data.get('is_compliant', False)),
            is_managed=dp_data.get('isManaged', dp_data.get('is_managed', False)),
            manufacturer=dp_data.get('manufacturer', ''),
            model=dp_data.get('model', ''),
            registration_date=dp_data.get('registrationDateTime', dp_data.get('registration_date', '')),
            architecture=dp_data.get('architecture', '')
        ) if dp_data else None,
        defender_status=DefenderStatus(
            onboarding_status=ds_data.get('onboardingStatus', ds_data.get('onboarding_status', '')),
            sensor_health=ds_data.get('sensorHealthState', ds_data.get('sensor_health', '')),
            exposure_level=ds_data.get('exposureLevel', ds_data.get('exposure_level', '')),
            is_internet_facing=ds_data.get('isInternetFacing', ds_data.get('is_internet_facing', False)),
            public_ip=ds_data.get('publicIP', ds_data.get('public_ip', '')),
            machine_group=ds_data.get('machineGroup', ds_data.get('machine_group', '')),
            device_tags=ds_data.get('deviceTags', ds_data.get('device_tags', []))
        ) if ds_data else None,
        device_owners=data.get('device_owners', []),
        device_users=data.get('device_users', []),
        security_alerts=[SecurityAlert(
            time_generated=a.get('TimeGenerated', a.get('time_generated', '')),
            alert_name=a.get('AlertName', a.get('alert_name', '')),
            severity=a.get('Severity', a.get('severity', '')),
            status=a.get('Status', a.get('status', '')),
            provider=a.get('ProviderName', a.get('provider', '')),
            tactics=a.get('Tactics', a.get('tactics', '')),
            techniques=a.get('Techniques', a.get('techniques', '')),
            compromised_entity=a.get('CompromisedEntity', a.get('compromised_entity', '')),
            description=a.get('Description', a.get('description', '')),
            remediation_steps=a.get('RemediationSteps', a.get('remediation_steps', ''))
        ) for a in alerts_data],
        incidents=[SecurityIncident(
            incident_id=str(i.get('ProviderIncidentId', i.get('IncidentNumber', i.get('incident_id', '')))),
            title=i.get('Title', i.get('title', '')),
            severity=i.get('Severity', i.get('severity', '')),
            status=i.get('Status', i.get('status', '')),
            classification=i.get('Classification', i.get('classification', '')),
            created_time=i.get('CreatedTime', i.get('created_time', '')),
            owner=i.get('OwnerUPN', i.get('owner', 'Unassigned')),
            alert_count=int(i.get('AlertCount', i.get('alert_count', 1))),
            portal_url=i.get('ProviderIncidentUrl', i.get('portal_url', '')),
            tactics=i.get('Tactics', i.get('tactics', ''))
        ) for i in incidents_data],
        logon_events=[LogonEvent(
            account=l.get('AccountName', l.get('account', '')),
            domain=l.get('AccountDomain', l.get('domain', '')),
            logon_type=l.get('LogonType', l.get('logon_type', '')),
            logon_count=int(l.get('LogonCount', l.get('logon_count', 0))),
            success_count=int(l.get('SuccessCount', l.get('success_count', 0))),
            failure_count=int(l.get('FailureCount', l.get('failure_count', 0))),
            first_seen=l.get('FirstSeen', l.get('first_seen', '')),
            last_seen=l.get('LastSeen', l.get('last_seen', '')),
            remote_ips=l.get('RemoteIPs', l.get('remote_ips', ''))
        ) for l in logon_data],
        signin_events=signin_data,
        process_events=[ProcessEvent(
            process_name=p.get('FileName', p.get('process_name', '')),
            folder_path=p.get('FolderPath', p.get('folder_path', '')),
            account=p.get('AccountName', p.get('account', '')),
            process_count=int(p.get('ProcessCount', p.get('process_count', 0))),
            suspicious_count=int(p.get('SuspiciousCount', p.get('suspicious_count', 0))),
            sample_commands=p.get('SampleCommands', p.get('sample_commands', []))
        ) for p in process_data],
        network_connections=[NetworkConnection(
            remote_ip=n.get('RemoteIP', n.get('remote_ip', '')),
            port=int(n.get('RemotePort', n.get('port', 0))),
            url=n.get('RemoteUrl', n.get('url', '')),
            connection_count=int(n.get('ConnectionCount', n.get('connection_count', 0))),
            protocols=n.get('Protocols', n.get('protocols', '')),
            initiating_processes=n.get('InitiatingProcesses', n.get('initiating_processes', '')),
            first_seen=n.get('FirstSeen', n.get('first_seen', '')),
            last_seen=n.get('LastSeen', n.get('last_seen', ''))
        ) for n in network_data],
        file_events=[FileEvent(
            folder_path=f.get('FolderPath', f.get('folder_path', '')),
            initiating_process=f.get('InitiatingProcess', f.get('initiating_process', '')),
            total_events=int(f.get('TotalEvents', f.get('total_events', 0))),
            suspicious_count=int(f.get('SuspiciousCount', f.get('suspicious_count', 0))),
            created=int(f.get('Created', f.get('created', 0))),
            modified=int(f.get('Modified', f.get('modified', 0))),
            deleted=int(f.get('Deleted', f.get('deleted', 0))),
            extensions=f.get('Extensions', f.get('extensions', '')),
            first_seen=f.get('FirstSeen', f.get('first_seen', '')),
            last_seen=f.get('LastSeen', f.get('last_seen', ''))
        ) for f in file_data],
        registry_events=[RegistryEvent(
            registry_key=reg.get('RegistryKey', reg.get('registry_key', '')),
            value_name=reg.get('RegistryValueName', reg.get('value_name', '')),
            initiating_process=reg.get('InitiatingProcess', reg.get('initiating_process', '')),
            total_events=int(reg.get('TotalEvents', reg.get('total_events', 0))),
            persistence_count=int(reg.get('PersistenceCount', reg.get('persistence_count', 0))),
            first_seen=reg.get('FirstSeen', reg.get('first_seen', '')),
            last_seen=reg.get('LastSeen', reg.get('last_seen', ''))
        ) for reg in registry_data],
        ip_intelligence=[],
        threat_intel_matches=[ThreatIntelMatch(
            ip=t.get('IP', t.get('ip', '')),
            threat_description=t.get('ThreatDescription', t.get('threat_description', '')),
            confidence=int(t.get('ConfidenceScore', t.get('confidence', 0))),
            valid_until=t.get('ExpirationDateTime', t.get('valid_until', '')),
            is_active=t.get('Active', t.get('is_active', True))
        ) for t in ti_data],
        data_gaps=data.get('data_gaps', [])
    )

    # Summary metrics
    result.summary = {
        'total_alerts': summary_data.get('total_alerts', len(result.security_alerts)),
        'critical_alerts': summary_data.get('critical_alerts', sum(1 for a in result.security_alerts if a.severity == 'High')),
        'suspicious_processes': summary_data.get('suspicious_processes', sum(p.suspicious_count for p in result.process_events)),
        'unique_logged_on_users': summary_data.get('unique_logged_on_users', len(set(l.account for l in result.logon_events))),
        'threat_intel_hits': summary_data.get('threat_intel_hits', len(result.threat_intel_matches)),
        'external_ips_contacted': summary_data.get('external_ips_contacted', len(result.network_connections))
    }

    # IP enrichment → IPIntelligence
    net_ip_freq = {}
    net_ip_procs = {}
    for nc in result.network_connections:
        net_ip_freq[nc.remote_ip] = net_ip_freq.get(nc.remote_ip, 0) + nc.connection_count
        net_ip_procs[nc.remote_ip] = nc.initiating_processes
    net_ip_timeline = {nc.remote_ip: {'FirstSeen': nc.first_seen, 'LastSeen': nc.last_seen}
                       for nc in result.network_connections if nc.first_seen}
    ti_ips = {t.ip for t in result.threat_intel_matches}

    for ip_e in ip_enrich:
        ip = ip_e['ip']
        cats = []
        if ip in ti_ips:
            cats.append('ti_match')
        intel = IPIntelligence(
            ip=ip, city=ip_e.get('city', 'Unknown'), region=ip_e.get('region', 'Unknown'),
            country=ip_e.get('country', 'Unknown'), org=ip_e.get('org', 'Unknown'),
            asn=ip_e.get('asn', 'Unknown'), timezone=ip_e.get('timezone', 'Unknown'),
            risk_level=ip_e.get('risk_level', 'LOW'), assessment=ip_e.get('assessment', ''),
            abuse_confidence_score=ip_e.get('abuse_confidence_score', 0),
            is_whitelisted=ip_e.get('is_whitelisted', False),
            total_reports=ip_e.get('total_reports', 0),
            is_vpn=ip_e.get('is_vpn', False), is_proxy=ip_e.get('is_proxy', False),
            is_tor=ip_e.get('is_tor', False), is_hosting=ip_e.get('is_hosting', False),
            threat_description=ip_e.get('threat_description', ''),
            categories=cats,
            connection_count=net_ip_freq.get(ip, 0),
            initiating_processes=net_ip_procs.get(ip, ''),
            first_seen=net_ip_timeline.get(ip, {}).get('FirstSeen', ''),
            last_seen=net_ip_timeline.get(ip, {}).get('LastSeen', '')
        )
        result.ip_intelligence.append(intel)
    print(f"  Loaded {len(result.ip_intelligence)} IPs from enrichment cache")

    # Risk assessment
    risk_factors, mitigating = [], []
    crit_alerts = [a for a in result.security_alerts if a.severity in ('High', 'Critical')]
    if crit_alerts:
        risk_factors.append(f'🚨 <strong>{len(crit_alerts)} High/Critical alerts</strong>')
    open_incs = [i for i in result.incidents if i.status not in ('Closed', 'Resolved')]
    if open_incs:
        risk_factors.append(f'🛡️ <strong>{len(open_incs)} open incidents</strong>')
    ds = result.defender_status
    if ds and ds.exposure_level == 'High':
        risk_factors.append('🟠 <strong>High exposure level</strong>')
    if ds and ds.is_internet_facing:
        risk_factors.append('🌐 <strong>Internet-facing device</strong>')
    susp_procs = sum(p.suspicious_count for p in result.process_events)
    if susp_procs > 0:
        risk_factors.append(f'⚙️ <strong>{susp_procs} suspicious processes</strong>')
    if result.threat_intel_matches:
        risk_factors.append(f'⚠️ <strong>{len(result.threat_intel_matches)} TI matches</strong>')
    persist_regs = sum(r.persistence_count for r in result.registry_events)
    if persist_regs > 0:
        risk_factors.append(f'🗝️ <strong>{persist_regs} persistence registry changes</strong>')

    dp = result.device_profile
    if dp and dp.is_compliant:
        mitigating.append('✅ Device is compliant')
    if dp and dp.is_managed:
        mitigating.append('✅ Device is managed (MDM)')
    if ds and ds.sensor_health == 'Active':
        mitigating.append('✅ Defender sensor active and healthy')
    if not result.threat_intel_matches:
        mitigating.append('✅ No threat intelligence matches')
    if not crit_alerts:
        mitigating.append('✅ No high/critical severity alerts')

    score = max(0, min(100, len(risk_factors) * 12 - len(mitigating) * 5 + 25))
    rl = 'CRITICAL' if score >= 80 else 'HIGH' if score >= 65 else 'MEDIUM' if score >= 40 else 'LOW'
    result.risk_assessment = {'risk_level': rl, 'risk_score': score,
                              'risk_factors': risk_factors, 'mitigating_factors': mitigating}

    # Recommendations
    crit_acts, high_acts, mon_acts = [], [], []
    if crit_alerts:
        crit_acts.append(f'Triage {len(crit_alerts)} high/critical alerts immediately')
    if result.threat_intel_matches:
        crit_acts.append(f'Investigate {len(result.threat_intel_matches)} TI-matched IPs — block if confirmed malicious')
    if persist_regs > 0:
        high_acts.append(f'Review {persist_regs} persistence-related registry changes')
    if susp_procs > 0:
        high_acts.append(f'Analyze {susp_procs} suspicious process executions')
    if open_incs:
        high_acts.append(f'Review {len(open_incs)} open incidents for this device')
    if ds and ds.is_internet_facing:
        high_acts.append('Verify internet-facing exposure is intentional and hardened')
    if dp and not dp.is_compliant:
        high_acts.append('Bring device into compliance (check MDM policies)')
    mon_acts.append('Monitor for new alerts and process anomalies (14 days)')
    mon_acts.append('Watch for additional TI matches on contacted IPs')
    mon_acts.append('Track logon event patterns for unexpected users')
    result.recommendations = {'critical_actions': crit_acts, 'high_priority_actions': high_acts, 'monitoring_actions': mon_acts}

    # Generate HTML
    print("Generating HTML report...")
    gen = CompactReportGenerator()
    path = gen.generate(result)
    print(f"✅ Report: {path}")


if __name__ == "__main__":
    main()
