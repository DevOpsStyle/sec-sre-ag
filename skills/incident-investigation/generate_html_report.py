"""
Incident Investigation HTML Report Generator
=============================================
Self-contained HTML report generator for security incident investigations.
Zero external dependencies — Python 3 stdlib only.

Usage:
    python3 generate_html_report.py <json_file> [--output-dir DIR]

Reads a JSON file matching the incident-investigation export structure
(investigation_metadata, incident_details, user_investigations,
device_investigations, ioc_investigations, summary) and generates
a styled HTML report with dark theme.
"""

import json
import sys
import os
import re
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

def esc(v):
    return escape(str(v)) if v else ''

def defang_ip(ip):
    """Defang an IP address: 1.2.3.4 → 1[.]2[.]3[.]4"""
    if not ip: return ''
    return re.sub(r'\.', '[.]', str(ip))

def defang_url(url):
    """Defang a URL: https://evil.com → hxxps://evil[.]com"""
    if not url: return ''
    s = str(url)
    s = re.sub(r'^https://', 'hxxps://', s)
    s = re.sub(r'^http://', 'hxxp://', s)
    s = re.sub(r'\.', '[.]', s)
    return s

def severity_color(sev):
    s = (sev or '').lower()
    return {'high': '#f65314', 'medium': '#ffbb00', 'low': '#7cbb00', 'informational': '#00a1f1'}.get(s, '#737373')

def severity_badge(sev):
    c = severity_color(sev)
    tc = '#1a1a1a' if (sev or '').lower() in ('medium', 'low') else 'white'
    return f'<span style="background:{c};color:{tc};padding:2px 9px;border-radius:3px;font-size:0.85em;font-weight:600;">{esc(sev)}</span>'

def status_badge(status):
    s = (status or '').lower()
    c = {'active': '#f65314', 'new': '#ffbb00', 'closed': '#7cbb00', 'resolved': '#7cbb00'}.get(s, '#737373')
    return f'<span style="background:{c};color:{"#1a1a1a" if s in ("new",) else "white"};padding:2px 9px;border-radius:3px;font-size:0.85em;font-weight:600;">{esc(status)}</span>'

def tactic_pill(tactic):
    colors = {
        'initialaccess': '#e74c3c', 'execution': '#e67e22', 'persistence': '#f1c40f',
        'privilegeescalation': '#9b59b6', 'defenseevasion': '#1abc9c', 'credentialaccess': '#e74c3c',
        'discovery': '#3498db', 'lateralmovement': '#2ecc71', 'collection': '#e67e22',
        'exfiltration': '#c0392b', 'commandandcontrol': '#8e44ad', 'impact': '#c0392b',
    }
    key = re.sub(r'[^a-z]', '', (tactic or '').lower())
    bg = colors.get(key, '#555')
    return f'<span style="background:{bg};color:white;padding:2px 8px;border-radius:12px;font-size:0.8em;margin:2px;">{esc(tactic)}</span>'

def fmt_ts(ts):
    if not ts: return '—'
    s = str(ts)
    if 'T' in s: return s[:19].replace('T', ' ')
    return s[:19]


# ═══════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════

class IncidentReportGenerator:
    def __init__(self, data):
        self.data = data
        self.meta = data.get('investigation_metadata', {})
        self.details = data.get('incident_details', {})
        self.inc_meta = self.details.get('metadata', {})
        self.alerts = self.details.get('alerts', [])
        self.assets = self.details.get('assets', {})
        self.evidences = self.details.get('evidences', {})
        self.user_inv = data.get('user_investigations', [])
        self.device_inv = data.get('device_investigations', [])
        self.ioc_inv = data.get('ioc_investigations', [])
        self.summary = data.get('summary', {})

    # ─── Metadata Card ────────────────────────────────────────────
    def _metadata_card(self):
        m = self.inc_meta
        rows = ''
        fields = [
            ('Title', m.get('title')),
            ('Severity', None),  # handled specially
            ('Status', None),    # handled specially
            ('Classification', m.get('classification')),
            ('Classification Reason', m.get('classification_reason')),
            ('Provider', m.get('provider') or self.meta.get('provider')),
            ('Incident Number', self.meta.get('incident_id') or m.get('incident_number')),
            ('Provider Incident ID', self.meta.get('provider_incident_id') or m.get('provider_incident_id')),
            ('Created', fmt_ts(m.get('created_date'))),
            ('First Activity', fmt_ts(m.get('first_activity_date'))),
            ('Last Updated', fmt_ts(m.get('last_updated_date'))),
            ('Closed', fmt_ts(m.get('closed_date'))),
            ('Assigned To', m.get('assigned_to')),
        ]
        for label, val in fields:
            if label == 'Severity':
                val_html = severity_badge(m.get('severity'))
            elif label == 'Status':
                val_html = status_badge(m.get('status'))
            elif label == 'Closed' and (not m.get('closed_date') or m.get('closed_date') == '—'):
                continue
            else:
                val_html = esc(val) if val and val != '—' else '<span style="color:#737373;">—</span>'
            rows += f'<tr><td class="l">{label}</td><td>{val_html}</td></tr>'

        desc = m.get('description', '')
        desc_html = ''
        if desc:
            desc_html = f'<div style="margin-top:10px;padding:10px;background:#2a2a2a;border-radius:4px;font-size:0.9em;color:#b0b0b0;border-left:3px solid #00a1f1;">{esc(desc)}</div>'

        return f'''<div class="section"><h2>📋 Incident Metadata</h2>
<table style="font-size:0.92em;"><tbody>{rows}</tbody></table>{desc_html}</div>'''

    # ─── MITRE Card ───────────────────────────────────────────────
    def _mitre_card(self):
        tactics = self.inc_meta.get('mitre_tactics', [])
        techniques = self.inc_meta.get('mitre_techniques', [])
        if not tactics and not techniques:
            return ''
        pills = ' '.join(tactic_pill(t) for t in tactics if t) if tactics else '<span style="color:#737373;">None</span>'
        tech_html = ''
        if techniques:
            tech_items = ', '.join(f'<code style="background:#333;padding:1px 5px;border-radius:3px;font-size:0.85em;">{esc(t)}</code>' for t in techniques if t)
            tech_html = f'<div style="margin-top:8px;"><span class="l">Techniques:</span><div style="margin-top:4px;">{tech_items}</div></div>'
        return f'''<div class="section"><h2>🎯 MITRE ATT&CK</h2>
<div><span class="l">Tactics:</span><div style="margin-top:4px;">{pills}</div></div>{tech_html}</div>'''

    # ─── Key Metrics ──────────────────────────────────────────────
    def _metrics(self):
        n_alerts = len(self.alerts)
        n_users = len(self.assets.get('users', []))
        n_devices = len(self.assets.get('devices', []))
        n_ips = len(self.evidences.get('ip_addresses', []))
        n_urls = len(self.evidences.get('urls', [])) + len(self.evidences.get('domains', []))
        n_files = len(self.evidences.get('files', [])) + len(self.evidences.get('file_hashes', []))

        def mc(v, l, c='#00a1f1'):
            return f'<div class="metric" style="background:linear-gradient(135deg,{c},{c}cc);"><div class="mv">{v}</div><div class="ml">{l}</div></div>'

        sev = (self.inc_meta.get('severity') or '').lower()
        sev_c = severity_color(self.inc_meta.get('severity'))
        return f'''<div class="section"><h2>📊 Key Metrics</h2><div class="metrics">
{mc(n_alerts, 'Alerts', sev_c)}{mc(n_users, 'Users')}
{mc(n_devices, 'Devices', '#9b59b6')}{mc(n_ips + n_urls + n_files, 'Evidences', '#ff7f00')}
</div></div>'''

    # ─── Investigation Phases ─────────────────────────────────────
    def _phases(self):
        phases = self.meta.get('phases_completed', [])
        if not phases:
            return ''
        items = ''
        phase_icons = {
            'incident_description': '📋', 'user_investigation': '👤',
            'device_investigation': '💻', 'ioc_investigation': '🔍',
        }
        for p in phases:
            icon = phase_icons.get(p, '✅')
            label = p.replace('_', ' ').title()
            items += f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;"><span>{icon}</span><span>{label}</span><span style="color:#7cbb00;margin-left:auto;">✅</span></div>'
        elapsed = self.meta.get('total_elapsed_time_seconds')
        elapsed_html = f'<div style="margin-top:8px;color:#b0b0b0;font-size:0.85em;">Total elapsed: {elapsed}s</div>' if elapsed else ''
        return f'<div class="section"><h2>🔄 Investigation Phases</h2>{items}{elapsed_html}</div>'

    # ─── Alerts Table ─────────────────────────────────────────────
    def _alerts_table(self):
        if not self.alerts:
            return '<div class="section"><h2>🔔 Alerts</h2><p style="color:#7cbb00;">✅ No alerts</p></div>'
        rows = ''
        for i, a in enumerate(self.alerts[:30], 1):
            sev = a.get('severity') or a.get('alert_severity') or '?'
            name = a.get('name') or a.get('alert_name') or '?'
            tactics = a.get('tactics', '')
            if isinstance(tactics, list): tactics = ', '.join(tactics)
            src = a.get('detection_source') or a.get('provider_name') or a.get('product_name') or ''
            end = fmt_ts(a.get('end_time'))
            entity = esc(a.get('compromised_entity') or a.get('compromised_entity', ''))
            rows += f'<tr><td style="text-align:center;color:#737373;">{i}</td><td>{esc(name)}</td><td style="text-align:center;">{severity_badge(sev)}</td><td style="font-size:0.82em;">{esc(tactics)}</td><td style="font-size:0.82em;">{esc(src)}</td><td style="font-size:0.82em;">{end}</td></tr>'
        more = f'<p class="l" style="margin-top:6px;">Showing 30 of {len(self.alerts)}</p>' if len(self.alerts) > 30 else ''
        return f'''<div class="section"><h2>🔔 Alerts ({len(self.alerts)})</h2>
<table><thead><tr><th style="width:30px;">#</th><th>Alert</th><th style="text-align:center;">Severity</th><th>Tactics</th><th>Source</th><th>Last Activity</th></tr></thead><tbody>{rows}</tbody></table>{more}</div>'''

    # ─── User Assets ──────────────────────────────────────────────
    def _user_assets(self):
        users = self.assets.get('users', [])
        if not users:
            return ''
        rows = ''
        for u in users:
            upn = u.get('upn') or u.get('UPN') or '?'
            display = u.get('display_name') or u.get('DisplayName') or ''
            ac = u.get('alert_count') or u.get('AlertCount') or 0
            investigated = '✅' if any(inv.get('upn', '').lower() == upn.lower() or inv.get('user', '').lower() == upn.lower() for inv in self.user_inv) else ''
            rows += f'<tr><td>👤</td><td style="font-size:0.85em;">{esc(upn)}</td><td>{esc(display)}</td><td style="text-align:center;">{ac}</td><td style="text-align:center;">{investigated}</td></tr>'
        return f'''<div class="section"><h2>👤 User Assets ({len(users)})</h2>
<table><thead><tr><th style="width:25px;"></th><th>UPN</th><th>Name</th><th style="text-align:center;">Alerts</th><th style="text-align:center;">Investigated</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── Device Assets ────────────────────────────────────────────
    def _device_assets(self):
        devices = self.assets.get('devices', [])
        if not devices:
            return ''
        rows = ''
        for d in devices:
            host = d.get('hostname') or d.get('HostName') or d.get('fqdn') or d.get('FQDN') or '?'
            os_name = d.get('os') or d.get('OSFamily') or ''
            ac = d.get('alert_count') or d.get('AlertCount') or 0
            investigated = '✅' if any(inv.get('hostname', '').lower() == host.lower() or inv.get('device', '').lower() == host.lower() for inv in self.device_inv) else ''
            rows += f'<tr><td>💻</td><td>{esc(host)}</td><td>{esc(os_name)}</td><td style="text-align:center;">{ac}</td><td style="text-align:center;">{investigated}</td></tr>'
        return f'''<div class="section"><h2>💻 Device Assets ({len(devices)})</h2>
<table><thead><tr><th style="width:25px;"></th><th>Hostname</th><th>OS</th><th style="text-align:center;">Alerts</th><th style="text-align:center;">Investigated</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── IP Evidences ─────────────────────────────────────────────
    def _ip_evidences(self):
        ips = self.evidences.get('ip_addresses', [])
        if not ips:
            return ''
        rows = ''
        for ip_rec in ips[:15]:
            if isinstance(ip_rec, str):
                rows += f'<tr><td style="font-family:monospace;">{esc(defang_ip(ip_rec))}</td><td>—</td><td>—</td></tr>'
            else:
                addr = ip_rec.get('address') or ip_rec.get('IPAddress') or ip_rec.get('ip') or '?'
                ac = ip_rec.get('alert_count') or ip_rec.get('AlertCount') or ''
                alerts = ip_rec.get('alerts') or ip_rec.get('Alerts') or ''
                if isinstance(alerts, list): alerts = ', '.join(str(a) for a in alerts[:3])
                rows += f'<tr><td style="font-family:monospace;">{esc(defang_ip(addr))}</td><td style="text-align:center;">{ac}</td><td style="font-size:0.82em;">{esc(alerts)}</td></tr>'
        more = f'<p class="l" style="margin-top:4px;">Showing 15 of {len(ips)}</p>' if len(ips) > 15 else ''
        return f'''<div class="section"><h2>🌐 IP Evidences ({len(ips)})</h2>
<table><thead><tr><th>IP (defanged)</th><th style="text-align:center;">Alerts</th><th>Context</th></tr></thead><tbody>{rows}</tbody></table>{more}</div>'''

    # ─── URL/Domain Evidences ─────────────────────────────────────
    def _url_evidences(self):
        urls = self.evidences.get('urls', [])
        domains = self.evidences.get('domains', [])
        combined = []
        for u in urls:
            if isinstance(u, str):
                combined.append(('url', u, '', ''))
            else:
                combined.append(('url', u.get('value') or u.get('Value') or u.get('url') or '?',
                                 u.get('alert_count') or u.get('AlertCount') or '',
                                 u.get('alerts') or u.get('Alerts') or ''))
        for d in domains:
            if isinstance(d, str):
                combined.append(('dns', d, '', ''))
            else:
                combined.append(('dns', d.get('value') or d.get('Value') or d.get('domain') or '?',
                                 d.get('alert_count') or d.get('AlertCount') or '',
                                 d.get('alerts') or d.get('Alerts') or ''))
        if not combined:
            return ''
        rows = ''
        for typ, val, ac, alerts in combined[:15]:
            if isinstance(alerts, list): alerts = ', '.join(str(a) for a in alerts[:3])
            icon = '🔗' if typ == 'url' else '🌍'
            defanged = defang_url(val) if typ == 'url' else defang_url(val)
            rows += f'<tr><td>{icon}</td><td style="font-family:monospace;font-size:0.82em;word-break:break-all;">{esc(defanged)}</td><td style="text-align:center;">{ac}</td><td style="font-size:0.82em;">{esc(alerts)}</td></tr>'
        return f'''<div class="section"><h2>🔗 URLs & Domains ({len(combined)})</h2>
<table><thead><tr><th style="width:25px;"></th><th>Value (defanged)</th><th style="text-align:center;">Alerts</th><th>Context</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── File/Hash Evidences ──────────────────────────────────────
    def _file_evidences(self):
        files = self.evidences.get('files', [])
        hashes = self.evidences.get('file_hashes', [])
        combined = files + hashes
        if not combined:
            return ''
        rows = ''
        for f in combined[:15]:
            if isinstance(f, str):
                rows += f'<tr><td>📄</td><td>{esc(f)}</td><td>—</td><td>—</td></tr>'
            else:
                name = f.get('file_name') or f.get('FileName') or f.get('name') or ''
                hash_val = f.get('hash') or f.get('HashValue') or f.get('sha256') or f.get('sha1') or f.get('md5') or ''
                algo = f.get('hash_algorithm') or f.get('HashAlgorithm') or ''
                ac = f.get('alert_count') or f.get('AlertCount') or ''
                hash_display = f'{algo}: {hash_val[:16]}…' if len(str(hash_val)) > 16 else f'{algo}: {hash_val}' if hash_val else '—'
                rows += f'<tr><td>📄</td><td>{esc(name) or "—"}</td><td style="font-family:monospace;font-size:0.8em;">{esc(hash_display)}</td><td style="text-align:center;">{ac}</td></tr>'
        return f'''<div class="section"><h2>📄 File Evidences ({len(combined)})</h2>
<table><thead><tr><th style="width:25px;"></th><th>File</th><th>Hash</th><th style="text-align:center;">Alerts</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── Process Evidences ────────────────────────────────────────
    def _process_evidences(self):
        procs = self.evidences.get('processes', [])
        if not procs:
            return ''
        rows = ''
        for p in procs[:10]:
            if isinstance(p, str):
                rows += f'<tr><td>⚙️</td><td colspan="2" style="font-family:monospace;font-size:0.82em;">{esc(p)}</td></tr>'
            else:
                cmd = p.get('command_line') or p.get('ProcessCommandLine') or p.get('title') or '?'
                device = p.get('device') or p.get('DeviceName') or ''
                rows += f'<tr><td>⚙️</td><td style="font-family:monospace;font-size:0.82em;word-break:break-all;">{esc(cmd)}</td><td style="font-size:0.82em;">{esc(device)}</td></tr>'
        return f'''<div class="section"><h2>⚙️ Suspicious Processes ({len(procs)})</h2>
<table><thead><tr><th style="width:25px;"></th><th>Command Line</th><th>Device</th></tr></thead><tbody>{rows}</tbody></table></div>'''

    # ─── Sub-Investigation Summaries ──────────────────────────────
    def _sub_investigations(self):
        parts = []
        if self.user_inv:
            items = ''
            for inv in self.user_inv:
                user = inv.get('upn') or inv.get('user') or inv.get('display_name') or '?'
                risk = inv.get('risk_level') or inv.get('risk_assessment') or '—'
                findings = inv.get('key_findings') or inv.get('findings') or []
                if isinstance(findings, list):
                    findings = ', '.join(str(f) for f in findings[:3]) or '—'
                items += f'<div style="padding:8px;background:#2a2a2a;border-radius:4px;margin-bottom:6px;border-left:3px solid #00a1f1;"><div style="font-weight:600;">👤 {esc(user)}</div><div style="font-size:0.85em;color:#b0b0b0;margin-top:3px;">Risk: {esc(risk)} | {esc(findings)}</div></div>'
            parts.append(f'<div class="section"><h2>👤 User Investigation Results ({len(self.user_inv)})</h2>{items}</div>')

        if self.device_inv:
            items = ''
            for inv in self.device_inv:
                device = inv.get('hostname') or inv.get('device') or inv.get('device_name') or '?'
                risk = inv.get('risk_level') or inv.get('risk_assessment') or '—'
                findings = inv.get('key_findings') or inv.get('findings') or []
                if isinstance(findings, list):
                    findings = ', '.join(str(f) for f in findings[:3]) or '—'
                items += f'<div style="padding:8px;background:#2a2a2a;border-radius:4px;margin-bottom:6px;border-left:3px solid #9b59b6;"><div style="font-weight:600;">💻 {esc(device)}</div><div style="font-size:0.85em;color:#b0b0b0;margin-top:3px;">Risk: {esc(risk)} | {esc(findings)}</div></div>'
            parts.append(f'<div class="section"><h2>💻 Device Investigation Results ({len(self.device_inv)})</h2>{items}</div>')

        if self.ioc_inv:
            items = ''
            for inv in self.ioc_inv:
                ioc = inv.get('indicator') or inv.get('ioc') or inv.get('value') or '?'
                ioc_type = inv.get('type') or inv.get('ioc_type') or ''
                risk = inv.get('risk_level') or inv.get('risk_assessment') or '—'
                ioc_display = defang_ip(ioc) if ioc_type.lower() in ('ip', 'ipv4', 'ipv6') else defang_url(ioc) if ioc_type.lower() in ('url', 'domain', 'dns') else ioc
                items += f'<div style="padding:8px;background:#2a2a2a;border-radius:4px;margin-bottom:6px;border-left:3px solid #ff7f00;"><div style="font-weight:600;">🔍 [{esc(ioc_type)}] <span style="font-family:monospace;">{esc(ioc_display)}</span></div><div style="font-size:0.85em;color:#b0b0b0;margin-top:3px;">Risk: {esc(risk)}</div></div>'
            parts.append(f'<div class="section"><h2>🔍 IoC Investigation Results ({len(self.ioc_inv)})</h2>{items}</div>')

        return '\n'.join(parts)

    # ─── Security Assessment ──────────────────────────────────────
    def _assessment(self):
        risk = self.summary.get('risk_assessment', '')
        findings = self.summary.get('key_findings', [])
        if not risk and not findings:
            return ''
        risk_c = {'critical': '#f65314', 'high': '#f65314', 'medium': '#ffbb00', 'low': '#7cbb00'}.get((risk or '').lower(), '#737373')
        risk_html = f'<div style="text-align:center;margin:8px 0;"><span style="font-size:1.8em;font-weight:bold;color:{risk_c};">{esc(risk)}</span><div class="l">Overall Risk Assessment</div></div>' if risk else ''
        findings_html = ''
        if findings:
            items = ''
            for f in findings:
                items += f'<div class="alert" style="border-color:{risk_c};background:rgba({",".join(str(int(risk_c.lstrip("#")[i:i+2],16)) for i in (0,2,4))},0.1);">• {esc(f)}</div>'
            findings_html = items
        return f'<div class="section"><h2>⚠️ Security Assessment</h2>{risk_html}{findings_html}</div>'

    # ─── Recommendations ──────────────────────────────────────────
    def _recommendations(self):
        recs = self.summary.get('recommendations', [])
        if not recs:
            return ''
        items = ''.join(f'<li style="margin:4px 0;">{esc(r)}</li>' for r in recs)
        return f'''<div style="padding:12px;"><div class="section"><h2>💡 Recommendations</h2><ol style="font-size:0.92em;">{items}</ol></div></div>'''

    # ─── Full HTML ────────────────────────────────────────────────
    def generate(self, output_path=None):
        inc_id = self.meta.get('incident_id') or self.meta.get('provider_incident_id') or '?'
        title = self.inc_meta.get('title', 'Incident Investigation')
        sev = self.inc_meta.get('severity', '')
        status = self.inc_meta.get('status', '')
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        sev_c = severity_color(sev)

        if not output_path:
            ts = datetime.now().strftime('%Y-%m-%d_%H%M%S')
            output_path = f'Incident_{inc_id}_{ts}.html'
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

        left = '\n'.join(filter(None, [
            self._metadata_card(), self._mitre_card(), self._metrics(), self._phases()]))
        right = '\n'.join(filter(None, [
            self._assessment(), self._alerts_table(), self._user_assets(), self._device_assets(),
            self._ip_evidences(), self._url_evidences(), self._file_evidences(), self._process_evidences(),
            self._sub_investigations()]))

        html = f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Incident {esc(inc_id)} — {esc(title)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,sans-serif;font-size:13.5px;line-height:1.4;color:#e0e0e0;background:#1a1a1a;padding:12px}}
.ctr{{max-width:1600px;margin:0 auto;background:#1e1e1e;border-radius:7px;box-shadow:0 4px 20px rgba(0,0,0,0.5)}}
.wm{{position:fixed;top:0;left:0;right:0;background:linear-gradient(135deg,#dc3545,#c82333);color:white;padding:10px 20px;z-index:9999;box-shadow:0 2px 8px rgba(0,0,0,0.4);font-size:13px;font-weight:600;border-bottom:2px solid #ff6b6b;display:flex;justify-content:space-between;align-items:center}}
.hdr{{background:linear-gradient(135deg,#00a1f1,#0078d4);color:white;padding:18px 24px;display:flex;justify-content:space-between;align-items:center}}
.hdr h1{{font-size:1.5em;margin:0}}
.hdr .meta{{font-size:0.85em;text-align:right}}
.cnt{{display:grid;grid-template-columns:1.7fr 3.3fr;gap:12px;padding:12px}}
.section{{background:#252525;border-radius:5px;padding:14px;border-left:3px solid #00a1f1}}
.section h2{{font-size:1.15em;color:#00a1f1;margin-bottom:10px;padding-bottom:5px;border-bottom:1px solid #3a3a3a}}
.metrics{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}}
.metric{{padding:12px;border-radius:5px;text-align:center}}
.mv{{font-size:2em;font-weight:bold;color:white}}.ml{{font-size:0.95em;color:rgba(255,255,255,0.9);margin-top:2px}}
table{{width:100%;border-collapse:collapse;font-size:0.95em}}
th{{background:#2a2a2a;color:#00a1f1;padding:7px 10px;text-align:left;font-weight:600;border-bottom:2px solid #3a3a3a}}
td{{padding:6px 10px;border-bottom:1px solid #2a2a2a}}tr:hover{{background:#2a2a2a}}
.l{{color:#b0b0b0;font-weight:500}}
.alert{{padding:10px 14px;margin:7px 0;border-left:3px solid;border-radius:4px;font-size:0.95em}}
.alert-critical{{background:#3d1f1f;border-color:#f65314}}
ul,ol{{margin:7px 0 7px 24px;font-size:0.95em}}li{{margin:4px 0}}
.ftr{{background:#252525;padding:10px 20px;text-align:center;font-size:0.85em;color:#737373;border-top:1px solid #3a3a3a}}
</style></head><body>
<div class="wm"><div>🔒 <strong>CONFIDENTIAL — INCIDENT INVESTIGATION</strong></div><div style="font-size:12px;">Generated by <strong>{get_user()}</strong> on <strong>{get_host()}</strong> | {now_str}</div></div>
<div class="ctr" style="margin-top:50px;">
  <div class="hdr"><div><h1>🔍 Incident {esc(inc_id)} <span style="color:rgba(255,255,255,0.5);font-weight:300;">|</span> <span style="font-size:0.6em;font-weight:400;opacity:0.9;">{esc(title)}</span></h1>
    <div style="font-size:1em;opacity:0.9;margin-top:4px;">
      <span style="background:{sev_c};padding:3px 8px;border-radius:10px;font-size:0.8em;margin-right:6px;">{esc(sev)}</span>
      {status_badge(status)}
      <span style="background:rgba(255,255,255,0.2);padding:3px 8px;border-radius:10px;font-size:0.8em;margin-left:6px;">🔔 {len(self.alerts)} alerts</span>
    </div></div>
    <div class="meta"><div><strong>Generated:</strong> {now_str}</div><div><strong>Workspace:</strong> {esc(self.meta.get('workspace_id', ''))[:12]}…</div></div></div>
  <div class="cnt"><div style="display:flex;flex-direction:column;gap:12px;">{left}</div><div style="display:flex;flex-direction:column;gap:12px;">{right}</div></div>
  {self._recommendations()}
  <div class="ftr"><strong style="color:#f65314;">⚠️ CONFIDENTIAL</strong> — Incident Investigation Report | Incident {esc(inc_id)} | {now_str}</div>
</div></body></html>'''

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return output_path


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_html_report.py <json_file> [--output-dir DIR]")
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

    inc_id = data.get('investigation_metadata', {}).get('incident_id', 'unknown')
    ts = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    output_path = os.path.join(output_dir, f'Incident_{inc_id}_{ts}.html')

    gen = IncidentReportGenerator(data)
    path = gen.generate(output_path)
    print(f"✅ Report: {path}")


if __name__ == '__main__':
    main()
