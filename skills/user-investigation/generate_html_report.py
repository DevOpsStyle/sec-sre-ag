"""
Consolidated HTML Investigation Report Generator
Combines: investigator.py + report_generator.py + generate_report_from_json.py
into a single self-contained file with zero external dependencies.

Usage:
    python3 generate_html_report.py <json_file_path>

Reads a pre-enriched investigation JSON (produced by the agent) and generates
a styled HTML report with dark theme, two-column layout, IP intelligence cards,
pagination, timeline modal, and Copy KQL buttons.
"""

import json
import sys
import os
import socket
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════
# DATACLASSES (from investigator.py — report-relevant only)
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AnomalyFinding:
    detected_date: str; upn: str; anomaly_type: str; value: str
    severity: str; country: str; city: str
    country_novelty: bool; city_novelty: bool
    artifact_hits: int; first_seen: str

@dataclass
class IPIntelligence:
    ip: str; city: str; region: str; country: str; org: str; asn: str
    timezone: str; risk_level: str; assessment: str
    abuse_confidence_score: int = 0; is_whitelisted: bool = False
    total_reports: int = 0; is_vpn: bool = False
    is_proxy: bool = False; is_tor: bool = False; is_hosting: bool = False
    threat_detected: bool = False; threat_description: str = ""
    threat_confidence: int = 0; threat_tlp_level: str = ""
    threat_activity_groups: str = ""
    first_seen: str = ""; last_seen: str = ""; signin_count: int = 0
    success_count: int = 0; failure_count: int = 0
    anomaly_type: str = ""; hit_count: int = 0
    categories: list = None; last_auth_result_detail: str = ""

@dataclass
class UserProfile:
    display_name: str; upn: str; job_title: str; department: str
    office_location: str; account_enabled: bool; user_type: str

@dataclass
class MFAStatus:
    mfa_enabled: bool; methods_count: int; methods: List[str]
    has_fido2: bool; has_authenticator: bool

@dataclass
class DeviceInfo:
    display_name: str; operating_system: str; trust_type: str
    is_compliant: bool; approximate_last_sign_in: str

@dataclass
class RiskDetection:
    risk_event_type: str; risk_state: str; risk_level: str
    risk_detail: str; detected_date: str; last_updated: str
    activity: str; ip_address: str
    location_city: str; location_state: str; location_country: str

@dataclass
class RiskySignIn:
    sign_in_id: str; created_date: str; upn: str
    app_display_name: str; ip_address: str
    location_city: str; location_state: str; location_country: str
    risk_state: str; risk_level: str; risk_event_types: List[str]
    risk_detail: str; status_error_code: int; status_failure_reason: str

@dataclass
class DLPEvent:
    time_generated: str; user_id: str; device_name: str; client_ip: str
    rule_name: str; file_name: str; operation: str
    target_domain: str; target_file_path: str; severity: str = "High"

@dataclass
class UserRiskProfile:
    risk_level: str; risk_state: str; risk_detail: str
    risk_last_updated: str; is_deleted: bool; is_processing: bool

@dataclass
class InvestigationResult:
    upn: str; user_id: Optional[str]; investigation_date: str
    start_date: str; end_date: str
    anomalies: List[AnomalyFinding]; ip_intelligence: List[IPIntelligence]
    user_profile: Optional[UserProfile]; mfa_status: Optional[MFAStatus]
    devices: List[DeviceInfo]
    user_risk_profile: Optional[UserRiskProfile]
    risk_detections: List[RiskDetection]; risky_signins: List[RiskySignIn]
    signin_events: Dict[str, Any]; audit_events: List[Dict]
    office_events: List[Dict]; security_alerts: List[Dict]
    dlp_events: List[DLPEvent]
    risk_level: str; risk_factors: List[str]; mitigating_factors: List[str]
    critical_actions: List[str]; high_priority_actions: List[str]
    monitoring_actions: List[str]
    kql_queries: Optional[Dict[str, str]] = None
    result_counts: Optional[Dict[str, Dict[str, int]]] = None
    # These are set by main() after construction
    risk_assessment: Dict = field(default_factory=dict)
    recommendations: Dict = field(default_factory=dict)
    security_incidents: List = field(default_factory=list)



# ═══════════════════════════════════════════════════════════════════
# COMPACT REPORT GENERATOR (from report_generator.py)
# ═══════════════════════════════════════════════════════════════════

class CompactReportGenerator:
    """Generates compact HTML investigation reports with two-column layout"""

    def generate(self, result, output_path=None):
        if not output_path:
            ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
            user = result.upn.split('@')[0]
            output_path = f"reports/user-investigations/Investigation_Report_{user}_{ts}.html"
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self._html(result))
        return output_path

    def _get_user(self):
        try: return os.getlogin().upper()
        except: return os.environ.get('USERNAME', 'AGENT').upper()

    def _get_host(self):
        try: return socket.gethostname().upper()
        except: return 'UNKNOWN'

    def _mfa_badge(self, auth):
        if not auth: return ""
        if "Authentication failed" in auth or "MFA required" in auth:
            return '<span style="background:#f65314;color:white;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;">❌ Failed</span>'
        if auth == "Token":
            return '<span style="background:#00b7c3;color:white;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;">🎫 Token</span>'
        if "MFA requirement satisfied" in auth or "Passkey" in auth:
            return '<span style="background:#7cbb00;color:white;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;">🔒 MFA</span>'
        if "Correct password" in auth:
            return '<span style="background:#00a1f1;color:white;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;">🔑 Pwd</span>'
        if "First factor" in auth:
            return '<span style="background:#737373;color:white;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;">PWD</span>'
        return ""

    def _ip_type_info(self, org):
        ol = (org or '').lower()
        if any(p in ol for p in ['microsoft','azure']): return ("☁️ Azure Cloud", "#00a1f1", True)
        if any(p in ol for p in ['amazon','aws']): return ("☁️ AWS", "#ff9900", True)
        if any(p in ol for p in ['google','gcp']): return ("☁️ GCP", "#4285f4", True)
        if any(p in ol for p in ['cloudflare','akamai','fastly']): return ("☁️ CDN", "#00a1f1", True)
        if any(p in ol for p in ['vpn','proxy']): return ("🔒 VPN/Proxy", "#ffc107", False)
        if any(p in ol for p in ['hosting','datacenter']): return ("🖥️ Hosting", "#ffc107", False)
        if any(p in ol for p in ['telecom','communications','mobile']): return ("📱 Telecom", "#7cbb00", False)
        if any(p in ol for p in ['rogers','telus','comcast','verizon','at&t','bell']): return ("🏠 ISP", "#7cbb00", False)
        return ("🌐 ISP", "#b0b0b0", False)

    def _cat_badges(self, cats):
        if not cats: return ''
        m = {'threat':('#dc3545','🚨 THREAT'),'risky':('#ff7f00','⚠️ RISKY'),'anomaly':('#ffc107','ANOMALY'),
             'primary':('#007bff','PRIMARY'),'active':('#17a2b8','ACTIVE')}
        order = {'threat':0,'risky':1,'anomaly':2,'primary':3,'active':4}
        html = ''
        for c in sorted(cats, key=lambda x: order.get(x,99)):
            if c in m:
                bg, label = m[c]
                tc = '#1a1a1a' if c == 'anomaly' else 'white'
                html += f' <span style="background:{bg};color:{tc};padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;">{label}</span>'
        return html

    def _badge(self, level):
        m = {'CRITICAL':'#f65314','HIGH':'#f65314','MEDIUM':'#ffbb00','LOW':'#7cbb00','INFO':'#737373'}
        bg = m.get(level, '#737373')
        tc = '#1a1a1a' if level == 'MEDIUM' else 'white'
        return f'<span style="background:{bg};color:{tc};padding:2px 9px;border-radius:3px;font-size:0.9em;font-weight:600;">{level}</span>'

    # ─── IP Card ───────────────────────────────────────────────────
    def _ip_card(self, ip):
        border_m = {'CRITICAL':'#f65314','HIGH':'#f65314','MEDIUM':'#ffbb00','LOW':'#7cbb00'}
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
        return f'''<div style="background:#2a2a2a;border-left:3px solid {border};padding:11px;border-radius:5px;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
    <span style="font-weight:600;color:#00a1f1;font-size:1.1em;">{ip.ip}{self._cat_badges(ip.categories or [])}</span>{self._badge(ip.risk_level)}
  </div>
  <div style="font-size:0.92em;">
    <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
      <span><span class="l">Location:</span> {loc}</span>
      <span><span style="color:#7cbb00;">✓{ip.success_count or 0}</span> <span style="color:#dc3545;">✗{ip.failure_count or 0}</span></span>
    </div>{dates}
    <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
      <span><span class="l">Type:</span> <span style="color:{ip_tc};">{ip_type}{vpn_i}</span></span>
      <span><span class="l">Auth:</span> {self._mfa_badge(ip.last_auth_result_detail) or '<span class="l">N/A</span>'}</span>
    </div>
    <details style="margin-top:6px;"><summary style="cursor:pointer;color:#00a1f1;font-size:0.9em;background:#333;padding:4px 8px;border-radius:3px;">🔍 Details</summary>
      <div style="padding:6px;font-size:0.85em;color:#b0b0b0;margin-top:4px;">
        <div>Org: {ip.org}</div><div>ASN: {ip.asn}</div>
        <div>Type: <span style="color:{ip_tc};">{ip_type}{vpn_i}</span> | {status}</div>
        <div>Threat: <span style="color:{threat_color};">{threat_text}</span></div>
      </div>
    </details>
  </div></div>'''

    # ─── Table Helpers ─────────────────────────────────────────────
    def _table(self, headers, rows, id_attr=''):
        id_s = f' id="{id_attr}"' if id_attr else ''
        h = ''.join(f'<th style="{s}">{t}</th>' if s else f'<th>{t}</th>' for t, s in headers)
        r = ''.join(rows)
        return f'<table{id_s}><thead><tr>{h}</tr></thead><tbody>{r}</tbody></table>'

    def _section(self, title, body, kql_key=None):
        kql = f'<button class="kb" onclick="copyKQL(event,\'{kql_key}\')" title="Copy KQL">📋</button>' if kql_key else ''
        return f'<div class="section"><h2>{title}{kql}</h2>{body}</div>'

    # ─── Left Column Sections ─────────────────────────────────────
    def _metrics(self, r):
        se = r.signin_events or {}
        ts = se.get('total_signins', 0)
        tf = se.get('total_failures', 0)
        an = len(r.anomalies) if r.anomalies else 0
        dl = len(r.dlp_events) if r.dlp_events else 0
        ts_d = f"{ts/1000:.1f}K" if ts >= 1000 else str(ts)
        def m(v, l): return f'<div class="metric"><div class="mv">{v}</div><div class="ml">{l}</div></div>'
        return f'<div class="section"><h2>📊 Key Metrics</h2><div class="metrics">{m(an,"Anomalies")}{m(ts_d,"Sign-ins")}{m(dl,"DLP Events")}{m(tf,"Failures")}</div></div>'

    def _mfa(self, r):
        ms = r.mfa_status
        if not ms or not ms.mfa_enabled:
            body = '<span style="background:#f65314;color:white;padding:3px 8px;border-radius:3px;font-weight:600;">❌ No MFA</span>'
        else:
            nm = {'fido2AuthenticationMethod':'FIDO2','microsoftAuthenticatorAuthenticationMethod':'Authenticator',
                  'phoneAuthenticationMethod':'Phone','passwordAuthenticationMethod':'Password',
                  'emailAuthenticationMethod':'Email','softwareOathAuthenticationMethod':'Software Token'}
            body = ' '.join(f'<span style="background:#7cbb00;color:white;padding:3px 8px;border-radius:3px;font-size:0.85em;font-weight:600;">{nm.get(m,m.replace("AuthenticationMethod",""))}</span>' for m in (ms.methods or []))
        return f'<div class="section"><h2>🔐 MFA Status</h2><div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:6px;">{body}</div></div>'

    def _risk_assessment(self, r):
        ra = r.risk_assessment or {}
        rl = ra.get('risk_level','UNKNOWN')
        rf = ra.get('risk_factors',[])
        mf = ra.get('mitigating_factors',[])
        rf_h = f'<details open><summary>Risk Factors ({len(rf)})</summary><ul>{"".join(f"<li>{f}</li>" for f in rf)}</ul></details>' if rf else ''
        mf_h = f'<details open><summary>Mitigating Factors ({len(mf)})</summary><ul>{"".join(f"<li>{f}</li>" for f in mf)}</ul></details>' if mf else ''
        return f'<div class="section"><h2>🎯 Risk Assessment</h2><div style="margin-bottom:10px;"><strong>Overall:</strong> {self._badge(rl)}</div>{rf_h}{mf_h}</div>'

    def _critical_actions(self, r):
        rec = r.recommendations or {}
        crit = rec.get('critical_actions',[])
        high = rec.get('high_priority_actions',[])
        alerts = []
        for a in crit[:3]: alerts.append(f'<div class="alert alert-critical"><strong>🚨 CRITICAL:</strong> {a}</div>')
        for a in high[:2]: alerts.append(f'<div class="alert alert-high"><strong>⚠️ HIGH:</strong> {a}</div>')
        if not alerts: alerts.append('<div class="alert alert-medium"><strong>✓</strong> No critical actions</div>')
        return f'<div class="section"><h2>🎯 Critical Actions</h2>{"".join(alerts)}</div>'

    def _identity_protection(self, r):
        rp = r.user_risk_profile
        if not rp: return self._section('🛡️ Identity Protection','<p style="color:#7cbb00;">✓ No risk detected</p>')
        rl = (rp.risk_level or 'none').lower()
        rs = rp.risk_state or 'none'
        badge_m = {'none':('badge-info','✓'),'low':('badge-low','⚠️'),'medium':('badge-medium','⚠️'),'high':('badge-critical','🚨')}
        bc, icon = badge_m.get(rl, ('badge-info','ℹ️'))
        state_m = {'atRisk':('#f65314','Active Risk'),'dismissed':('#737373','Dismissed'),'remediated':('#7cbb00','Remediated'),'none':('#7cbb00','No Risk')}
        sc, sl = state_m.get(rs, ('#737373', rs))
        body = f'''<div style="margin-top:6px;">
  <div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span class="l">Risk Level:</span>{self._badge(rl.upper())}</div>
  <div style="display:flex;justify-content:space-between;"><span class="l">State:</span><span style="color:{sc};font-weight:500;">{sl}</span></div>
</div>'''
        return self._section('🛡️ Identity Protection', body)

    def _devices(self, r):
        devs = r.devices or []
        uid = r.user_id or ''
        dlink = f' <a href="https://security.microsoft.com/user?aad={uid}&tab=data&datatab=devices" target="_blank" style="color:#00a1f1;font-size:0.75em;">🛡️</a>' if uid else ''
        if not devs: return self._section(f'💻 Devices{dlink}','<p class="l">No registered devices</p>')
        rows = ''
        for d in devs[:5]:
            comp = '<span style="color:#7cbb00;">✓</span>' if d.is_compliant else '<span style="color:#f65314;">✗</span>'
            ls = d.approximate_last_sign_in[:10] if d.approximate_last_sign_in else 'N/A'
            rows += f'<tr><td>{d.display_name}</td><td>{d.operating_system}</td><td>{comp}</td><td>{ls}</td></tr>'
        tbl = self._table([('Device',''),('OS',''),('Compliant',''),('Last Seen','')], [rows])
        return self._section(f'💻 Devices{dlink}', tbl)

    def _top_locations(self, r):
        locs = (r.signin_events or {}).get('locations', [])
        if not locs: return self._section('📍 Top Locations','<p class="l">No location data</p>')
        rows = ''
        for l in sorted(locs, key=lambda x: x.get('SignInCount',0), reverse=True)[:6]:
            rows += f'<tr><td>{l["Location"]}</td><td style="text-align:center;">{l["SignInCount"]}</td><td style="text-align:center;color:#7cbb00;">✓{l["SuccessCount"]}</td><td style="text-align:center;color:#f65314;">✗{l["FailureCount"]}</td></tr>'
        tbl = self._table([('Location',''),('Total','text-align:center'),('Success','text-align:center'),('Failures','text-align:center')],[rows])
        return self._section('📍 Top Locations', tbl)

    def _top_apps(self, r):
        apps = (r.signin_events or {}).get('applications', [])
        if not apps: return self._section('📱 Top Applications','<p class="l">No app data</p>')
        rows = ''
        for a in sorted(apps, key=lambda x: x.get('SignInCount',0), reverse=True)[:8]:
            rows += f'<tr><td>{a["AppDisplayName"]}</td><td style="text-align:center;">{a["SignInCount"]}</td><td style="text-align:center;color:#7cbb00;">✓{a["SuccessCount"]}</td><td style="text-align:center;color:#f65314;">✗{a["FailureCount"]}</td></tr>'
        tbl = self._table([('Application',''),('Total','text-align:center'),('Success','text-align:center'),('Failures','text-align:center')],[rows])
        return self._section('📱 Top Applications', tbl)

    # ─── Right Column Sections ─────────────────────────────────────
    def _ip_intelligence(self, r):
        ips = r.ip_intelligence or []
        if not ips: return self._section('🌐 IP Intelligence','<p class="l">No IP data</p>')
        cards = '\n'.join(self._ip_card(ip) for ip in ips)
        return f'<div class="section"><h2>🌐 User Sign-in IP Intelligence</h2><div class="ip-grid">{cards}</div></div>'

    def _incidents(self, r):
        incs = r.security_incidents or []
        uid = r.user_id or ''
        dlink = f' <a href="https://security.microsoft.com/user?aad={uid}" target="_blank" style="color:#00a1f1;font-size:0.75em;">🛡️</a>' if uid else ''
        if not incs: return self._section(f'🚨 Security Incidents{dlink}','<p style="color:#7cbb00;">✓ No incidents detected</p>', 'incidents')
        rows = ''
        for i in incs[:10]:
            sev = i.get('Severity','Unknown')
            sev_bg = '#f65314' if sev=='High' else '#ffbb00' if sev=='Medium' else '#7cbb00'
            sev_tc = 'white' if sev != 'Medium' else '#1a1a1a'
            st = i.get('Status','Unknown')
            st_bg = '#f65314' if st in ('New','Active') else '#7cbb00' if st in ('Resolved','Closed') else '#00a1f1'
            title = i.get('Title','')
            title = title[:65]+'...' if len(title)>65 else title
            url = i.get('ProviderIncidentUrl','')
            t_html = f'<a href="{url}" target="_blank" style="color:#00a1f1;">{title}</a>' if url else title
            ct = i.get('CreatedTime','')[:10]
            owner = (i.get('OwnerUPN','') or 'Unassigned').split('@')[0]
            rows += f'''<tr><td>{ct}</td><td><span style="background:{sev_bg};color:{sev_tc};padding:2px 8px;border-radius:3px;font-size:0.85em;font-weight:600;">{sev}</span></td>
<td>{i.get("ProviderIncidentId","")}</td><td style="text-align:center;font-weight:bold;color:#00a1f1;">{i.get("AlertCount",1)}</td>
<td>{t_html}</td><td><span style="background:{st_bg};color:white;padding:2px 8px;border-radius:3px;font-size:0.85em;">{st}</span></td><td style="font-size:0.8em;">{owner}</td></tr>'''
        tbl = self._table([('Date',''),('Sev',''),('ID',''),('🔔','width:40px;text-align:center'),('Title',''),('Status',''),('Owner','')],[rows],'incTbl')
        return self._section(f'🚨 Security Incidents{dlink}', tbl, 'incidents')

    def _office(self, r):
        evts = r.office_events or []
        if not evts: return self._section('📈 Office 365 Activity','<p style="color:#7cbb00;">✓ No activity</p>','activity_summary')
        cards = ''.join(f'<div style="background:#2a2a2a;padding:10px;border-radius:4px;text-align:center;"><div style="font-size:1.5em;font-weight:bold;color:#7cbb00;">{e.get("ActivityCount",0)}</div><div style="font-size:0.8em;color:#b0b0b0;">{e.get("Operation","")}</div></div>' for e in evts[:5])
        return self._section('📈 Office 365 Activity', f'<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:8px;">{cards}</div>','activity_summary')

    def _dlp(self, r):
        evts = r.dlp_events or []
        if not evts: return self._section('📤 DLP Events','<p style="color:#7cbb00;">✓ No DLP events</p>','dlp')
        rows = ''
        for e in evts[:5]:
            op = e.operation
            if 'NetworkShare' in op: ob = '<span style="background:#f65314;color:white;padding:2px 6px;border-radius:3px;font-size:0.8em;">Network Share</span>'
            elif 'Cloud' in op or 'Upload' in op: ob = '<span style="background:#ffbb00;color:#1a1a1a;padding:2px 6px;border-radius:3px;font-size:0.8em;">Cloud Upload</span>'
            else: ob = f'<span style="background:#00a1f1;color:white;padding:2px 6px;border-radius:3px;font-size:0.8em;">{op}</span>'
            fn = e.file_name.split('\\')[-1] if e.file_name else 'Unknown'
            tgt = e.target_file_path or e.target_domain or ''
            rows += f'<tr><td>{e.time_generated[:16]}</td><td>{ob}</td><td title="{e.file_name}">{fn[:30]}</td><td>{tgt[:30]}</td><td>{e.client_ip}</td></tr>'
        tbl = self._table([('Time',''),('Op',''),('File',''),('Target',''),('IP','')],[rows])
        return self._section('📤 DLP Events', tbl, 'dlp')

    def _signin_failures(self, r):
        fails = (r.signin_events or {}).get('failures', [])
        if not fails: return self._section('🔒 Sign-in Failures','<p style="color:#7cbb00;">✓ No failures</p>','signin_failures')
        rows = ''
        for f in fails[:5]:
            ec = f.get('ResultType','')
            desc = f.get('ResultDescription','')
            if len(desc)>90: desc = desc[:87]+'...'
            cnt = f.get('FailureCount',0)
            apps = ', '.join(f.get('Applications',[])[:3])
            locs = ', '.join(f.get('Locations',[])[:2])
            rows += f'<tr><td>{ec}</td><td style="white-space:normal;word-wrap:break-word;">{desc}</td><td style="text-align:center;font-weight:bold;">{cnt}</td><td style="font-size:0.85em;">{apps}</td><td style="font-size:0.85em;">{locs}</td></tr>'
        tbl = self._table([('Error',''),('Description',''),('Count','text-align:center'),('Apps',''),('Locations','')],[rows])
        return self._section('🔒 Sign-in Failures', tbl, 'signin_failures')

    def _audit(self, r):
        evts = r.audit_events or []
        if not evts: return self._section('📋 Audit Log Activity','<p style="color:#7cbb00;">✓ No audit activity</p>','audit')
        rows = ''
        sensitive = ['password','reset','secret','credential','permission','consent','grant','role','admin','privilege','pim']
        cat_colors = {'GroupManagement':'#f65314','Authentication':'#00a1f1','UserManagement':'#7cbb00','RoleManagement':'#f65314','ApplicationManagement':'#7cbb00','Policy':'#ffbb00'}
        for e in evts:
            cat = e.get('Category','Unknown')
            cc = cat_colors.get(cat,'#737373')
            cnt = e.get('Count', e.get('count',0))
            res = e.get('Result','Unknown')
            rc = '#7cbb00' if res=='success' else '#f65314'
            ops = e.get('Operations',[])
            has_sens = any(kw in op.lower() for op in ops for kw in sensitive)
            rb = 'background:rgba(246,83,20,0.1);' if has_sens else ''
            ops_h = ', '.join(f'<span style="color:#f65314;font-weight:500;">🔐 {op}</span>' if any(kw in op.lower() for kw in sensitive) else op for op in ops)
            rows += f'<tr style="{rb}"><td><span style="background:{cc};color:white;padding:2px 6px;border-radius:3px;font-size:0.8em;">{cat}</span></td><td style="text-align:center;font-weight:bold;">{cnt}</td><td style="text-align:center;"><span style="background:{rc};color:white;padding:2px 6px;border-radius:3px;font-size:0.8em;">{res}</span></td><td style="font-size:0.85em;">{ops_h}</td></tr>'
        tbl = self._table([('Category',''),('Count','text-align:center'),('Result','text-align:center'),('Operations','')],[rows])
        return self._section('📋 Audit Log Activity', tbl, 'audit')

    # ─── Recommendations ───────────────────────────────────────────
    def _recommendations(self, r):
        rec = r.recommendations or {}
        def li_list(items, default='No actions required'):
            if not items: return f'<li>{default}</li>'
            return ''.join(f'<li>{a.replace("<strong>","").replace("</strong>","").replace("<br>",": ")}</li>' for a in items)
        c = li_list(rec.get('critical_actions',[]))
        h = li_list(rec.get('high_priority_actions',[]))
        m = li_list(rec.get('monitoring_actions',[]))
        return f'''<div style="padding:12px;"><div class="section"><h2>💡 Recommendations</h2>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;">
  <div><h3 style="color:#f65314;font-size:1em;margin-bottom:6px;">Critical</h3><ul style="font-size:0.85em;">{c}</ul></div>
  <div><h3 style="color:#ffbb00;font-size:1em;margin-bottom:6px;">High Priority</h3><ul style="font-size:0.85em;">{h}</ul></div>
  <div><h3 style="color:#00a1f1;font-size:1em;margin-bottom:6px;">Monitoring (14d)</h3><ul style="font-size:0.85em;">{m}</ul></div>
</div></div></div>'''

    # ─── Timeline Modal ────────────────────────────────────────────
    def _timeline(self, r):
        events = []
        for inc in (r.security_incidents or []):
            events.append({'t': inc.get('CreatedTime',''), 's': 'high', 'i': '🛡️',
                'title': f"Incident: {inc.get('Title','')[:60]}", 'detail': f"Status: {inc.get('Status','')} | Severity: {inc.get('Severity','')}"})
        for det in (r.risk_detections or []):
            events.append({'t': det.detected_date, 's': det.risk_level.lower() if det.risk_level else 'medium', 'i': '⚠️',
                'title': f"Risk: {det.risk_event_type}", 'detail': f"{det.location_city}, {det.location_country} ({det.ip_address}) - {det.risk_state}"})
        for dlp in (r.dlp_events or []):
            fn = dlp.file_name.split('\\')[-1] if '\\' in dlp.file_name else dlp.file_name
            events.append({'t': dlp.time_generated, 's': 'high', 'i': '📁', 'title': 'DLP Event', 'detail': f"{dlp.operation} - {fn}"})
        events.sort(key=lambda x: x['t'] or '', reverse=True)
        items = ''
        cur_date = None
        for e in events:
            if not e['t']: continue
            ed = e['t'][:10]
            et = e['t'][11:16] if len(e['t'])>16 else ''
            if ed != cur_date:
                cur_date = ed
                items += f'<div style="margin:20px 0 15px;padding:8px 12px;background:#2d2020;border-left:4px solid #00a1f1;border-radius:4px;"><span style="color:#00a1f1;font-weight:600;font-size:1.1em;">{ed}</span></div>'
            mc = {'high':'#f65314','medium':'#ffbb00','low':'#7cbb00'}.get(e['s'],'#ffbb00')
            items += f'''<div style="position:relative;margin-bottom:20px;padding-left:30px;">
  <div style="position:absolute;left:-20px;width:24px;height:24px;border-radius:50%;background:{mc};display:flex;align-items:center;justify-content:center;border:2px solid #1e1e1e;font-size:12px;">{e['i']}</div>
  <div style="background:#252525;padding:12px;border-radius:6px;border-left:3px solid #00a1f1;">
    <div style="color:#b0b0b0;font-size:0.85em;">{et} UTC</div>
    <div style="font-weight:600;margin-bottom:5px;">{e['title']}</div>
    <div style="color:#b0b0b0;font-size:0.9em;">{e['detail']}</div>
  </div></div>'''
        if not items: items = '<p class="l">No timeline events</p>'
        return f'''<div id="tlModal" style="display:none;position:fixed;z-index:1000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,0.8);">
<div style="background:#1e1e1e;margin:5% auto;padding:20px;border:1px solid #00a1f1;border-radius:8px;width:60%;max-width:900px;max-height:80vh;overflow-y:auto;">
  <span onclick="document.getElementById('tlModal').style.display='none'" style="float:right;font-size:28px;cursor:pointer;color:#aaa;">&times;</span>
  <h2 style="color:#00a1f1;margin-bottom:20px;">📅 Investigation Timeline</h2>
  <div style="position:relative;padding-left:30px;margin-top:20px;">{items}</div>
</div></div>'''

    # ─── Full HTML ─────────────────────────────────────────────────
    def _html(self, r):
        up = r.user_profile
        dn = up.display_name if up else r.upn.split('@')[0]
        jt = (up.job_title if up else None) or 'Unknown'
        dep = (up.department if up else None) or 'Unknown'
        ol = (up.office_location if up else None) or 'Unknown'
        ut = up.user_type if up else 'Member'
        uid = r.user_id or ''
        dlink = f' <a href="https://security.microsoft.com/user?aad={uid}" target="_blank" style="color:white;font-size:0.6em;">🛡️</a>' if uid else ''
        se = r.signin_events or {}
        loc_badges = ''.join(f'<span style="background:#7cbb00;color:white;padding:3px 8px;border-radius:10px;font-size:0.7em;font-weight:500;margin-right:6px;">📍 {l["Location"]}</span>' for l in sorted(se.get('locations',[]), key=lambda x: x.get('SignInCount',0), reverse=True)[:4])
        left = '\n'.join([self._metrics(r), self._mfa(r), self._risk_assessment(r), self._critical_actions(r), self._identity_protection(r), self._devices(r), self._top_locations(r), self._top_apps(r)])
        right = '\n'.join([self._ip_intelligence(r), self._incidents(r), self._office(r), self._dlp(r), self._signin_failures(r), self._audit(r)])
        return f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Investigation Report - {r.upn}</title>
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
.kb{{background:none;border:none;color:#00a1f1;cursor:pointer;font-size:0.9em;padding:0 8px;position:absolute;right:0;top:6px}}.kb:hover{{color:#0078d4}}
.ftr{{background:#252525;padding:10px 20px;text-align:center;font-size:0.85em;color:#737373;border-top:1px solid #3a3a3a}}
.tb{{background:linear-gradient(135deg,#00a1f1,#0078d4);color:white;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:0.9em;font-weight:600;width:100%}}.tb:hover{{background:linear-gradient(135deg,#0078d4,#005a9e)}}
</style></head><body>
<div class="wm"><div>🔒 <strong>CONFIDENTIAL - INTERNAL USE ONLY</strong></div><div style="font-size:12px;">Generated by <strong>{self._get_user()}</strong> on <strong>{self._get_host()}</strong> | {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}</div></div>
<div class="ctr" style="margin-top:50px;">
  <div class="hdr"><div><h1>{dn}{dlink} <span style="color:rgba(255,255,255,0.7);font-weight:300;">|</span> <span style="font-size:0.6em;font-weight:400;opacity:0.9;">{r.upn} • {jt}</span></h1>
    <div style="font-size:1em;opacity:0.9;margin-top:4px;">{dep} • {ol} • {loc_badges}<br><span style="color:#90ee90;">● Active</span> • {ut}</div></div>
    <div class="meta"><div><strong>Investigation:</strong> {r.investigation_date}</div><div><strong>Period:</strong> {r.start_date} → {r.end_date}</div>
    <div style="margin-top:8px;"><button class="tb" onclick="document.getElementById('tlModal').style.display='block'">📅 View Timeline</button></div></div></div>
  <div class="cnt"><div style="display:flex;flex-direction:column;gap:12px;">{left}</div><div style="display:flex;flex-direction:column;gap:12px;">{right}</div></div>
  {self._recommendations(r)}
  <div class="ftr"><strong style="color:#f65314;">⚠️ CONFIDENTIAL</strong> — Security Investigation Report | {r.investigation_date} | {r.start_date} → {r.end_date}</div>
</div>
{self._timeline(r)}
<script>
function copyKQL(e,k){{e.stopPropagation();const q=window._kql&&window._kql[k]||'Query not available';navigator.clipboard.writeText(q).then(()=>{{const b=e.target;b.textContent='✓';b.style.color='#7cbb00';setTimeout(()=>{{b.textContent='📋';b.style.color='#00a1f1'}},2000)}})}}
document.addEventListener('keydown',e=>{{if(e.key==='Escape')document.getElementById('tlModal').style.display='none'}});
window.onclick=e=>{{if(e.target.id==='tlModal')e.target.style.display='none'}};
</script></body></html>'''


# ═══════════════════════════════════════════════════════════════════
# MAIN: JSON → Dataclasses → HTML (from generate_report_from_json.py)
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
    anomalies_data = data.get('anomalies', [])
    signin_apps = data.get('signin_apps', [])
    signin_locs = data.get('signin_locations', [])
    signin_fails = data.get('signin_failures', [])
    signin_ips = data.get('signin_ip_counts', [])
    audit_data = data.get('audit_events', [])
    office_data = data.get('office_events', [])
    dlp_data = data.get('dlp_events', [])
    incidents_data = data.get('incidents', [])
    up_data = data.get('user_profile')
    mfa_data = data.get('mfa_methods')
    devices_data = data.get('devices', [])
    rp_data = data.get('risk_profile')
    rd_data = data.get('risk_detections', [])
    rs_data = data.get('risky_signins', [])

    # Build InvestigationResult
    result = InvestigationResult(
        upn=data['upn'], user_id=data.get('user_id'),
        investigation_date=data['investigation_date'],
        start_date=data['start_date'], end_date=data['end_date'],
        anomalies=[AnomalyFinding(
            detected_date=a['DetectedDateTime'], upn=a['UserPrincipalName'],
            anomaly_type=a['AnomalyType'], value=a['Value'], severity=a['Severity'],
            country=a['Country'], city=a['City'],
            country_novelty=a['CountryNovelty'], city_novelty=a['CityNovelty'],
            artifact_hits=a['ArtifactHits'], first_seen=a['FirstSeenRecent']
        ) for a in anomalies_data],
        ip_intelligence=[],
        user_profile=UserProfile(
            display_name=up_data['displayName'], upn=up_data['userPrincipalName'],
            job_title=up_data.get('jobTitle'), department=up_data.get('department'),
            office_location=up_data.get('officeLocation'),
            account_enabled=up_data.get('accountEnabled', True),
            user_type=up_data.get('userType', 'Member')
        ) if up_data else None,
        mfa_status=None, devices=[
            DeviceInfo(display_name=d['displayName'], operating_system=d['operatingSystem'],
                trust_type=d['trustType'], is_compliant=d['isCompliant'],
                approximate_last_sign_in=d.get('approximateLastSignInDateTime','')[:10])
            for d in devices_data],
        user_risk_profile=UserRiskProfile(
            risk_level=rp_data['riskLevel'], risk_state=rp_data['riskState'],
            risk_detail=rp_data['riskDetail'],
            risk_last_updated=rp_data['riskLastUpdatedDateTime'],
            is_deleted=rp_data['isDeleted'], is_processing=rp_data['isProcessing']
        ) if rp_data else None,
        risk_detections=[RiskDetection(
            risk_event_type=rd['riskEventType'], risk_state=rd['riskState'],
            risk_level=rd['riskLevel'], risk_detail=rd['riskDetail'],
            detected_date=rd['detectedDateTime'],
            last_updated=rd.get('lastUpdatedDateTime', rd['detectedDateTime']),
            activity=rd['activity'], ip_address=rd['ipAddress'],
            location_city=rd['location']['city'], location_state=rd['location']['state'],
            location_country=rd['location']['countryOrRegion']
        ) for rd in rd_data],
        risky_signins=[RiskySignIn(
            sign_in_id=rs['id'], created_date=rs['createdDateTime'],
            upn=rs['userPrincipalName'], app_display_name=rs['appDisplayName'],
            ip_address=rs['ipAddress'],
            location_city=rs['location']['city'], location_state=rs['location']['state'],
            location_country=rs['location']['countryOrRegion'],
            risk_state=rs['riskState'], risk_level=rs['riskLevelDuringSignIn'],
            risk_event_types=rs['riskEventTypes_v2'], risk_detail=rs['riskDetail'],
            status_error_code=rs['status']['errorCode'],
            status_failure_reason=rs['status']['failureReason']
        ) for rs in rs_data],
        signin_events={}, audit_events=audit_data, office_events=office_data,
        dlp_events=[DLPEvent(
            time_generated=d['TimeGenerated'], user_id=d['UserId'],
            device_name=d['DeviceName'], client_ip=d['ClientIP'],
            rule_name=d['RuleName'], file_name=d['File'],
            operation=d['Operation'], target_domain=d.get('TargetDomain',''),
            target_file_path=d.get('TargetFilePath','')
        ) for d in dlp_data],
        security_alerts=[], risk_level="MEDIUM", risk_factors=[], mitigating_factors=[],
        critical_actions=[], high_priority_actions=[], monitoring_actions=[]
    )

    # MFA
    if mfa_data:
        methods = []
        if 'value' in mfa_data:
            methods = [m['@odata.type'].split('.')[-1] for m in mfa_data['value']]
        elif 'methods' in mfa_data:
            methods = [m['type']+'AuthenticationMethod' for m in mfa_data['methods']]
        if methods:
            result.mfa_status = MFAStatus(
                mfa_enabled=len(methods) > 1, methods_count=len(methods), methods=methods,
                has_fido2=any('fido2' in m.lower() or 'passkey' in m.lower() for m in methods),
                has_authenticator=any('authenticator' in m.lower() for m in methods))

    # Sign-in events
    ti = sum(ip.get('SignInCount',0) for ip in signin_ips)
    tf = sum(f.get('FailureCount',0) for f in signin_fails)
    result.signin_events = {
        'by_application': signin_apps, 'applications': signin_apps,
        'by_location': signin_locs, 'locations': signin_locs,
        'failures': signin_fails,
        'total_signins': ti if ti > 0 else sum(a.get('SignInCount',0) for a in signin_apps),
        'total_success': ti - tf, 'total_failures': tf
    }

    # Incidents
    result.security_incidents = [{
        'IncidentNumber': i.get('IncidentNumber', i.get('ProviderIncidentId','N/A')),
        'ProviderIncidentId': i.get('ProviderIncidentId','N/A'),
        'Title': i['Title'], 'Severity': i['Severity'], 'Status': i['Status'],
        'CreatedTime': i['CreatedTime'], 'ProviderIncidentUrl': i.get('ProviderIncidentUrl',''),
        'OwnerUPN': i.get('OwnerUPN','Unassigned'), 'AlertCount': i.get('AlertCount',1),
        'title': i['Title'], 'severity': i['Severity'], 'status': i['Status'],
        'created_time': i['CreatedTime']
    } for i in incidents_data]

    # IP enrichment (from cached data — no fresh API calls)
    ip_enrichment = data.get('ip_enrichment', [])
    ip_freq = {e['IPAddress']: e.get('SignInCount',0) for e in signin_ips}
    ip_timeline = {e['IPAddress']: {'FirstSeen': e.get('FirstSeen',''), 'LastSeen': e.get('LastSeen','')} for e in signin_ips if e.get('FirstSeen')}
    ip_auth = {e['IPAddress']: e.get('LastAuthResultDetail','') for e in signin_ips}
    ip_sf = {e['IPAddress']: {'S': e.get('SuccessCount',0), 'F': e.get('FailureCount',0)} for e in signin_ips}

    # Assign categories
    counts = sorted(ip_freq.values(), reverse=True)
    high_t = counts[max(0, int(len(counts)*0.10)-1)] if counts else 0

    for ip_e in ip_enrichment:
        ip = ip_e['ip']
        cats = []
        if ip_freq.get(ip, 0) >= high_t: cats.append('primary')
        intel = IPIntelligence(
            ip=ip, city=ip_e.get('city','Unknown'), region=ip_e.get('region','Unknown'),
            country=ip_e.get('country','Unknown'), org=ip_e.get('org','Unknown'),
            asn=ip_e.get('asn','Unknown'), timezone=ip_e.get('timezone','Unknown'),
            risk_level=ip_e.get('risk_level','LOW'), assessment=ip_e.get('assessment',''),
            abuse_confidence_score=ip_e.get('abuse_confidence_score',0),
            is_whitelisted=ip_e.get('is_whitelisted',False),
            total_reports=ip_e.get('total_reports',0),
            is_vpn=ip_e.get('is_vpn',False), is_proxy=ip_e.get('is_proxy',False),
            is_tor=ip_e.get('is_tor',False), is_hosting=ip_e.get('is_hosting',False),
            threat_description=ip_e.get('threat_description',''),
            categories=cats,
            signin_count=ip_freq.get(ip, 0),
            success_count=ip_sf.get(ip,{}).get('S',0),
            failure_count=ip_sf.get(ip,{}).get('F',0),
            last_auth_result_detail=ip_auth.get(ip,''),
            first_seen=ip_timeline.get(ip,{}).get('FirstSeen',''),
            last_seen=ip_timeline.get(ip,{}).get('LastSeen','')
        )
        result.ip_intelligence.append(intel)
    print(f"  Loaded {len(result.ip_intelligence)} IPs from cache")

    # Risk assessment
    risk_factors, mitigating = [], []
    open_incs = [i for i in result.security_incidents if i.get('status') != 'Closed']
    if open_incs:
        risk_factors.append(f'🚨 <strong>Active incidents:</strong> {len(open_incs)} open')
    se = result.signin_events
    ts, tfl = se.get('total_signins',0), se.get('total_failures',0)
    if ts > 0 and tfl/ts > 0.2:
        risk_factors.append(f'🟠 <strong>High failure rate:</strong> {tfl/ts*100:.1f}%')
    vpn_ips = [ip for ip in result.ip_intelligence if ip.is_vpn and not any(p in (ip.org or '').lower() for p in ['microsoft','azure','amazon','google'])]
    if vpn_ips:
        risk_factors.append(f'🎭 <strong>VPN/Proxy:</strong> {len(vpn_ips)} anonymous IPs')
    if result.mfa_status and result.mfa_status.mfa_enabled:
        mitigating.append(f'✅ MFA active ({result.mfa_status.methods_count} methods)')
    if ts > 0:
        mitigating.append(f'✅ {(ts-tfl)/ts*100:.1f}% sign-in success rate')
    threat_ips = [ip for ip in result.ip_intelligence if ip.threat_description]
    if not threat_ips:
        mitigating.append('✅ No threat intel matches on IPs')
    if result.user_risk_profile and result.user_risk_profile.risk_level == 'none':
        mitigating.append('✅ Identity Protection: no risk')
    score = max(0, min(100, len(risk_factors)*10 - len(mitigating)*5 + 30))
    rl = 'HIGH' if score >= 70 else 'MEDIUM' if score >= 40 else 'LOW'
    result.risk_assessment = {'risk_level': rl, 'risk_score': score, 'risk_factors': risk_factors, 'mitigating_factors': mitigating}

    # Recommendations
    crit, high_p, mon = [], [], []
    if open_incs:
        high_p.append(f'<strong>Review {len(open_incs)} open incidents</strong><br>Triage and classify')
    for a in audit_data:
        if any('PIM' in op for op in a.get('Operations',[])):
            high_p.append('<strong>Verify PIM activations</strong><br>Confirm authorization')
            break
    mon.append('Watch for sign-ins from non-Azure IPs')
    mon.append('Monitor for additional PIM activations')
    mon.append('Continue normal monitoring procedures')
    result.recommendations = {'critical_actions': crit, 'high_priority_actions': high_p, 'monitoring_actions': mon}

    # Generate HTML
    print("Generating HTML report...")
    gen = CompactReportGenerator()
    path = gen.generate(result)
    print(f"✅ Report: {path}")

if __name__ == "__main__":
    main()
