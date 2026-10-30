"""
Identity Posture HTML Report Generator
=======================================
Self-contained HTML report generator for identity security posture assessments.
Zero external dependencies — Python 3 stdlib only.

Usage:
    python3 generate_html_report.py <input_dir> [--output-dir DIR] [--tenant NAME]

Reads pre-collected Graph API + KQL JSON files from <input_dir> (same input
format as analyze-identity-posture.py), computes all metrics and the Identity
Posture Score, and generates a styled HTML report with dark theme.
"""

import json
import sys
import os
import glob
import socket
from datetime import datetime, timezone
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════

HIGH_PRIV_ROLES = {
    "Global Administrator", "Security Administrator", "Exchange Administrator",
    "SharePoint Administrator", "Application Administrator",
    "Cloud App Security Administrator", "Privileged Role Administrator",
    "Intune Administrator", "Intune Service Administrator",
    "Compliance Administrator", "Privileged Authentication Administrator",
    "User Administrator", "Azure AD Joined Device Local Administrator",
    "Conditional Access Administrator", "Security Operator",
    "Authentication Administrator", "Helpdesk Administrator",
    "Groups Administrator", "Identity Governance Administrator",
}
SERVICE_ACCOUNT_PATTERNS = [
    "serviceaccount", "securitycopilotagentuser", "phishinganalysisreports",
    "userreportingmbx", "slrtravelplanner", "automation account",
]
AGENT_UPN_PREFIXES = ["securitycopilotagentuser", "slrtravelplanner"]

# ═══════════════════════════════════════════════════════════════════
# DATA LOADING
# ═══════════════════════════════════════════════════════════════════

def find_latest(d, prefix):
    files = sorted(glob.glob(os.path.join(d, f"{prefix}_*.json")))
    return files[-1] if files else None

def load_json_array(path, label):
    if not path: return []
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        arr = data.get('value', data) if isinstance(data, dict) else data
        return arr if isinstance(arr, list) else [arr]
    except Exception:
        return []

def load_kql_results(path, label):
    if not path: return []
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        arr = data.get('results', data.get('value', data))
        return arr if isinstance(arr, list) else ([arr] if arr else [])
    except Exception:
        return []

# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

def safe_int(v, d=0):
    try: return int(v)
    except (TypeError, ValueError): return d

def pct(n, d):
    return round(n / d * 100, 1) if d > 0 else 0.0

def is_guest(upn): return '#EXT#' in upn

def is_agent_user(u):
    if u.get('@odata.type') == '#microsoft.graph.agentUser': return True
    upn = (u.get('userPrincipalName') or '').lower()
    return any(upn.split('@')[0].startswith(p) for p in AGENT_UPN_PREFIXES)

def is_service_account(u):
    upn = (u.get('userPrincipalName') or '').lower()
    name = (u.get('displayName') or '').lower()
    if is_agent_user(u): return True
    if upn.startswith('spam@'): return True
    return any(p in upn or p in name for p in SERVICE_ACCOUNT_PATTERNS)

def get_user():
    try: return os.getlogin().upper()
    except Exception: return os.environ.get('USERNAME', 'AGENT').upper()

def get_host():
    try: return socket.gethostname().upper()
    except Exception: return 'UNKNOWN'

# ═══════════════════════════════════════════════════════════════════
# ANALYZER (same logic as analyze-identity-posture.py)
# ═══════════════════════════════════════════════════════════════════

class PostureAnalyzer:
    def __init__(self, input_dir):
        self.input_dir = input_dir
        self.now = datetime.now(timezone.utc)
        self.m = {}

    def load_all(self):
        d = self.input_dir
        self.users   = load_json_array(find_latest(d, 'users'), 'Users')
        self.roles   = load_json_array(find_latest(d, 'directory_roles'), 'Roles')
        self.pim     = load_json_array(find_latest(d, 'pim_eligible_roles'), 'PIM')
        self.risky   = load_json_array(find_latest(d, 'risky_users'), 'Risky')
        self.deleted = load_json_array(find_latest(d, 'deleted_users'), 'Deleted')
        self.mfa     = load_json_array(find_latest(d, 'mfa_registration'), 'MFA')
        self.kql_uac          = load_kql_results(find_latest(d, 'kql_uac_flags'), 'UAC')
        self.kql_tags         = load_kql_results(find_latest(d, 'kql_mdi_tags'), 'Tags')
        self.kql_risk         = load_kql_results(find_latest(d, 'kql_identity_risk'), 'Risk')
        self.kql_builtin      = load_kql_results(find_latest(d, 'kql_builtin_accounts'), 'BuiltIn')
        self.kql_stale_summary= load_kql_results(find_latest(d, 'kql_stale_summary'), 'StaleSummary')
        self.kql_stale_detail = load_kql_results(find_latest(d, 'kql_stale_detail'), 'StaleDetail')
        self.kql_cross_domain = load_kql_results(find_latest(d, 'kql_cross_domain'), 'CrossDomain')
        self.kql_service      = load_kql_results(find_latest(d, 'kql_service_accounts'), 'Service')
        if not self.users:
            print("[CRITICAL] No user data found.", file=sys.stderr); sys.exit(1)

    def compute_all(self):
        m = self.m
        users = self.users
        # Inventory
        m['total'] = len(users)
        mfa_by_id = {r.get('id'): r for r in self.mfa}
        guests, members, agents = 0, 0, 0
        for u in users:
            uid = u.get('id')
            utype = u.get('userType')
            if not utype and uid in mfa_by_id:
                utype = mfa_by_id[uid].get('userType')
            if not utype:
                utype = 'Guest' if is_guest(u.get('userPrincipalName', '')) else 'Member'
            u['_resolved_type'] = utype.lower() if utype else 'member'
            if is_agent_user(u):
                agents += 1; u['_category'] = 'agent'
            elif is_service_account(u):
                u['_category'] = 'service'
            elif u['_resolved_type'] == 'guest':
                guests += 1; u['_category'] = 'guest'
            else:
                members += 1; u['_category'] = 'member'
        m['guests'], m['members'], m['agents'] = guests, members, agents
        m['hybrid'] = sum(1 for u in users if u.get('onPremisesSyncEnabled') is True)
        m['cloud_only'] = m['total'] - m['hybrid']
        if self.kql_cross_domain:
            cd = self.kql_cross_domain[0]
            m['ii_total'] = safe_int(cd.get('TotalAccounts'))
            m['ii_enabled'] = safe_int(cd.get('EnabledAccounts'))
        else:
            m['ii_total'] = m['ii_enabled'] = 0

        # Privilege
        perm_accounts, role_counts = {}, {}
        for role in self.roles:
            rname = role.get('displayName', '')
            members_list = role.get('members', [])
            role_counts[rname] = len(members_list)
            if rname in HIGH_PRIV_ROLES:
                for mem in members_list:
                    upn = mem.get('userPrincipalName', 'unknown')
                    perm_accounts.setdefault(upn, []).append(rname)
        pim_accounts = {}
        for inst in self.pim:
            upn = inst.get('principal', {}).get('userPrincipalName', 'unknown')
            rname = inst.get('roleDefinition', {}).get('displayName', 'unknown')
            pim_accounts.setdefault(upn, []).append(rname)
        m['perm_high_priv'] = perm_accounts
        m['pim_accounts'] = pim_accounts
        m['n_perm_high'] = len(perm_accounts)
        m['n_pim'] = len(pim_accounts)
        m['roles_available'] = len(self.roles) > 0
        m['pim_available'] = len(self.pim) > 0
        admin_from_mfa = {r.get('userPrincipalName'): r for r in self.mfa if r.get('isAdmin')}
        m['admin_from_mfa'] = admin_from_mfa
        m['n_admin_mfa'] = len(admin_from_mfa)

        # Stale
        active_upns = set()
        for row in self.kql_stale_detail:
            upn = (row.get('UPN') or '').strip().lower()
            if upn: active_upns.add(upn)
        for u in self.users:
            sia = u.get('signInActivity')
            if sia and (sia.get('lastSignInDateTime') or sia.get('lastNonInteractiveSignInDateTime')):
                active_upns.add(u.get('userPrincipalName', '').lower())
        stale = [u for u in self.users if u.get('userPrincipalName', '').lower() not in active_upns and not is_service_account(u)]
        m['stale_accounts'] = stale
        m['n_stale'] = len(stale)
        m['stale_pct'] = pct(len(stale), m['total'])

        # Password
        pwd_ages, disable_pwd_expiry, with_pwd_data = [], 0, 0
        for u in self.users:
            lpcd = u.get('lastPasswordChangeDateTime')
            if lpcd:
                with_pwd_data += 1
                try:
                    dt = datetime.fromisoformat(lpcd.replace('Z', '+00:00'))
                    pwd_ages.append((self.now - dt).days)
                except (ValueError, TypeError): pass
            if 'DisablePasswordExpiration' in (u.get('passwordPolicies') or ''):
                disable_pwd_expiry += 1
        m['pwd_with_data'] = with_pwd_data
        m['pwd_disable_expiry'] = disable_pwd_expiry
        m['pwd_avg_age'] = round(sum(pwd_ages) / len(pwd_ages)) if pwd_ages else None
        m['pwd_max_age'] = max(pwd_ages) if pwd_ages else None
        m['pwd_over_365'] = sum(1 for a in pwd_ages if a > 365)
        if self.kql_uac:
            u0 = self.kql_uac[0]
            m['uac_with_data'] = safe_int(u0.get('WithUACData'))
            m['uac_pwd_never_expires'] = safe_int(u0.get('PwdNeverExpiresCount'))
            m['uac_pwd_not_required'] = safe_int(u0.get('PwdNotRequiredCount'))
        else:
            m['uac_with_data'] = m['uac_pwd_never_expires'] = m['uac_pwd_not_required'] = 0

        # MFA
        mfa = self.mfa
        m['mfa_total'] = len(mfa)
        m['mfa_registered'] = sum(1 for r in mfa if r.get('isMfaRegistered'))
        m['mfa_capable'] = sum(1 for r in mfa if r.get('isMfaCapable'))
        m['mfa_pwdless'] = sum(1 for r in mfa if r.get('isPasswordlessCapable'))
        m['mfa_sspr'] = sum(1 for r in mfa if r.get('isSsprRegistered'))
        m['mfa_not_reg'] = m['mfa_total'] - m['mfa_registered']
        m['mfa_pct'] = pct(m['mfa_registered'], m['mfa_total'])
        methods = {}
        for r in mfa:
            for meth in (r.get('methodsRegistered') or []):
                methods[meth] = methods.get(meth, 0) + 1
        m['mfa_methods'] = dict(sorted(methods.items(), key=lambda x: -x[1]))
        # Admin without MFA
        admin_no_mfa = []
        if m['roles_available']:
            mfa_by_upn = {r.get('userPrincipalName', '').lower(): r for r in mfa}
            for upn in m['perm_high_priv']:
                mr = mfa_by_upn.get(upn.lower())
                if mr and not mr.get('isMfaRegistered'):
                    admin_no_mfa.append(mr)
        else:
            admin_no_mfa = [r for r in mfa if r.get('isAdmin') and not r.get('isMfaRegistered')]
        m['admin_no_mfa'] = admin_no_mfa
        m['n_admin_no_mfa'] = len(admin_no_mfa)

        # Risk
        m['risky_users'] = self.risky
        m['high_risk'] = [r for r in self.risky if (r.get('riskLevel') or '').lower() == 'high']
        m['n_high_risk'] = len(m['high_risk'])
        m['n_at_risk'] = len([r for r in self.risky if r.get('riskState') in ('atRisk', 'confirmedCompromised')])

        # Tags / Deleted
        m['mdi_tags'] = self.kql_tags
        m['kql_builtin'] = self.kql_builtin
        m['deleted_users'] = self.deleted
        m['n_deleted'] = len(self.deleted)

        # Score
        sp = m['stale_pct']
        d1 = min(20, max(0, int(sp)) if sp <= 5 else (6 + int(sp - 5) if sp <= 15 else min(20, 12 + int(sp - 15) // 3)))
        d1_detail = f"{m['n_stale']} stale ({sp:.0f}%)"
        if m['roles_available']:
            n_perm = m['n_perm_high']
            d2 = n_perm if n_perm <= 5 else (10 + (n_perm - 5) if n_perm <= 15 else 18)
            if m['n_admin_no_mfa'] > 0: d2 = min(20, d2 + m['n_admin_no_mfa'] * 2)
        else:
            d2 = min(20, 8 + m['n_admin_no_mfa'] * 3)
        d2 = min(d2, 20)
        d2_detail = f"{m.get('n_perm_high', m['n_admin_mfa'])} priv, {m['n_admin_no_mfa']} no MFA"
        uac_pne = m['uac_pwd_never_expires']; uac_total = m['uac_with_data']
        pne_pct = pct(uac_pne, uac_total) if uac_total > 0 else 0
        d3 = max(0, int(pne_pct)) if pne_pct <= 10 else (8 + int((pne_pct - 10) / 5) if pne_pct <= 40 else 14)
        if m['pwd_disable_expiry'] > 0: d3 = min(20, d3 + min(6, m['pwd_disable_expiry']))
        d3 = min(d3, 20); d3_detail = f"{uac_pne}/{uac_total} PwdNeverExp"
        mfa_p = m['mfa_pct']
        d4 = (12 if mfa_p < 50 else (8 if mfa_p < 80 else (4 if mfa_p < 95 else 0)))
        if m['n_high_risk'] > 0: d4 += 6
        d4 = min(d4, 20); d4_detail = f"MFA {mfa_p:.0f}%, {m['n_high_risk']} high-risk"
        d5 = 4
        if m['ii_total'] > m['total']: d5 += min(6, (m['ii_total'] - m['total']) // 2)
        if m['agents'] > 3: d5 += 2
        d5 = min(d5, 20); d5_detail = f"II:{m['ii_total']} vs Graph:{m['total']}"
        total = d1 + d2 + d3 + d4 + d5
        if total <= 20: rating, emoji = 'Healthy', '✅'
        elif total <= 45: rating, emoji = 'Elevated', '🟡'
        elif total <= 70: rating, emoji = 'Concerning', '🟠'
        else: rating, emoji = 'Critical', '🔴'
        m['score_total'] = total; m['score_rating'] = rating; m['score_emoji'] = emoji
        m['dims'] = [('Stale/Deleted', d1, d1_detail), ('Privileged', d2, d2_detail),
                     ('Password', d3, d3_detail), ('Risk & MFA', d4, d4_detail),
                     ('Identity Sprawl', d5, d5_detail)]
        return m

# ═══════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════

class HTMLReportGenerator:
    def __init__(self, m, analyzer):
        self.m = m; self.a = analyzer

    def _badge(self, level):
        cm = {'CRITICAL': '#f65314', 'HIGH': '#f65314', 'MEDIUM': '#ffbb00', 'LOW': '#7cbb00',
              'HEALTHY': '#7cbb00', 'ELEVATED': '#ffbb00', 'CONCERNING': '#ff7f00', 'NONE': '#737373'}
        bg = cm.get((level or '').upper(), '#737373')
        tc = '#1a1a1a' if (level or '').upper() in ('MEDIUM', 'ELEVATED', 'LOW', 'HEALTHY') else 'white'
        return f'<span style="background:{bg};color:{tc};padding:2px 9px;border-radius:3px;font-size:0.9em;font-weight:600;">{level}</span>'

    def _table(self, headers, rows):
        h = ''.join(f'<th style="{s}">{t}</th>' if s else f'<th>{t}</th>' for t, s in headers)
        r = ''.join(rows)
        return f'<table><thead><tr>{h}</tr></thead><tbody>{r}</tbody></table>'

    def _section(self, title, body):
        return f'<div class="section"><h2>{title}</h2>{body}</div>'

    def _bar_svg(self, score, max_s=20, w=120, h=16):
        pct_val = score / max_s * 100 if max_s > 0 else 0
        c = '#7cbb00' if pct_val <= 30 else ('#ffbb00' if pct_val <= 60 else '#f65314')
        fw = int(w * pct_val / 100)
        return f'<svg width="{w}" height="{h}" style="vertical-align:middle;"><rect x="0" y="0" width="{w}" height="{h}" rx="3" fill="#333"/><rect x="0" y="0" width="{fw}" height="{h}" rx="3" fill="{c}"/><text x="{w//2}" y="{h//2+4}" text-anchor="middle" fill="white" font-size="10" font-weight="bold">{score}/{max_s}</text></svg>'

    # ─── Score Card ───────────────────────────────────────────────
    def _score_card(self):
        m = self.m
        dims_html = ''
        for name, score, detail in m['dims']:
            dims_html += f'''<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
  <span style="width:130px;font-weight:500;">{name}</span>{self._bar_svg(score)}
  <span style="color:#b0b0b0;font-size:0.85em;">{detail}</span></div>'''
        sc = m['score_total']
        sc_c = '#7cbb00' if sc <= 20 else ('#ffbb00' if sc <= 45 else ('#ff7f00' if sc <= 70 else '#f65314'))
        return f'''<div class="section" style="border-left-color:{sc_c};">
  <h2>🔐 Identity Posture Score</h2>
  <div style="text-align:center;margin:12px 0;">
    <span style="font-size:3em;font-weight:bold;color:{sc_c};">{sc}</span><span style="font-size:1.5em;color:#737373;">/100</span>
    <div style="margin-top:4px;">{self._badge(m['score_rating'])}</div>
  </div>
  <div style="margin-top:14px;">{dims_html}</div></div>'''

    # ─── Key Metrics ──────────────────────────────────────────────
    def _metrics(self):
        m = self.m
        def mc(v, l, c='#00a1f1'):
            return f'<div class="metric" style="background:linear-gradient(135deg,{c},{c}cc);"><div class="mv">{v}</div><div class="ml">{l}</div></div>'
        return f'''<div class="section"><h2>📊 Key Metrics</h2><div class="metrics">
{mc(m['total'], 'Accounts')}{mc(f"{m['mfa_pct']:.0f}%", 'MFA Coverage', '#7cbb00' if m['mfa_pct']>=90 else '#ffbb00' if m['mfa_pct']>=70 else '#f65314')}
{mc(m['n_stale'], 'Stale (90d)', '#f65314' if m['n_stale']>10 else '#ffbb00' if m['n_stale']>0 else '#7cbb00')}{mc(m['n_high_risk'], 'High-Risk', '#f65314' if m['n_high_risk']>0 else '#7cbb00')}
</div></div>'''

    # ─── Account Breakdown ────────────────────────────────────────
    def _account_breakdown(self):
        m = self.m
        items = [
            ('Members', m['members'], '#00a1f1'), ('Guests', m['guests'], '#ffbb00'),
            ('Agent Users', m['agents'], '#737373'), ('Hybrid (AD-synced)', m['hybrid'], '#9b59b6'),
            ('Cloud-Only', m['cloud_only'], '#3498db')]
        bars = ''
        max_v = max(v for _, v, _ in items) or 1
        for label, val, color in items:
            w = int(val / max_v * 100)
            bars += f'<div style="margin-bottom:6px;"><div style="display:flex;justify-content:space-between;font-size:0.85em;"><span>{label}</span><span style="font-weight:600;">{val}</span></div><div style="background:#333;border-radius:3px;height:8px;"><div style="background:{color};height:8px;border-radius:3px;width:{max(2,w)}%;"></div></div></div>'
        return self._section('👥 Account Breakdown', bars)

    # ─── Privileged Accounts ──────────────────────────────────────
    def _privilege(self):
        m = self.m
        if not m['roles_available']:
            body = '<p style="color:#ffbb00;">⚠️ Directory Roles data not available (403). Admin accounts from MFA isAdmin flag.</p>'
            if m['admin_from_mfa']:
                rows = ''
                for upn, mfa_rec in sorted(m['admin_from_mfa'].items()):
                    mfa_s = '<span style="color:#7cbb00;">✅</span>' if mfa_rec.get('isMfaRegistered') else '<span style="color:#f65314;">🔴 No</span>'
                    methods = ', '.join(mfa_rec.get('methodsRegistered') or []) or '—'
                    rows += f'<tr><td style="font-size:0.85em;">{upn}</td><td style="text-align:center;">{mfa_s}</td><td style="font-size:0.85em;">{methods}</td></tr>'
                body += self._table([('Account', ''), ('MFA', 'text-align:center'), ('Methods', '')], [rows])
            return self._section(f'👑 Privileged Accounts ({m["n_admin_mfa"]})', body)

        all_priv = set(m['perm_high_priv'].keys()) | set(m['pim_accounts'].keys())
        rows = ''
        for upn in sorted(all_priv):
            perm = ', '.join(m['perm_high_priv'].get(upn, [])) or '—'
            pim_r = ', '.join(m['pim_accounts'].get(upn, [])) or '—'
            risk_c = '#f65314' if upn in m.get('perm_high_priv', {}) and upn not in m.get('pim_accounts', {}) else '#7cbb00'
            risk_l = '🔴 Perm-only' if risk_c == '#f65314' else '🟢 PIM'
            rows += f'<tr><td style="font-size:0.85em;">{upn}</td><td style="font-size:0.82em;">{perm}</td><td style="font-size:0.82em;">{pim_r}</td><td><span style="color:{risk_c};font-weight:600;">{risk_l}</span></td></tr>'
        tbl = self._table([('Account', ''), ('Permanent Roles', ''), ('PIM Eligible', ''), ('Risk', '')], [rows])
        alert = ''
        if m['n_admin_no_mfa'] > 0:
            names = ', '.join(r.get('userPrincipalName', '?') for r in m['admin_no_mfa'])
            alert = f'<div class="alert alert-critical">🔴 <strong>{m["n_admin_no_mfa"]} admin account(s) without MFA:</strong> {names}</div>'
        return self._section(f'👑 Privileged Accounts ({len(all_priv)})', tbl + alert)

    # ─── Stale & Deleted ─────────────────────────────────────────
    def _stale(self):
        m = self.m
        if not m['stale_accounts']:
            return self._section('🗑️ Stale & Deleted', '<p style="color:#7cbb00;">✅ No stale accounts detected</p>' +
                                 (f'<p class="l">Deleted users in recycle bin: {m["n_deleted"]}</p>' if m['n_deleted'] > 0 else ''))
        rows = ''
        for u in m['stale_accounts'][:15]:
            cat = u.get('_category', 'member')
            cat_c = {'guest': '#ffbb00', 'member': '#00a1f1', 'agent': '#737373'}.get(cat, '#b0b0b0')
            rows += f'<tr><td>{u.get("displayName", "?")}</td><td style="font-size:0.82em;">{u.get("userPrincipalName", "?")}</td><td><span style="color:{cat_c};">{cat}</span></td></tr>'
        tbl = self._table([('Name', ''), ('UPN', ''), ('Type', '')], [rows])
        more = f'<p class="l" style="margin-top:6px;">Showing 15 of {m["n_stale"]}</p>' if m['n_stale'] > 15 else ''
        deleted = f'<div style="margin-top:10px;"><span class="l">Deleted (recycle bin):</span> <strong>{m["n_deleted"]}</strong></div>' if m['n_deleted'] > 0 else ''
        return self._section(f'🗑️ Stale Accounts ({m["n_stale"]})', tbl + more + deleted)

    # ─── Password Posture ─────────────────────────────────────────
    def _password(self):
        m = self.m
        items = []
        if m['pwd_with_data'] > 0:
            items.append(f'<div style="margin-bottom:4px;"><span class="l">Accounts with pwd data:</span> {m["pwd_with_data"]}/{m["total"]}</div>')
            if m['pwd_avg_age'] is not None:
                items.append(f'<div style="margin-bottom:4px;"><span class="l">Avg password age:</span> {m["pwd_avg_age"]} days</div>')
                items.append(f'<div style="margin-bottom:4px;"><span class="l">Max password age:</span> {m["pwd_max_age"]} days</div>')
            items.append(f'<div style="margin-bottom:4px;"><span class="l">Passwords > 365 days:</span> <span style="color:{"#f65314" if m["pwd_over_365"]>0 else "#7cbb00"};">{m["pwd_over_365"]}</span></div>')
            items.append(f'<div style="margin-bottom:4px;"><span class="l">DisablePasswordExpiration (Entra):</span> {m["pwd_disable_expiry"]}</div>')
        else:
            items.append('<div style="color:#ffbb00;">⚠️ Entra password data not available</div>')
        if m['uac_with_data'] > 0:
            items.append(f'<div style="margin-top:8px;border-top:1px solid #3a3a3a;padding-top:8px;"><span class="l">AD accounts with UAC data:</span> {m["uac_with_data"]}</div>')
            pne_c = '#f65314' if m['uac_pwd_never_expires'] > 5 else '#ffbb00' if m['uac_pwd_never_expires'] > 0 else '#7cbb00'
            items.append(f'<div><span class="l">PasswordNeverExpires:</span> <span style="color:{pne_c};font-weight:600;">{m["uac_pwd_never_expires"]}</span></div>')
            items.append(f'<div><span class="l">PasswordNotRequired:</span> <span style="color:{"#f65314" if m["uac_pwd_not_required"]>0 else "#7cbb00"};font-weight:600;">{m["uac_pwd_not_required"]}</span></div>')
        return self._section('🔑 Password Posture', ''.join(items))

    # ─── MFA Coverage ─────────────────────────────────────────────
    def _mfa_coverage(self):
        m = self.m
        mfa_c = '#7cbb00' if m['mfa_pct'] >= 90 else ('#ffbb00' if m['mfa_pct'] >= 70 else '#f65314')
        gauge = f'<div style="text-align:center;margin:8px 0;"><span style="font-size:2.5em;font-weight:bold;color:{mfa_c};">{m["mfa_pct"]:.0f}%</span><div class="l">MFA Registered ({m["mfa_registered"]}/{m["mfa_total"]})</div></div>'
        rows = ''
        stats = [('MFA Capable', m['mfa_capable']), ('Passwordless', m['mfa_pwdless']),
                 ('SSPR Registered', m['mfa_sspr']), ('Not Registered', m['mfa_not_reg'])]
        for label, val in stats:
            c = '#f65314' if label == 'Not Registered' and val > 0 else '#e0e0e0'
            rows += f'<div style="display:flex;justify-content:space-between;margin-bottom:3px;"><span>{label}</span><span style="color:{c};font-weight:600;">{val}</span></div>'
        methods_html = ''
        if m['mfa_methods']:
            methods_html = '<div style="margin-top:8px;border-top:1px solid #3a3a3a;padding-top:8px;"><span class="l">Methods:</span>'
            for meth, cnt in list(m['mfa_methods'].items())[:6]:
                methods_html += f'<div style="display:flex;justify-content:space-between;font-size:0.85em;"><span>{meth}</span><span>{cnt}</span></div>'
            methods_html += '</div>'
        return self._section('🛡️ MFA Coverage', gauge + rows + methods_html)

    # ─── Risk Distribution ────────────────────────────────────────
    def _risk(self):
        m = self.m
        if not m['risky_users']:
            return self._section('🟠 Risk Distribution', '<p style="color:#7cbb00;">✅ No risky users detected</p>')
        rows = ''
        for r in sorted(m['risky_users'], key=lambda x: (0 if (x.get('riskLevel') or '').lower() == 'high' else 1)):
            lvl = (r.get('riskLevel') or 'none').upper()
            ic = '🔴' if lvl == 'HIGH' else ('🟠' if lvl == 'MEDIUM' else '⚪')
            st = r.get('riskState', '?')
            st_c = '#f65314' if st in ('atRisk', 'confirmedCompromised') else '#ffbb00'
            rows += f'<tr><td>{ic} {lvl}</td><td>{r.get("userDisplayName", "?")}</td><td><span style="color:{st_c};">{st}</span></td><td style="font-size:0.85em;">{str(r.get("riskLastUpdatedDateTime", ""))[:10]}</td></tr>'
        tbl = self._table([('Level', ''), ('Account', ''), ('State', ''), ('Updated', '')], [rows])
        return self._section(f'🟠 Risk Distribution ({len(m["risky_users"])})', tbl)

    # ─── MDI Tags ─────────────────────────────────────────────────
    def _tags(self):
        m = self.m
        if not m['mdi_tags']:
            return self._section('🏷️ Sensitive & Honeytoken', '<p style="color:#ffbb00;">⚠️ No MDI tags configured</p>')
        rows = ''
        for t in m['mdi_tags']:
            rows += f'<tr><td style="font-weight:600;">{t.get("TagName", "?")}</td><td style="text-align:center;">{t.get("AccountCount", 0)}</td><td style="font-size:0.85em;">{t.get("Accounts", "?")}</td></tr>'
        tbl = self._table([('Tag', ''), ('Count', 'text-align:center'), ('Accounts', '')], [rows])
        return self._section('🏷️ Sensitive & Honeytoken', tbl)

    # ─── Security Assessment ──────────────────────────────────────
    def _assessment(self):
        m = self.m
        findings = []
        if m['n_high_risk'] > 0:
            for r in m['high_risk']:
                findings.append(('🔴', 'Compromised Account', f'{r.get("userDisplayName")} — {r.get("riskState")}'))
        if m['n_admin_no_mfa'] > 0:
            findings.append(('🔴', 'Admin without MFA', f'{m["n_admin_no_mfa"]} admin account(s)'))
        if m['mfa_pct'] < 80:
            findings.append(('🟠', 'Low MFA Coverage', f'{m["mfa_pct"]:.0f}% (target: >95%)'))
        if m['n_stale'] > 0:
            findings.append(('🟠', 'Stale Accounts', f'{m["n_stale"]} without sign-in in 90+ days'))
        if m['uac_pwd_never_expires'] > 0:
            findings.append(('🟠', 'PasswordNeverExpires', f'{m["uac_pwd_never_expires"]} AD accounts'))
        if not findings:
            findings.append(('✅', 'Clean Posture', 'No critical findings'))
        rows = ''
        for icon, factor, detail in findings:
            bc = '#f65314' if icon == '🔴' else ('#ffbb00' if icon == '🟠' else '#7cbb00')
            rows += f'<div class="alert" style="border-color:{bc};background:rgba({",".join(str(int(bc.lstrip("#")[i:i+2],16)) for i in (0,2,4))},0.1);">{icon} <strong>{factor}:</strong> {detail}</div>'
        return self._section('⚠️ Security Assessment', rows)

    # ─── Recommendations ──────────────────────────────────────────
    def _recommendations(self):
        m = self.m
        recs = []
        if m['n_high_risk'] > 0:
            recs.append(('🔴', 'IMMEDIATE — Remediate compromised accounts'))
        if m['n_admin_no_mfa'] > 0:
            recs.append(('🔴', 'URGENT — Register MFA for all admin accounts'))
        if m['mfa_pct'] < 80:
            recs.append(('🟠', f'HIGH — Increase MFA coverage to >95% (current: {m["mfa_pct"]:.0f}%)'))
        if m['n_stale'] > 5:
            recs.append(('🟠', f'HIGH — Review {m["n_stale"]} stale accounts'))
        if m['uac_pwd_never_expires'] > 0:
            recs.append(('🟠', f'MEDIUM — Fix PasswordNeverExpires for {m["uac_pwd_never_expires"]} accounts'))
        if not m['roles_available']:
            recs.append(('🟡', 'MEDIUM — Grant Directory.Read.All for full role audit'))
        if not m['mdi_tags']:
            recs.append(('🟡', 'LOW — Configure Sensitive/Honeytoken tags in MDI'))
        items = ''.join(f'<li>{icon} {text}</li>' for icon, text in recs) if recs else '<li>✅ No actions required</li>'
        return f'''<div style="padding:12px;"><div class="section"><h2>💡 Recommendations</h2><ol style="font-size:0.92em;">{items}</ol></div></div>'''

    # ─── Full HTML ────────────────────────────────────────────────
    def generate(self, tenant, output_path=None):
        m = self.m
        if not output_path:
            ts = datetime.now().strftime('%Y-%m-%d_%H%M%S')
            output_path = f'reports/identity-posture/Identity_Posture_Report_{tenant}_{ts}.html'
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        sc_c = '#7cbb00' if m['score_total'] <= 20 else ('#ffbb00' if m['score_total'] <= 45 else ('#ff7f00' if m['score_total'] <= 70 else '#f65314'))

        left = '\n'.join([self._score_card(), self._metrics(), self._account_breakdown(),
                          self._mfa_coverage(), self._password(), self._tags()])
        right = '\n'.join([self._assessment(), self._privilege(), self._stale(),
                           self._risk()])

        html = f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Identity Posture Report — {tenant}</title>
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
.section h2{{font-size:1.2em;color:#00a1f1;margin-bottom:10px;padding-bottom:5px;border-bottom:1px solid #3a3a3a}}
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
details{{margin:10px 0}}summary{{cursor:pointer;padding:10px;background:#2a2a2a;border-radius:5px;font-weight:600;color:#00a1f1}}summary:hover{{background:#333}}
.ftr{{background:#252525;padding:10px 20px;text-align:center;font-size:0.85em;color:#737373;border-top:1px solid #3a3a3a}}
</style></head><body>
<div class="wm"><div>🔒 <strong>CONFIDENTIAL - INTERNAL USE ONLY</strong></div><div style="font-size:12px;">Generated by <strong>{get_user()}</strong> on <strong>{get_host()}</strong> | {now_str}</div></div>
<div class="ctr" style="margin-top:50px;">
  <div class="hdr"><div><h1>🔐 Identity Security Posture <span style="color:rgba(255,255,255,0.7);font-weight:300;">|</span> <span style="font-size:0.6em;font-weight:400;opacity:0.9;">{tenant}</span></h1>
    <div style="font-size:1em;opacity:0.9;margin-top:4px;">
      <span style="background:rgba(255,255,255,0.2);padding:3px 8px;border-radius:10px;font-size:0.8em;margin-right:6px;">📊 {m['total']} accounts</span>
      <span style="background:rgba(255,255,255,0.2);padding:3px 8px;border-radius:10px;font-size:0.8em;margin-right:6px;">🛡️ MFA {m['mfa_pct']:.0f}%</span>
      <span style="background:{sc_c};padding:3px 8px;border-radius:10px;font-size:0.8em;">Score: {m['score_total']}/100 {m['score_emoji']}</span>
    </div></div>
    <div class="meta"><div><strong>Generated:</strong> {now_str}</div><div><strong>Sources:</strong> Graph API + KQL</div></div></div>
  <div class="cnt"><div style="display:flex;flex-direction:column;gap:12px;">{left}</div><div style="display:flex;flex-direction:column;gap:12px;">{right}</div></div>
  {self._recommendations()}
  <div class="ftr"><strong style="color:#f65314;">⚠️ CONFIDENTIAL</strong> — Identity Security Posture Report | {tenant} | {now_str}</div>
</div></body></html>'''

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return output_path


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate_html_report.py <input_dir> [--output-dir DIR] [--tenant NAME]")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_dir = 'reports/identity-posture/'
    tenant = 'tenant'
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--output-dir' and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]; i += 2
        elif sys.argv[i] == '--tenant' and i + 1 < len(sys.argv):
            tenant = sys.argv[i + 1]; i += 2
        else:
            i += 1

    print(f"Loading data from {input_dir}...")
    analyzer = PostureAnalyzer(input_dir)
    analyzer.load_all()
    print("Computing metrics...")
    m = analyzer.compute_all()

    print("Generating HTML report...")
    gen = HTMLReportGenerator(m, analyzer)
    ts = datetime.now().strftime('%Y-%m-%d_%H%M%S')
    output_path = os.path.join(output_dir, f'Identity_Posture_Report_{tenant}_{ts}.html')
    path = gen.generate(tenant, output_path)
    print(f"✅ Report: {path}")


if __name__ == '__main__':
    main()
