#!/usr/bin/env python3
"""
Identity Posture Analyzer — reads collected Graph API + KQL data and produces a report.

This script is the Phase 2 engine for the identity-posture skill.
It expects the agent to have already collected data via:
  - RunAzCliReadCommands (Graph API) → saved as JSON in --input-dir
  - Log Analytics KQL queries          → saved as JSON in --input-dir

It reads all available JSON files, computes metrics and the Identity Posture
Score (0-100), and generates a markdown report + inline summary.

Usage
-----
    python3 analyze-identity-posture.py \\
        --input-dir  output/identity-posture/ \\
        --output-dir reports/identity-posture/ \\
        --format     both \\
        --tenant     mytenantname

File naming conventions (input)
-------------------------------
Graph API (saved by agent — the most recent file matching each prefix is used):
    users_<ts>.json              — User inventory
    directory_roles_<ts>.json    — Permanent role assignments
    pim_eligible_roles_<ts>.json — PIM eligible roles
    risky_users_<ts>.json        — Identity Protection risky users
    deleted_users_<ts>.json      — Soft-deleted users
    mfa_registration_<ts>.json   — MFA registration details

KQL enrichment (saved by agent — JSON with "results" key):
    kql_uac_flags_<ts>.json        — AD UAC PasswordNeverExpires / PasswordNotRequired
    kql_mdi_tags_<ts>.json         — MDI Sensitive / Honeytoken tags
    kql_identity_risk_<ts>.json    — IdentityInfo risk + blast radius
    kql_builtin_accounts_<ts>.json — Built-in / infrastructure accounts
    kql_stale_summary_<ts>.json    — SigninLogs stale aggregation
    kql_stale_detail_<ts>.json     — SigninLogs per-user last activity
    kql_cross_domain_<ts>.json     — IdentityInfo cross-domain summary
    kql_service_accounts_<ts>.json — IdentityInfo service account detection

Collection metadata:
    collection_metadata_<ts>.json  — Summary from get-entra-posture-data.py

Output
------
    reports/identity-posture/Identity_Posture_Report_<tenant>_<ts>.md
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from typing import Any

# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

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

# Accounts excluded from stale analysis (service / agent / system accounts)
SERVICE_ACCOUNT_PATTERNS = [
    "serviceaccount", "securitycopilotagentuser", "phishinganalysisreports",
    "userreportingmbx", "slrtravelplanner", "automation account",
]

# UPN prefixes that identify agent users (when @odata.type is absent)
AGENT_UPN_PREFIXES = [
    "securitycopilotagentuser", "slrtravelplanner",
]

# ═══════════════════════════════════════════════════════════════════════════════
#  DATA LOADING
# ═══════════════════════════════════════════════════════════════════════════════

def find_latest(input_dir: str, prefix: str) -> str | None:
    """Return the path of the most-recent file matching  <prefix>_*.json."""
    pattern = os.path.join(input_dir, f"{prefix}_*.json")
    files = sorted(glob.glob(pattern))
    return files[-1] if files else None


def load_json_array(path: str | None, label: str) -> list[dict]:
    """Load a JSON file that is either a plain array or has a 'value' key."""
    if path is None:
        print(f"  [--] {label}: file not found — skipped")
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        arr = data.get("value", data) if isinstance(data, dict) else data
        if not isinstance(arr, list):
            arr = [arr]
        print(f"  [OK] {label}: {len(arr)} records  ({os.path.basename(path)})")
        return arr
    except Exception as e:
        print(f"  [!!] {label}: error reading {path} — {e}")
        return []


def load_kql_results(path: str | None, label: str) -> list[dict]:
    """Load KQL results — expects {"results": [...]} or plain array."""
    if path is None:
        print(f"  [--] {label}: file not found — skipped")
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        arr = data.get("results", data.get("value", data))
        if not isinstance(arr, list):
            arr = [arr] if arr else []
        print(f"  [OK] {label}: {len(arr)} records  ({os.path.basename(path)})")
        return arr
    except Exception as e:
        print(f"  [!!] {label}: error reading {path} — {e}")
        return []


# ═══════════════════════════════════════════════════════════════════════════════
#  METRIC COMPUTATION HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def safe_int(val, default=0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def pct(num: int, den: int) -> float:
    return round(num / den * 100, 1) if den > 0 else 0.0


def bar(score: int, max_score: int = 20) -> str:
    filled = int(score / max_score * 10)
    return "\u2588" * filled + "\u2591" * (10 - filled)


def is_guest(upn: str) -> bool:
    return "#EXT#" in upn


def is_agent_user(user: dict) -> bool:
    """Detect agent users from @odata.type or UPN prefix."""
    if user.get("@odata.type") == "#microsoft.graph.agentUser":
        return True
    upn_lower = (user.get("userPrincipalName") or user.get("upn") or "").lower()
    return any(upn_lower.split("@")[0].startswith(p) for p in AGENT_UPN_PREFIXES)


def is_service_account(user: dict) -> bool:
    upn_lower = (user.get("userPrincipalName") or user.get("upn") or "").lower()
    name_lower = (user.get("displayName") or "").lower()
    if is_agent_user(user):
        return True
    if upn_lower.startswith("spam@"):
        return True
    return any(p in upn_lower or p in name_lower for p in SERVICE_ACCOUNT_PATTERNS)


# ═══════════════════════════════════════════════════════════════════════════════
#  ANALYZER CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class IdentityPostureAnalyzer:

    def __init__(self, input_dir: str, output_dir: str, tenant: str, fmt: str):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.tenant = tenant
        self.fmt = fmt  # inline | markdown | both
        self.now = datetime.now(timezone.utc)
        self.ts = self.now.strftime("%Y%m%d_%H%M%S")
        self.now_str = self.now.strftime("%Y-%m-%d %H:%M UTC")

        # ── raw data ──
        self.users: list[dict] = []
        self.roles: list[dict] = []
        self.pim: list[dict] = []
        self.risky: list[dict] = []
        self.deleted: list[dict] = []
        self.mfa: list[dict] = []

        self.kql_uac: list[dict] = []
        self.kql_tags: list[dict] = []
        self.kql_risk: list[dict] = []
        self.kql_builtin: list[dict] = []
        self.kql_stale_summary: list[dict] = []
        self.kql_stale_detail: list[dict] = []
        self.kql_cross_domain: list[dict] = []
        self.kql_service: list[dict] = []

        # ── computed metrics (populated by compute_*) ──
        self.m: dict[str, Any] = {}
        self.data_coverage: list[dict] = []

    # ── Loading ──────────────────────────────────────────────────────────
    def load_all(self):
        d = self.input_dir
        print("Loading Graph API data …")
        self.users   = load_json_array(find_latest(d, "users"),              "Users")
        self.roles   = load_json_array(find_latest(d, "directory_roles"),    "Directory Roles")
        self.pim     = load_json_array(find_latest(d, "pim_eligible_roles"), "PIM Eligible")
        self.risky   = load_json_array(find_latest(d, "risky_users"),        "Risky Users")
        self.deleted = load_json_array(find_latest(d, "deleted_users"),      "Deleted Users")
        self.mfa     = load_json_array(find_latest(d, "mfa_registration"),   "MFA Registration")

        print("\nLoading KQL enrichment data …")
        self.kql_uac          = load_kql_results(find_latest(d, "kql_uac_flags"),        "KQL UAC Flags")
        self.kql_tags         = load_kql_results(find_latest(d, "kql_mdi_tags"),         "KQL MDI Tags")
        self.kql_risk         = load_kql_results(find_latest(d, "kql_identity_risk"),    "KQL IdentityInfo Risk")
        self.kql_builtin      = load_kql_results(find_latest(d, "kql_builtin_accounts"), "KQL Built-In Accounts")
        self.kql_stale_summary = load_kql_results(find_latest(d, "kql_stale_summary"),   "KQL Stale Summary")
        self.kql_stale_detail = load_kql_results(find_latest(d, "kql_stale_detail"),     "KQL Stale Detail")
        self.kql_cross_domain = load_kql_results(find_latest(d, "kql_cross_domain"),     "KQL Cross-Domain")
        self.kql_service      = load_kql_results(find_latest(d, "kql_service_accounts"), "KQL Service Accounts")

        if not self.users:
            print("\n[CRITICAL] No user data found. Cannot produce report.", file=sys.stderr)
            sys.exit(1)

    # ── Inventory ────────────────────────────────────────────────────────
    def compute_inventory(self):
        m = self.m
        users = self.users
        m["total"] = len(users)

        # Use MFA data for userType when user list has default fields only
        mfa_by_id = {r.get("id"): r for r in self.mfa}
        guests, members, agents = 0, 0, 0
        for u in users:
            uid = u.get("id")
            utype = u.get("userType")
            if not utype and uid in mfa_by_id:
                utype = mfa_by_id[uid].get("userType")
            if not utype:
                utype = "Guest" if is_guest(u.get("userPrincipalName", "")) else "Member"
            u["_resolved_type"] = utype.lower() if utype else "member"

            if is_agent_user(u):
                agents += 1
                u["_category"] = "agent"
            elif is_service_account(u):
                u["_category"] = "service"
            elif u["_resolved_type"] == "guest":
                guests += 1
                u["_category"] = "guest"
            else:
                members += 1
                u["_category"] = "member"

        m["guests"] = guests
        m["members"] = members
        m["agents"] = agents

        # Hybrid vs cloud-only (from onPremisesSyncEnabled or UPN domain)
        hybrid = sum(1 for u in users if u.get("onPremisesSyncEnabled") is True)
        cloud_only = m["total"] - hybrid
        m["hybrid"] = hybrid
        m["cloud_only"] = cloud_only

        # IdentityInfo cross-domain enrichment
        if self.kql_cross_domain:
            cd = self.kql_cross_domain[0]
            m["ii_total"] = safe_int(cd.get("TotalAccounts"))
            m["ii_enabled"] = safe_int(cd.get("EnabledAccounts"))
            m["ii_disabled"] = safe_int(cd.get("DisabledAccounts"))
            m["ii_domains"] = cd.get("Domains", "[]")
        else:
            m["ii_total"] = m["ii_enabled"] = m["ii_disabled"] = 0
            m["ii_domains"] = "[]"

    # ── Privileged ───────────────────────────────────────────────────────
    def compute_privilege(self):
        m = self.m

        # Permanent roles from directory_roles
        perm_accounts: dict[str, list[str]] = {}  # upn → [roles]
        role_counts: dict[str, int] = {}           # role → member count
        for role in self.roles:
            rname = role.get("displayName", "")
            members = role.get("members", [])
            role_counts[rname] = len(members)
            if rname in HIGH_PRIV_ROLES:
                for mem in members:
                    upn = mem.get("userPrincipalName", "unknown")
                    perm_accounts.setdefault(upn, []).append(rname)

        # PIM eligible
        pim_accounts: dict[str, list[str]] = {}  # upn → [roles]
        pim_counts: dict[str, int] = {}
        for inst in self.pim:
            principal = inst.get("principal", {})
            rdef = inst.get("roleDefinition", {})
            upn = principal.get("userPrincipalName", "unknown")
            rname = rdef.get("displayName", "unknown")
            pim_accounts.setdefault(upn, []).append(rname)
            pim_counts[rname] = pim_counts.get(rname, 0) + 1

        # Classification
        perm_only = {u: r for u, r in perm_accounts.items() if u not in pim_accounts}
        pim_only  = {u: r for u, r in pim_accounts.items()  if u not in perm_accounts}
        both      = {u: r for u, r in perm_accounts.items() if u in pim_accounts}

        m["perm_high_priv"] = perm_accounts
        m["pim_accounts"]   = pim_accounts
        m["perm_only"]      = perm_only
        m["pim_only"]       = pim_only
        m["perm_and_pim"]   = both
        m["role_counts"]    = role_counts
        m["pim_role_counts"] = pim_counts
        m["n_perm_high"]    = len(perm_accounts)
        m["n_pim"]          = len(pim_accounts)
        m["roles_available"] = len(self.roles) > 0
        m["pim_available"]   = len(self.pim) > 0

        # Admin flag from MFA data (fallback when roles data unavailable)
        admin_from_mfa = {r.get("userPrincipalName"): r for r in self.mfa if r.get("isAdmin")}
        m["admin_from_mfa"] = admin_from_mfa
        m["n_admin_mfa"] = len(admin_from_mfa)

    # ── Stale ────────────────────────────────────────────────────────────
    def compute_stale(self):
        m = self.m

        # Build set of active UPNs from KQL stale detail
        active_upns: set[str] = set()
        for row in self.kql_stale_detail:
            upn = (row.get("UPN") or "").strip().lower()
            if upn:
                active_upns.add(upn)

        # Also try to match Graph signInActivity (if available)
        for u in self.users:
            sia = u.get("signInActivity")
            if sia:
                last = sia.get("lastSignInDateTime") or sia.get("lastNonInteractiveSignInDateTime")
                if last:
                    active_upns.add(u.get("userPrincipalName", "").lower())

        # Match sign-in UPNs to Graph UPNs (guests have different UPNs in sign-in logs)
        graph_upn_map: dict[str, str] = {}
        for u in self.users:
            gupn = u.get("userPrincipalName", "")
            mail = (u.get("mail") or "").lower()
            graph_upn_map[gupn.lower()] = gupn
            if mail:
                graph_upn_map[mail] = gupn

        resolved_active: set[str] = set()
        for aupn in active_upns:
            if aupn in graph_upn_map:
                resolved_active.add(graph_upn_map[aupn].lower())
            else:
                # Try direct match
                resolved_active.add(aupn)

        stale = []
        service_no_signin = []
        for u in self.users:
            upn = u.get("userPrincipalName", "")
            if upn.lower() in resolved_active:
                continue
            if is_service_account(u):
                service_no_signin.append(u)
            else:
                stale.append(u)

        m["stale_accounts"] = stale
        m["service_no_signin"] = service_no_signin
        m["n_stale"] = len(stale)
        m["stale_pct"] = pct(len(stale), m["total"])
        m["active_upns"] = resolved_active

        # KQL stale summary (aggregated)
        if self.kql_stale_summary:
            ss = self.kql_stale_summary[0]
            m["signin_total_with_activity"] = safe_int(ss.get("TotalWithActivity"))
            m["signin_active_30d"] = safe_int(ss.get("Active30d"))
            m["signin_active_60d"] = safe_int(ss.get("Active60d"))
            m["signin_active_90d"] = safe_int(ss.get("Active90d"))
            m["signin_stale_90d"]  = safe_int(ss.get("Stale90d"))
        else:
            m["signin_total_with_activity"] = len(active_upns)

    # ── Password ─────────────────────────────────────────────────────────
    def compute_password(self):
        m = self.m

        # Graph API password data
        pwd_ages = []
        disable_pwd_expiry = 0
        with_pwd_data = 0
        for u in self.users:
            lpcd = u.get("lastPasswordChangeDateTime")
            if lpcd:
                with_pwd_data += 1
                try:
                    dt = datetime.fromisoformat(lpcd.replace("Z", "+00:00"))
                    age = (self.now - dt).days
                    pwd_ages.append(age)
                except (ValueError, TypeError):
                    pass
            ppol = u.get("passwordPolicies") or ""
            if "DisablePasswordExpiration" in ppol:
                disable_pwd_expiry += 1

        m["pwd_with_data"] = with_pwd_data
        m["pwd_disable_expiry"] = disable_pwd_expiry
        m["pwd_ages"] = pwd_ages
        m["pwd_avg_age"] = round(sum(pwd_ages) / len(pwd_ages)) if pwd_ages else None
        m["pwd_max_age"] = max(pwd_ages) if pwd_ages else None
        m["pwd_over_365"] = sum(1 for a in pwd_ages if a > 365)
        m["pwd_buckets"] = {
            "0-30": sum(1 for a in pwd_ages if a <= 30),
            "31-90": sum(1 for a in pwd_ages if 31 <= a <= 90),
            "91-180": sum(1 for a in pwd_ages if 91 <= a <= 180),
            "181-365": sum(1 for a in pwd_ages if 181 <= a <= 365),
            "365+": sum(1 for a in pwd_ages if a > 365),
        }

        # KQL UAC enrichment
        if self.kql_uac:
            u0 = self.kql_uac[0]
            m["uac_with_data"]        = safe_int(u0.get("WithUACData"))
            m["uac_pwd_never_expires"] = safe_int(u0.get("PwdNeverExpiresCount"))
            m["uac_pwd_not_required"]  = safe_int(u0.get("PwdNotRequiredCount"))
        else:
            m["uac_with_data"] = m["uac_pwd_never_expires"] = m["uac_pwd_not_required"] = 0

    # ── MFA ──────────────────────────────────────────────────────────────
    def compute_mfa(self):
        m = self.m
        mfa = self.mfa
        total = len(mfa)
        m["mfa_total"] = total
        m["mfa_registered"]  = sum(1 for r in mfa if r.get("isMfaRegistered"))
        m["mfa_capable"]     = sum(1 for r in mfa if r.get("isMfaCapable"))
        m["mfa_pwdless"]     = sum(1 for r in mfa if r.get("isPasswordlessCapable"))
        m["mfa_sspr"]        = sum(1 for r in mfa if r.get("isSsprRegistered"))
        m["mfa_not_reg"]     = total - m["mfa_registered"]
        m["mfa_pct"]         = pct(m["mfa_registered"], total)

        # Method distribution
        methods: dict[str, int] = {}
        for r in mfa:
            for meth in (r.get("methodsRegistered") or []):
                methods[meth] = methods.get(meth, 0) + 1
        m["mfa_methods"] = dict(sorted(methods.items(), key=lambda x: -x[1]))

        # Accounts without MFA
        m["mfa_no_reg_list"] = [r for r in mfa if not r.get("isMfaRegistered")]

        # Cross-reference: admin accounts without MFA
        admin_no_mfa = []
        if m.get("roles_available"):
            mfa_by_upn = {r.get("userPrincipalName", "").lower(): r for r in mfa}
            for upn in m.get("perm_high_priv", {}):
                mr = mfa_by_upn.get(upn.lower())
                if mr and not mr.get("isMfaRegistered"):
                    admin_no_mfa.append(mr)
        else:
            # Fallback: use isAdmin from MFA data
            admin_no_mfa = [r for r in mfa if r.get("isAdmin") and not r.get("isMfaRegistered")]
        m["admin_no_mfa"] = admin_no_mfa
        m["n_admin_no_mfa"] = len(admin_no_mfa)

    # ── Risk ─────────────────────────────────────────────────────────────
    def compute_risk(self):
        m = self.m
        m["risky_users"] = self.risky
        m["high_risk"]   = [r for r in self.risky if (r.get("riskLevel") or "").lower() == "high"]
        m["at_risk"]     = [r for r in self.risky
                            if r.get("riskState") in ("atRisk", "confirmedCompromised")]
        m["n_high_risk"] = len(m["high_risk"])
        m["n_at_risk"]   = len(m["at_risk"])

        # KQL IdentityInfo risk
        m["kql_risk_rows"] = self.kql_risk

    # ── MDI Tags ─────────────────────────────────────────────────────────
    def compute_tags(self):
        m = self.m
        m["mdi_tags"] = self.kql_tags  # may be empty
        m["kql_builtin"] = self.kql_builtin

    # ── Deleted ──────────────────────────────────────────────────────────
    def compute_deleted(self):
        m = self.m
        m["deleted_users"] = self.deleted
        m["n_deleted"] = len(self.deleted)

    # ── Score ────────────────────────────────────────────────────────────
    def compute_score(self):
        m = self.m
        # D1: Stale / Deleted (0-20)
        sp = m["stale_pct"]
        if sp > 15:   d1 = min(20, 12 + int(sp - 15) // 3)
        elif sp > 5:  d1 = 6 + int((sp - 5))
        else:         d1 = max(0, int(sp))
        d1 = min(d1, 20)
        d1_detail = f"{m['n_stale']} stale ({sp:.0f}%)"

        # D2: Privileged (0-20)
        if m["roles_available"]:
            n_perm = m["n_perm_high"]
            if n_perm > 15:   d2 = 18
            elif n_perm > 5:  d2 = 10 + (n_perm - 5)
            else:             d2 = n_perm
            if m["n_admin_no_mfa"] > 0:
                d2 = min(20, d2 + m["n_admin_no_mfa"] * 2)
        else:
            # Fallback: use admin_from_mfa
            n_admin = m["n_admin_mfa"]
            d2 = min(20, 8 + m["n_admin_no_mfa"] * 3)  # penalty for unknown role state
        d2 = min(d2, 20)
        d2_detail = f"{m.get('n_perm_high', m['n_admin_mfa'])} priv, {m['n_admin_no_mfa']} no MFA"

        # D3: Password (0-20)
        uac_pne = m["uac_pwd_never_expires"]
        uac_total = m["uac_with_data"]
        pne_pct_val = pct(uac_pne, uac_total) if uac_total > 0 else 0
        if pne_pct_val > 40:   d3 = 14
        elif pne_pct_val > 10: d3 = 8 + int((pne_pct_val - 10) / 5)
        else:                  d3 = max(0, int(pne_pct_val))
        # Add penalty for Graph passwordPolicies DisablePasswordExpiration
        if m["pwd_disable_expiry"] > 0:
            d3 = min(20, d3 + min(6, m["pwd_disable_expiry"]))
        d3 = min(d3, 20)
        d3_detail = f"{uac_pne}/{uac_total} PwdNeverExp"

        # D4: Risk & MFA (0-20)
        mfa_p = m["mfa_pct"]
        d4 = 0
        if mfa_p < 50:   d4 += 12
        elif mfa_p < 80:  d4 += 8
        elif mfa_p < 95:  d4 += 4
        if m["n_high_risk"] > 0: d4 += 6
        d4 = min(d4, 20)
        d4_detail = f"MFA {mfa_p:.0f}%, {m['n_high_risk']} high-risk"

        # D5: Identity Sprawl (0-20)
        d5 = 4  # baseline
        if m["ii_total"] > m["total"]:
            d5 += min(6, (m["ii_total"] - m["total"]) // 2)
        if m["agents"] > 3:
            d5 += 2
        d5 = min(d5, 20)
        d5_detail = f"II:{m['ii_total']} vs Graph:{m['total']}"

        total = d1 + d2 + d3 + d4 + d5
        if total <= 20:   rating, emoji = "Healthy", "\u2705"
        elif total <= 45: rating, emoji = "Elevated", "\U0001f7e1"
        elif total <= 70: rating, emoji = "Concerning", "\U0001f7e0"
        else:             rating, emoji = "Critical", "\U0001f534"

        m["score_total"]  = total
        m["score_rating"] = rating
        m["score_emoji"]  = emoji
        m["dims"] = [
            ("Stale/Deleted",   d1, d1_detail),
            ("Privileged",      d2, d2_detail),
            ("Password",        d3, d3_detail),
            ("Risk & MFA",      d4, d4_detail),
            ("Identity Sprawl", d5, d5_detail),
        ]

    # ── Data Coverage ────────────────────────────────────────────────────
    def build_coverage(self):
        def _s(data, label, loaded: bool = True):
            if not loaded:
                return {"source": label, "status": "\u274c Missing", "note": "File not found"}
            if data:
                return {"source": label, "status": "\u2705 OK", "note": f"{len(data)} records"}
            return {"source": label, "status": "\u2705 OK", "note": "0 records (empty)"}

        d = self.input_dir
        self.data_coverage = [
            _s(self.users,   "Graph — Users",              find_latest(d, "users") is not None),
            _s(self.roles,   "Graph — Directory Roles",    find_latest(d, "directory_roles") is not None),
            _s(self.pim,     "Graph — PIM Eligible",       find_latest(d, "pim_eligible_roles") is not None),
            _s(self.risky,   "Graph — Risky Users",        find_latest(d, "risky_users") is not None),
            _s(self.deleted, "Graph — Deleted Users",      find_latest(d, "deleted_users") is not None),
            _s(self.mfa,     "Graph — MFA Registration",   find_latest(d, "mfa_registration") is not None),
            _s(self.kql_uac, "KQL — IdentityInfo (UAC)",   find_latest(d, "kql_uac_flags") is not None),
            _s(self.kql_tags, "KQL — IdentityInfo (Tags)", find_latest(d, "kql_mdi_tags") is not None),
            _s(self.kql_stale_detail, "KQL — SigninLogs (stale)", find_latest(d, "kql_stale_detail") is not None),
            _s(self.kql_cross_domain, "KQL — IdentityInfo (cross-domain)", find_latest(d, "kql_cross_domain") is not None),
            _s(self.kql_builtin, "KQL — IdentityInfo (built-in)", find_latest(d, "kql_builtin_accounts") is not None),
            _s(self.kql_service, "KQL — IdentityInfo (service accts)", find_latest(d, "kql_service_accounts") is not None),
        ]

    # ── Report Generation ────────────────────────────────────────────────
    def generate_report(self) -> str:
        m = self.m
        lines: list[str] = []
        a = lines.append

        a(f"# \U0001f510 Identity Security Posture Report\n")
        a(f"**Generated:** {self.now_str}")
        a(f"**Tenant:** {self.tenant}")
        a(f"**Data Sources:** Microsoft Graph API + Log Analytics KQL (IdentityInfo, SigninLogs)")
        a(f"**Analysis Period:** Graph collection: {self.now_str} | SigninLogs: 90-day lookback")
        a("")
        a("---\n")

        # ── Executive Summary ──
        a("## Executive Summary\n")
        a(f"The tenant contains **{m['total']} accounts** "
          f"({m['members']} members, {m['guests']} guests, {m['agents']} agent users). "
          f"**{m['n_stale']} accounts** have no sign-in activity in the last 90 days. "
          f"MFA coverage is **{m['mfa_pct']:.0f}%** ({m['mfa_registered']}/{m['mfa_total']}). "
          f"**{m['n_high_risk']} high-risk** account(s) detected.")
        a(f"\n**Overall Risk Rating:** {m['score_emoji']} **{m['score_rating']}** ({m['score_total']}/100)\n")
        a("---\n")

        # ── Key Metrics ──
        a("## Key Metrics\n")
        a("| Metric | Value |")
        a("|--------|-------|")
        a(f"| Total Accounts | {m['total']} |")
        a(f"| Members | {m['members']} |")
        a(f"| Guests | {m['guests']} |")
        a(f"| Agent Users | {m['agents']} |")
        if m["roles_available"]:
            a(f"| High-Privilege Permanent Roles | {m['n_perm_high']} |")
        if m["pim_available"]:
            a(f"| PIM-Eligible Accounts | {m['n_pim']} |")
        if not m["roles_available"]:
            a(f"| Admin Accounts (from MFA data) | {m['n_admin_mfa']} |")
        a(f"| Admin Accounts without MFA | {m['n_admin_no_mfa']} |")
        a(f"| Stale Accounts (no sign-in 90d) | {m['n_stale']} |")
        a(f"| Deleted Users (Recycle Bin) | {m['n_deleted']} |")
        a(f"| MFA Registered | {m['mfa_registered']}/{m['mfa_total']} ({m['mfa_pct']:.0f}%) |")
        a(f"| MFA Capable | {m['mfa_capable']} |")
        a(f"| Passwordless Capable | {m['mfa_pwdless']} |")
        a(f"| High-Risk Users | {m['n_high_risk']} |")
        if m["uac_with_data"] > 0:
            a(f"| AD PasswordNeverExpires | {m['uac_pwd_never_expires']}/{m['uac_with_data']} |")
        if m["ii_total"] > 0:
            a(f"| IdentityInfo Accounts (AD) | {m['ii_total']} ({m['ii_enabled']} enabled) |")
        a("")
        a("---\n")

        # ── Privileged Account Audit ──
        a("## \U0001f451 Privileged Account Audit\n")
        if m["roles_available"]:
            a("### Permanent High-Privilege Roles\n")
            a("| Account | Permanent Roles | PIM-Eligible Roles | Risk |")
            a("|---------|----------------|-------------------|------|")
            all_priv_upns = set(m["perm_high_priv"].keys()) | set(m["pim_accounts"].keys())
            for upn in sorted(all_priv_upns):
                perm = ", ".join(m["perm_high_priv"].get(upn, []))  or "—"
                pim_r = ", ".join(m["pim_accounts"].get(upn, []))   or "—"
                risk = "\U0001f534" if upn in m.get("perm_only", {}) else "\U0001f7e1"
                a(f"| {upn} | {perm} | {pim_r} | {risk} |")
            a("")
        else:
            a("> \u26a0\ufe0f **Directory Roles data not available** (403 Forbidden). "
              "Admin accounts identified via MFA registration `isAdmin` flag.\n")
            a("| Account | MFA | Methods | Risk |")
            a("|---------|-----|---------|------|")
            for upn, mfa_rec in sorted(m["admin_from_mfa"].items()):
                mfa_s = "\u2705" if mfa_rec.get("isMfaRegistered") else "\U0001f534 No"
                methods = ", ".join(mfa_rec.get("methodsRegistered") or []) or "\u2014"
                risk = "\U0001f534" if not mfa_rec.get("isMfaRegistered") else "\U0001f7e2"
                a(f"| {upn} | {mfa_s} | {methods} | {risk} |")
            a("")

        if m["n_admin_no_mfa"] > 0:
            names = ", ".join(r.get("userPrincipalName", "?") for r in m["admin_no_mfa"])
            a(f"> \U0001f534 **{m['n_admin_no_mfa']} admin account(s) without MFA:** {names}\n")
        a("---\n")

        # ── Stale & Deleted ──
        a("## \U0001f5d1\ufe0f Stale & Deleted Account Hygiene\n")
        a(f"### Stale Accounts (no sign-in in 90d, excluding service/agent) — {m['n_stale']} total\n")
        if m["stale_accounts"]:
            a("| Account | UPN | Category | Note |")
            a("|---------|-----|----------|------|")
            for u in m["stale_accounts"]:
                note = ""
                for r in m.get("high_risk", []):
                    if (r.get("userPrincipalName") or "").lower() == u.get("userPrincipalName", "").lower():
                        note = f"\U0001f534 {r.get('riskState', '')}"
                cat = u.get("_category", "member")
                a(f"| {u['displayName']} | {u['userPrincipalName']} | {cat} | {note} |")
        else:
            a("> \u2705 No stale accounts detected.")
        a("")
        a(f"### Deleted Users (Recycle Bin) — {m['n_deleted']}\n")
        if self.deleted:
            a("| Account | UPN | Deleted |")
            a("|---------|-----|---------|")
            for d in self.deleted:
                a(f"| {d.get('displayName', '?')} | {d.get('userPrincipalName', '?')} | {d.get('deletedDateTime', '?')} |")
        else:
            a("> \u2705 No deleted users in recycle bin.")
        a("\n---\n")

        # ── Password Posture ──
        a("## \U0001f511 Password Posture\n")
        if m["pwd_with_data"] > 0:
            a("### Entra ID Password Data (Graph API)\n")
            a("| Metric | Value |")
            a("|--------|-------|")
            a(f"| Accounts with Password Data | {m['pwd_with_data']}/{m['total']} |")
            a(f"| DisablePasswordExpiration | {m['pwd_disable_expiry']} |")
            if m["pwd_avg_age"] is not None:
                a(f"| Avg Password Age (days) | {m['pwd_avg_age']} |")
                a(f"| Max Password Age (days) | {m['pwd_max_age']} |")
                a(f"| Passwords > 365 days | {m['pwd_over_365']} |")
            a("")
        else:
            a("> \u26a0\ufe0f Entra ID password data (`lastPasswordChangeDateTime`, `passwordPolicies`) "
              "not available. Ensure the Graph API `$select` query includes these fields.\n")

        if m["uac_with_data"] > 0:
            a("### AD UAC Flags (IdentityInfo — on-prem AD with MDI)\n")
            a("| Flag | Accounts | Scope |")
            a("|------|----------|-------|")
            a(f"| PasswordNeverExpires | {m['uac_pwd_never_expires']} | {m['uac_with_data']} AD accounts with UAC data |")
            a(f"| PasswordNotRequired  | {m['uac_pwd_not_required']} | {m['uac_with_data']} AD accounts with UAC data |")
            if m["uac_pwd_never_expires"] > 0:
                p = pct(m["uac_pwd_never_expires"], m["uac_with_data"])
                a(f"\n> \U0001f7e0 **{m['uac_pwd_never_expires']} AD accounts ({p:.0f}%) have PasswordNeverExpires.**")
            a("")
        else:
            a("> \u26a0\ufe0f IdentityInfo UAC data not available.\n")

        if self.kql_builtin:
            a("### Built-In & Infrastructure Accounts\n")
            a("| Account | Domain | Enabled | PwdNeverExp | Sensitive |")
            a("|---------|--------|---------|-------------|-----------|")
            for b in self.kql_builtin:
                a(f"| {b.get('AccountName', '?')} | {b.get('AccountDomain', '?')} "
                  f"| {b.get('IsAccountEnabled', '?')} | {b.get('PwdNeverExpires', '?')} "
                  f"| {b.get('Sensitive', '?')} |")
            a("")
        a("---\n")

        # ── MFA Coverage ──
        a("## \U0001f6e1\ufe0f MFA Coverage\n")
        a("| Metric | Value | % |")
        a("|--------|------:|--:|")
        a(f"| Total with MFA Data | {m['mfa_total']} | — |")
        a(f"| MFA Registered | {m['mfa_registered']} | {m['mfa_pct']:.0f}% |")
        a(f"| MFA Capable | {m['mfa_capable']} | {pct(m['mfa_capable'], m['mfa_total']):.0f}% |")
        a(f"| Passwordless Capable | {m['mfa_pwdless']} | {pct(m['mfa_pwdless'], m['mfa_total']):.0f}% |")
        a(f"| SSPR Registered | {m['mfa_sspr']} | {pct(m['mfa_sspr'], m['mfa_total']):.0f}% |")
        a(f"| **Not MFA Registered** | **{m['mfa_not_reg']}** | **{pct(m['mfa_not_reg'], m['mfa_total']):.0f}%** |")
        a("")

        if m["mfa_methods"]:
            a("### MFA Method Distribution\n")
            a("| Method | Users |")
            a("|--------|------:|")
            for meth, cnt in m["mfa_methods"].items():
                a(f"| {meth} | {cnt} |")
            a("")

        if m["admin_no_mfa"]:
            a("### Admin Accounts Without MFA\n")
            a("| Account | UPN |")
            a("|---------|-----|")
            for r in m["admin_no_mfa"]:
                a(f"| {r.get('userDisplayName', '?')} | {r.get('userPrincipalName', '?')} |")
            a(f"\n> \U0001f534 **{m['n_admin_no_mfa']} admin account(s) without MFA** — Critical finding.\n")
        a("---\n")

        # ── Risk Distribution ──
        a("## \U0001f7e0 Risk Distribution\n")
        if self.risky:
            a("### Graph API (Identity Protection)\n")
            a("| Level | Account | State | Detail | Date |")
            a("|-------|---------|-------|--------|------|")
            for r in sorted(self.risky, key=lambda x: (0 if x.get("riskLevel") == "high" else 1)):
                lvl = (r.get("riskLevel") or "none").upper()
                icon = "\U0001f534" if lvl == "HIGH" else "\U0001f7e0" if lvl == "MEDIUM" else "\u26aa"
                a(f"| {icon} {lvl} | {r.get('userDisplayName', '?')} | {r.get('riskState', '?')} "
                  f"| {r.get('riskDetail', '?')} | {str(r.get('riskLastUpdatedDateTime', '?'))[:10]} |")
            a("")
        else:
            a("> \u2705 No risky users detected (or Identity Protection not available).\n")

        if self.kql_risk:
            a("### IdentityInfo Risk\n")
            a("| Risk Level | Count | Enabled |")
            a("|------------|------:|--------:|")
            for row in self.kql_risk:
                a(f"| {row.get('RiskLevel', '?')} ({row.get('RiskState', '?')}) | {row.get('Count', 0)} | {row.get('EnabledCount', 0)} |")
            a("")
        a("---\n")

        # ── MDI Tags ──
        a("## \U0001f3f7\ufe0f Sensitive & Honeytoken Accounts\n")
        if self.kql_tags:
            a("| Tag | Count | Sample Accounts |")
            a("|-----|------:|----------------|")
            for t in self.kql_tags:
                a(f"| {t.get('TagName', '?')} | {t.get('AccountCount', 0)} | {t.get('Accounts', '?')} |")
            a("")
        else:
            a("> \u26a0\ufe0f No MDI tags found in IdentityInfo. No accounts tagged Sensitive/Honeytoken.\n")
        a("---\n")

        # ── Score Card ──
        a("## Identity Posture Score Card\n")
        a("```")
        a(f"\u250c{'─'*61}\u2510")
        a(f"\u2502{'IDENTITY POSTURE SCORE: ' + str(m['score_total']) + '/100':^61}\u2502")
        a(f"\u2502{'Rating: ' + m['score_emoji'] + ' ' + m['score_rating']:^61}\u2502")
        a(f"\u251c{'─'*61}\u2524")
        for name, score, detail in m["dims"]:
            line = f" {name:<16}[{bar(score)}] {score:>2}/20  {detail}"
            a(f"\u2502{line:<61}\u2502")
        a(f"\u2514{'─'*61}\u2518")
        a("```\n")
        a("---\n")

        # ── Security Assessment ──
        a("## Security Assessment\n")
        a("| Factor | Finding |")
        a("|--------|---------|")
        if m["n_high_risk"] > 0:
            for r in m["high_risk"]:
                a(f"| \U0001f534 **Compromised Account** | {r.get('userDisplayName')} (`{r.get('userPrincipalName')}`) — "
                  f"{r.get('riskState')} since {str(r.get('riskLastUpdatedDateTime',''))[:10]} |")
        if m["n_admin_no_mfa"] > 0:
            a(f"| \U0001f534 **Admin without MFA** | {m['n_admin_no_mfa']} admin account(s) have no MFA registered |")
        if m["mfa_pct"] < 80:
            a(f"| \U0001f7e0 **Low MFA Coverage** | {m['mfa_pct']:.0f}% MFA coverage (target: >95%) |")
        if m["n_stale"] > 0:
            a(f"| \U0001f7e0 **Stale Accounts** | {m['n_stale']} accounts without sign-in in 90+ days |")
        if m["uac_pwd_never_expires"] > 0:
            a(f"| \U0001f7e0 **PasswordNeverExpires** | {m['uac_pwd_never_expires']} AD accounts with password that never expires |")
        if not m["roles_available"]:
            a(f"| \U0001f7e1 **Roles Not Available** | Directory Roles returned 403 — role audit incomplete |")
        if not self.kql_tags:
            a(f"| \U0001f7e1 **No MDI Tags** | No Sensitive/Honeytoken tags configured |")
        a("\n---\n")

        # ── Recommendations ──
        a("## Recommendations\n")
        rec_num = 0
        if m["n_high_risk"] > 0:
            rec_num += 1
            a(f"{rec_num}. \U0001f534 **IMMEDIATE — Remediate compromised account(s):** Disable, revoke sessions, investigate lateral movement.")
        if m["n_admin_no_mfa"] > 0:
            rec_num += 1
            a(f"{rec_num}. \U0001f534 **URGENT — MFA for admin accounts:** Register MFA for all privileged accounts.")
        if m["mfa_pct"] < 80:
            rec_num += 1
            a(f"{rec_num}. \U0001f7e0 **HIGH — Increase MFA coverage:** Target >95%. Deploy Conditional Access requiring MFA.")
        if m["n_stale"] > 5:
            rec_num += 1
            a(f"{rec_num}. \U0001f7e0 **HIGH — Review stale accounts:** Disable or delete the {m['n_stale']} accounts without activity.")
        if m["uac_pwd_never_expires"] > 0:
            rec_num += 1
            a(f"{rec_num}. \U0001f7e0 **MEDIUM — Fix AD password policy:** Remove PasswordNeverExpires from {m['uac_pwd_never_expires']} accounts.")
        if not m["roles_available"]:
            rec_num += 1
            a(f"{rec_num}. \U0001f7e1 **MEDIUM — Grant Directory.Read.All:** Enable full role audit.")
        if not self.kql_tags:
            rec_num += 1
            a(f"{rec_num}. \U0001f7e1 **LOW — Configure MDI tags:** Tag privileged accounts as Sensitive in Defender for Identity.")
        a("\n---\n")

        # ── Data Coverage ──
        a("## Data Coverage Summary\n")
        a("| Source | Status | Notes |")
        a("|--------|--------|-------|")
        for c in self.data_coverage:
            a(f"| {c['source']} | {c['status']} | {c['note']} |")
        a("")

        return "\n".join(lines)

    # ── Inline Summary ───────────────────────────────────────────────────
    def print_inline_summary(self):
        m = self.m
        print(f"\n{'='*60}")
        print(f"  IDENTITY POSTURE SCORE: {m['score_total']}/100  {m['score_emoji']}  {m['score_rating']}")
        print(f"{'='*60}")
        print(f"  Accounts:  {m['total']}  (Members: {m['members']}, Guests: {m['guests']}, Agents: {m['agents']})")
        print(f"  MFA:       {m['mfa_registered']}/{m['mfa_total']} ({m['mfa_pct']:.0f}%)")
        print(f"  Stale:     {m['n_stale']} (no sign-in 90d)")
        print(f"  High-Risk: {m['n_high_risk']}")
        print(f"  Admin ∅MFA: {m['n_admin_no_mfa']}")
        if m["uac_with_data"]:
            print(f"  AD PwdNeverExpires: {m['uac_pwd_never_expires']}/{m['uac_with_data']}")
        print(f"{'─'*60}")
        for name, score, detail in m["dims"]:
            print(f"  {name:<16} [{bar(score)}] {score:>2}/20  {detail}")
        print(f"{'='*60}\n")

    # ── Run ──────────────────────────────────────────────────────────────
    def run(self) -> str:
        self.load_all()
        print("\nComputing metrics …")
        self.compute_inventory()
        self.compute_privilege()
        self.compute_stale()
        self.compute_password()
        self.compute_mfa()
        self.compute_risk()
        self.compute_tags()
        self.compute_deleted()
        self.compute_score()
        self.build_coverage()

        report_text = self.generate_report()

        # Save markdown file
        os.makedirs(self.output_dir, exist_ok=True)
        report_filename = f"Identity_Posture_Report_{self.tenant}_{self.ts}.md"
        report_path = os.path.join(self.output_dir, report_filename)

        if self.fmt in ("markdown", "both"):
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_text)
            print(f"\n[OK] Report saved: {report_path}")

        if self.fmt in ("inline", "both"):
            self.print_inline_summary()

        return report_path


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def _load_config():
    """Walk up from script dir to find config.json (max 10 levels: the plugin install path is 6 deep)."""
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(10):
        candidate = os.path.join(d, "config.json")
        if os.path.isfile(candidate):
            with open(candidate, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    return {}


def main():
    config = _load_config()
    tenant_default = config.get("tenant_name", "")

    parser = argparse.ArgumentParser(description="Analyze identity posture data and generate report.")
    parser.add_argument("--input-dir",  default="./output/identity-posture/",  help="Input directory with JSON files")
    parser.add_argument("--output-dir", default="./reports/identity-posture/",  help="Output directory for report")
    parser.add_argument("--format",     default="both", choices=["inline", "markdown", "both"], help="Output format")
    parser.add_argument("--tenant",     default=tenant_default,  help="Tenant short name for report filename")
    args = parser.parse_args()

    analyzer = IdentityPostureAnalyzer(args.input_dir, args.output_dir, args.tenant, args.format)
    report_path = analyzer.run()
    print(f"\n[DONE] Analysis complete. Report: {report_path}")


if __name__ == "__main__":
    main()
