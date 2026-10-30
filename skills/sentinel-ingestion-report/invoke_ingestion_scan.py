#!/usr/bin/env python3
"""
invoke_ingestion_scan.py — Sentinel Ingestion Report data-gathering pipeline.
Reads queries.yaml, executes via az CLI, post-processes, writes scratchpad.
Drop-in replacement for Invoke-IngestionScan.ps1 (no pwsh required).
"""
import argparse, json, os, re, shlex, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

DL_YES = {
    "CloudAppEvents","DeviceEvents","DeviceFileCertificateInfo","DeviceFileEvents",
    "DeviceImageLoadEvents","DeviceInfo","DeviceLogonEvents","DeviceNetworkEvents",
    "DeviceNetworkInfo","DeviceProcessEvents","DeviceRegistryEvents",
    "EmailAttachmentInfo","EmailEvents","EmailPostDeliveryEvents","EmailUrlInfo","UrlClickEvents",
    "AADManagedIdentitySignInLogs","AADNonInteractiveUserSignInLogs","AADProvisioningLogs",
    "AADServicePrincipalSignInLogs","AADUserRiskEvents","AuditLogs","AWSCloudTrail",
    "AzureDiagnostics","CommonSecurityLog","Event","GCPAuditLogs","LAQueryLogs",
    "McasShadowItReporting","MicrosoftGraphActivityLogs","OfficeActivity","Perf",
    "SecurityAlert","SecurityEvent","SecurityIncident","SentinelHealth","SigninLogs",
    "StorageBlobLogs","Syslog","W3CIISLog","WindowsEvent","WindowsFirewall",
}
DL_NO = {
    "DeviceTvmSoftwareInventory","DeviceTvmSoftwareVulnerabilities","AlertEvidence",
    "AlertInfo","IdentityDirectoryEvents","IdentityLogonEvents","IdentityQueryEvents",
    "MicrosoftServicePrincipalSignInLogs","MicrosoftNonInteractiveUserSignInLogs",
    "MicrosoftManagedIdentitySignInLogs","ThreatIntelIndicators","ThreatIntelligenceIndicator",
    "AppDependencies","AppMetrics","AppPerformanceCounters","AppTraces","AzureActivity",
    "AzureMetrics","ConfigurationChange","Heartbeat","SecurityRecommendation",
}
XDR_TABLES = {
    "CloudAppEvents","DeviceEvents","DeviceFileCertificateInfo","DeviceFileEvents",
    "DeviceImageLoadEvents","DeviceInfo","DeviceLogonEvents","DeviceNetworkEvents",
    "DeviceNetworkInfo","DeviceProcessEvents","DeviceRegistryEvents",
    "EmailAttachmentInfo","EmailEvents","EmailPostDeliveryEvents","EmailUrlInfo","UrlClickEvents",
}

EVENT_ID_DESC = {
    "1100":"Event logging service shut down","1102":"Audit log cleared",
    "4624":"Successful logon","4625":"Failed logon","4627":"Group membership information",
    "4634":"Logoff","4648":"Logon using explicit credentials",
    "4656":"Handle to object requested","4658":"Handle to object closed",
    "4660":"Object deleted","4662":"Operation performed on object","4663":"Object access attempt",
    "4670":"Permissions on object changed","4672":"Special privileges assigned",
    "4673":"Privileged service called","4688":"New process created","4689":"Process exited",
    "4698":"Scheduled task created","4699":"Scheduled task deleted",
    "4700":"Scheduled task enabled","4701":"Scheduled task disabled",
    "4702":"Scheduled task updated","4703":"Token right adjusted",
    "4704":"User right assigned","4706":"Trust to domain created",
    "4713":"Kerberos policy changed","4719":"System audit policy changed",
    "4720":"User account created","4722":"User account enabled",
    "4723":"Password change attempted","4724":"Password reset attempted",
    "4725":"User account disabled","4726":"User account deleted",
    "4728":"Member added to global group","4729":"Member removed from global group",
    "4732":"Member added to local group","4733":"Member removed from local group",
    "4738":"User account changed","4740":"User account locked out",
    "4741":"Computer account created","4742":"Computer account changed",
    "4743":"Computer account deleted","4756":"Member added to universal group",
    "4767":"User account unlocked",
    "4768":"Kerberos TGT requested","4769":"Kerberos service ticket requested",
    "4770":"Kerberos service ticket renewed","4771":"Kerberos pre-auth failed",
    "4776":"NTLM credential validation","4778":"Session reconnected",
    "4797":"Blank password test on account",
    "4798":"Local group membership enumerated","4799":"Security group membership enumerated",
    "4800":"Workstation locked","4801":"Workstation unlocked",
    "4826":"Boot Configuration Data loaded",
    "4946":"Firewall exception rule added","4947":"Firewall exception rule modified",
    "4948":"Firewall exception rule deleted","4950":"Firewall setting changed",
    "5024":"Windows Firewall started","5025":"Windows Firewall stopped",
    "5140":"Network share accessed","5145":"Network share check",
    "5156":"WFP connection allowed","5157":"WFP connection blocked",
    "5158":"WFP bind permitted","5379":"Credential Manager read",
    "5447":"WFP filter changed","6416":"External device recognized",
}

# Emoji / symbol constants
E_RED = "\U0001f534"; E_ORANGE = "\U0001f7e0"; E_YELLOW = "\U0001f7e1"; E_GREEN = "\U0001f7e2"
E_PURPLE = "\U0001f7e3"; E_BLUE = "\U0001f535"; E_WHITE = "\u26aa"; E_BLACK = "\u26ab"
E_SHIELD = "\U0001f6e1\ufe0f"; E_CHECK = "\u2705"; E_WARN = "\u26a0\ufe0f"
E_FIRE = "\U0001f525"; E_CHART = "\U0001f4ca"; E_SLEEP = "\U0001f4a4"
E_CROSS = "\u274c"; E_QUESTION = "\u2753"; E_BOOK = "\U0001f4d5"; E_EXCL = "\u2757"
EM_DASH = "\u2014"; EN_DASH = "\u2013"; GTEQ = "\u2265"; MID_DOT = "\u00b7"
E_LOCK = "\U0001f512"; E_GEAR = "\u2699\ufe0f"; E_CLOCK = "\u23f0"
E_MAILBOX = "\U0001f4ec"; E_MEMO = "\U0001f4dd"; E_SAT = "\U0001f4e1"

FACILITY_BADGES = {
    "auth": E_LOCK, "authpriv": E_LOCK,
    "daemon": E_GEAR, "kern": E_GEAR,
    "cron": E_CLOCK, "mail": E_MAILBOX,
    "user": E_MEMO, "syslog": E_MEMO, "lpr": E_MEMO,
    "news": E_MEMO, "uucp": E_MEMO, "ftp": E_MEMO,
}
SEV_EMOJIS = {
    "emerg": E_RED, "alert": E_RED, "crit": E_RED,
    "error": E_ORANGE, "warning": E_YELLOW, "notice": E_BLUE,
    "info": E_WHITE, "debug": E_BLACK,
}


# ═══════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def sf(val, default=0.0):
    """Safe float conversion."""
    if val is None:
        return default
    try:
        f = float(val)
        return default if f != f else f  # NaN check
    except (ValueError, TypeError):
        return default


def run_az(args_list, parse_json=True):
    """Run an az CLI command, return parsed JSON or raw text."""
    cmd = ["az"] + args_list
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, encoding="utf-8")
        if r.returncode != 0:
            print(f"   \u26a0\ufe0f  az error: {r.stderr.strip()[:200]}", file=sys.stderr)
            return None
        if parse_json and r.stdout.strip():
            return json.loads(r.stdout)
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"   \u26a0\ufe0f  az timeout: {' '.join(args_list[:4])}", file=sys.stderr)
        return None
    except json.JSONDecodeError:
        return r.stdout.strip() if 'r' in dir() else None


def flatten_kql_result(data):
    """Flatten az monitor log-analytics query JSON output to list of dicts."""
    if not data:
        return []
    if isinstance(data, list) and len(data) > 0:
        first = data[0]
        if isinstance(first, dict) and 'tables' in first:
            tables = first.get('tables', [])
            if tables:
                cols = [c['name'] for c in tables[0].get('columns', [])]
                return [dict(zip(cols, row)) for row in tables[0].get('rows', [])]
        if isinstance(first, dict) and 'tables' not in first:
            return data  # Already flat
    return []


# ═══════════════════════════════════════════════════════════════
# YAML PARSER (lightweight, no PyYAML dependency)
# ═══════════════════════════════════════════════════════════════

def parse_yaml_docs(text):
    """Parse multi-document YAML (--- separated). Returns list of dicts."""
    docs = []
    for raw in re.split(r'^---\s*$', text, flags=re.MULTILINE):
        raw = raw.strip()
        if not raw:
            continue
        doc = {}
        lines = raw.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.strip() or line.strip().startswith('#'):
                i += 1; continue
            m = re.match(r'^(\w[\w_-]*)\s*:\s*(.*)', line)
            if m:
                key, val = m.group(1), m.group(2).strip()
                if val in ('|', '>'):
                    block = []
                    i += 1
                    while i < len(lines):
                        bl = lines[i]
                        if bl and not bl[0].isspace() and bl.strip():
                            break
                        block.append(bl)
                        i += 1
                    if block:
                        indent = len(block[0]) - len(block[0].lstrip())
                        doc[key] = '\n'.join(l[indent:] if len(l) > indent else l for l in block).rstrip()
                    else:
                        doc[key] = ''
                    continue
                else:
                    if val.lower() in ('true', 'false'):
                        doc[key] = val.lower() == 'true'
                    else:
                        try:
                            doc[key] = int(val)
                        except ValueError:
                            doc[key] = val
            i += 1
        if doc.get('id'):
            docs.append(doc)
    return docs


# ═══════════════════════════════════════════════════════════════
# CONFIG & DATE WINDOWS
# ═══════════════════════════════════════════════════════════════

def find_config(start_dir):
    d = Path(start_dir).resolve()
    for _ in range(10):
        cfg = d / 'config.json'
        if cfg.exists():
            return cfg
        parent = d.parent
        if parent == d:
            break
        d = parent
    return None


def resolve_config(args):
    script_dir = Path(__file__).resolve().parent
    cfg_path = Path(args.config) if args.config else find_config(script_dir)
    cfg = {}
    if cfg_path and cfg_path.exists():
        with open(cfg_path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    mcp = cfg.get('azure_mcp', {})
    c = {
        'workspace_id': args.workspace_id or cfg.get('sentinel_workspace_id', ''),
        'subscription_id': args.subscription_id or cfg.get('subscription_id', ''),
        'resource_group': args.resource_group or mcp.get('resource_group', ''),
        'workspace_name': args.workspace_name or mcp.get('workspace_name', ''),
        'config': cfg,
    }
    if not c['workspace_id']:
        print("\u274c No workspace_id. Use --workspace-id or set sentinel_workspace_id in config.json", file=sys.stderr)
        sys.exit(1)
    return c


def compute_windows(days):
    if days <= 7: deep = days
    elif days <= 30: deep = 7
    elif days <= 60: deep = 14
    else: deep = 30
    wow = deep * 2
    if deep == 7: labels = ("This Week", "Last Week", "WoW Change")
    elif deep == 14: labels = ("This Period", "Last Period", "PoP Change")
    elif deep == 30: labels = ("This Month", "Last Month", "MoM Change")
    else: labels = (f"Last {deep}d", f"Prior {deep}d", "Change")
    return deep, wow, labels


# ═══════════════════════════════════════════════════════════════
# QUERY LOADING & EXECUTION
# ═══════════════════════════════════════════════════════════════

def load_queries(yaml_path):
    return parse_yaml_docs(yaml_path.read_text(encoding='utf-8'))


def substitute(q, days, deep, wow, config, extra=None):
    subs = {
        '{days}': str(days), '{deepDiveDays}': str(deep), '{wowTotalDays}': str(wow),
        '{workspace_id}': config.get('workspace_id', ''),
        '{subscription_id}': config.get('subscription_id', ''),
        '{resource_group}': config.get('resource_group', ''),
        '{workspace_name}': config.get('workspace_name', ''),
    }
    if extra:
        subs.update(extra)
    r = dict(q)
    for field in ('query', 'timespan', 'url', 'command', 'uri'):
        if field in r and isinstance(r[field], str):
            for tok, val in subs.items():
                r[field] = r[field].replace(tok, val)
    return r


def exec_kql(query_text, workspace_id, timespan):
    collapsed = ' '.join(line.strip() for line in query_text.split('\n') if line.strip())
    args = ["monitor", "log-analytics", "query", "-w", workspace_id, "--analytics-query", collapsed]
    if timespan:
        args += ["-t", timespan]
    args += ["-o", "json"]
    return flatten_kql_result(run_az(args))


def exec_rest(url, method="get", jmespath_expr=None):
    args = ["rest", "--method", method, "--url", url]
    if jmespath_expr:
        args += ["--query", jmespath_expr]
    args += ["-o", "json"]
    return run_az(args)


def exec_cli(command, config):
    cmd = command
    for k, v in config.items():
        if isinstance(v, str):
            cmd = cmd.replace(f'{{{k}}}', v)
    parts = shlex.split(cmd.strip())
    if parts and parts[0] == 'az':
        parts = parts[1:]
    if "-o" not in parts and "--output" not in parts:
        parts += ["-o", "json"]
    return run_az(parts)


def exec_graph(uri, method="GET"):
    url = f"https://graph.microsoft.com{uri}" if uri.startswith('/') else uri
    return run_az(["rest", "--method", method.lower(), "--url", url, "-o", "json"])


def execute_phase_queries(phase_queries, config, all_results, days, deep, wow, extra=None):
    """Execute all queries for a phase. KQL in parallel, non-KQL sequential. Skips depends_on."""
    kql_qs = [q for q in phase_queries if q.get('type', 'kql') == 'kql' and not q.get('depends_on')]
    non_kql = [q for q in phase_queries if q.get('type', 'kql') != 'kql']
    # depends_on queries are handled in post-processing
    deferred = [q for q in phase_queries if q.get('depends_on')]

    # Parallel KQL
    if kql_qs:
        def _run(q):
            sq = substitute(q, days, deep, wow, config, extra)
            print(f"   \u25b6 {sq['id']}: {sq.get('name', '')}")
            return sq['id'], exec_kql(sq.get('query', ''), config['workspace_id'], sq.get('timespan', ''))
        with ThreadPoolExecutor(max_workers=5) as pool:
            futs = {pool.submit(_run, q): q for q in kql_qs}
            for fut in as_completed(futs):
                try:
                    qid, data = fut.result()
                    all_results[qid] = data or []
                    print(f"   \u2705 {qid}: {len(data) if isinstance(data, list) else 0} rows")
                except Exception as e:
                    q = futs[fut]
                    print(f"   \u274c {q['id']}: {e}", file=sys.stderr)
                    all_results[q['id']] = []

    # Sequential non-KQL
    for q in non_kql:
        sq = substitute(q, days, deep, wow, config, extra)
        qid, qtype = sq['id'], sq.get('type', 'kql')
        print(f"   \u25b6 {qid}: {sq.get('name', '')} ({qtype})")
        try:
            if qtype == 'rest':
                data = exec_rest(sq.get('url', ''), sq.get('method', 'get'), sq.get('jmespath'))
            elif qtype == 'cli':
                data = exec_cli(sq.get('command', ''), config)
            elif qtype == 'graph':
                data = exec_graph(sq.get('uri', ''), sq.get('method', 'GET'))
            else:
                data = None
            all_results[qid] = data or []
            cnt = len(data) if isinstance(data, list) else ('dict' if isinstance(data, dict) else 'done')
            print(f"   \u2705 {qid}: {cnt}")
        except Exception as e:
            print(f"   \u274c {qid}: {e}", file=sys.stderr)
            all_results[qid] = []

    return deferred  # Return deferred queries for post-processing


# ═══════════════════════════════════════════════════════════════
# POST-PROCESSING: PHASE 1
# ═══════════════════════════════════════════════════════════════

def post_process_phase1(all_results, ctx, days):
    print("\U0001f4ca Phase 1 post-processing...")
    q1 = all_results.get('ingestion-q1', [])
    q2 = all_results.get('ingestion-q2', [])
    q3 = all_results.get('ingestion-q3', [])

    s = q3[0] if q3 else {}
    ctx['total_gb'] = sf(s.get('TotalGB'))
    ctx['billable_gb'] = sf(s.get('BillableGB'))
    ctx['non_billable_gb'] = sf(s.get('NonBillableGB'))
    ctx['avg_daily_gb'] = sf(s.get('AvgDailyGB'))
    ctx['total_table_count'] = int(sf(s.get('TotalTableCount')))
    ctx['billable_table_count'] = int(sf(s.get('BillableTableCount')))
    ctx['billable_percent'] = sf(s.get('BillablePercent'))
    ctx['q1_data'] = q1 or []

    daily = []
    for row in (q2 or []):
        ds = str(row.get('TimeGenerated', ''))[:10]
        try:
            dt = datetime.strptime(ds, '%Y-%m-%d')
        except ValueError:
            continue
        daily.append({'date': dt, 'gb': sf(row.get('DailyGB'))})
    ctx['daily_trend'] = daily
    if daily:
        ctx['peak'] = max(daily, key=lambda d: d['gb'])
        ctx['min_day'] = min(daily, key=lambda d: d['gb'])
    print(f"   \u2705 Phase 1: {len(q1)} tables, {len(daily)} days")


# ═══════════════════════════════════════════════════════════════
# POST-PROCESSING: PHASE 2
# ═══════════════════════════════════════════════════════════════

def post_process_phase2(all_results, ctx, deep_dive_days):
    print("\U0001f4ca Phase 2 post-processing...")
    for qid in ('ingestion-q4','ingestion-q5','ingestion-q6a','ingestion-q6b',
                 'ingestion-q6c','ingestion-q7','ingestion-q8'):
        d = all_results.get(qid, [])
        print(f"   \u2705 {qid}: {len(d) if isinstance(d, list) else 0} rows")


# ═══════════════════════════════════════════════════════════════
# POST-PROCESSING: PHASE 3
# ═══════════════════════════════════════════════════════════════

def post_process_phase3(all_results, ctx, config, days, deep, wow, deferred_queries):
    print("\U0001f4ca Phase 3 post-processing...")

    # --- Q9: Analytic Rules (REST) ---
    q9_raw = all_results.get('ingestion-q9', [])
    q9_rules = q9_raw.get('value', []) if isinstance(q9_raw, dict) else (q9_raw if isinstance(q9_raw, list) else [])

    all_rules = []
    ar_total = len(q9_rules)
    ar_enabled = ar_disabled = ar_nrt = 0
    for r in q9_rules:
        props = r.get('properties', r)
        enabled = props.get('enabled', False)
        if enabled:
            ar_enabled += 1
            kind = props.get('kind', '')
            if isinstance(kind, str) and kind.lower() == 'nrt':
                ar_nrt += 1
            all_rules.append({'name': props.get('displayName', ''), 'query': props.get('query', ''), 'source': 'AR'})
        else:
            ar_disabled += 1
    ctx.update(ar_total=ar_total, ar_enabled=ar_enabled, ar_disabled=ar_disabled, ar_nrt=ar_nrt)

    # --- Q9b: Custom Detections (Graph) ---
    q9b_raw = all_results.get('ingestion-q9b')
    cd_status = None
    if not q9b_raw or (isinstance(q9b_raw, list) and len(q9b_raw) == 0):
        cd_status = "Graph API returned no data or unavailable"
        ctx.update(cd_total=0, cd_enabled=0, cd_disabled=0)
    else:
        cd_list = q9b_raw.get('value', []) if isinstance(q9b_raw, dict) else q9b_raw
        cd_en = sum(1 for r in cd_list if r.get('isEnabled', False))
        ctx.update(cd_total=len(cd_list), cd_enabled=cd_en, cd_disabled=len(cd_list) - cd_en)
        for r in cd_list:
            if r.get('isEnabled', False):
                qt = ''
                qc = r.get('queryCondition')
                if isinstance(qc, dict):
                    qt = qc.get('queryText', '')
                all_rules.append({'name': r.get('displayName', ''), 'query': qt, 'source': 'CD'})
    ctx['cd_status'] = cd_status
    ctx['all_rules'] = all_rules

    # --- Q10: Tier Classification (CLI) ---
    q10_raw = all_results.get('ingestion-q10', [])
    q10_data = []
    if isinstance(q10_raw, list):
        for t in q10_raw:
            name = t.get('name', '')
            plan = t.get('plan', 'Analytics')
            if isinstance(plan, dict):
                plan = plan.get('planName', 'Analytics')
            q10_data.append({'name': name, 'plan': plan})
    ctx['q10_data'] = q10_data
    all_results['ingestion-q10'] = q10_data

    # --- Q10b: Tier Summary (KQL, depends_on Q10) ---
    dl_names = ','.join(f"'{t['name']}'" for t in q10_data if t['plan'] in ('Auxiliary', 'auxiliary')) or "'__NONE__'"
    basic_names = ','.join(f"'{t['name']}'" for t in q10_data if t['plan'] in ('Basic', 'basic')) or "'__NONE__'"
    extra = {'{DataLakeTables}': dl_names, '{BasicTables}': basic_names}

    q10b_def = next((q for q in deferred_queries if q['id'] == 'ingestion-q10b'), None)
    if 'ingestion-q10b' in all_results:
        print(f"   \u2705 ingestion-q10b: {len(all_results['ingestion-q10b']) if isinstance(all_results['ingestion-q10b'], list) else 'dict'} (already loaded)")
    elif q10b_def:
        sq = substitute(q10b_def, days, deep, wow, config, extra)
        print(f"   \u25b6 {sq['id']}: {sq.get('name', '')} (deferred KQL)")
        data = exec_kql(sq.get('query', ''), config['workspace_id'], sq.get('timespan', ''))
        all_results['ingestion-q10b'] = data or []
        print(f"   \u2705 ingestion-q10b: {len(data) if data else 0} rows")

    ctx['tier_summary'] = all_results.get('ingestion-q10b', [])

    print(f"   \u2705 Phase 3: AR={ar_total}(E:{ar_enabled} D:{ar_disabled} NRT:{ar_nrt}), "
          f"CD={ctx.get('cd_total',0)}, Tiers={len(q10_data)}")


# ═══════════════════════════════════════════════════════════════
# POST-PROCESSING: PHASES 4-5 (Turn 2 replaces these stubs)
# ═══════════════════════════════════════════════════════════════

def post_process_phase4(all_results, ctx, deep_dive_days):
    """Phase 4: Cross-ref, ASIM, value-ref, detection gaps."""
    print("\U0001f4ca Phase 4 post-processing...")
    all_rules = ctx.get('all_rules', [])
    q10_data = ctx.get('q10_data', [])
    q13 = all_results.get('ingestion-q13', [])

    # --- Cross-reference: table → rules ---
    cross_ref = []
    tables_with_data = sorted(set(str(r.get('DataType', '')) for r in q13 if r.get('DataType')))
    for tbl in tables_with_data:
        pat = re.compile(re.escape(tbl), re.IGNORECASE)
        ar_count = cd_count = 0
        key_names = []
        for rule in all_rules:
            query_text = rule.get('query', '')
            if pat.search(query_text):
                if rule['source'] == 'AR':
                    ar_count += 1
                else:
                    cd_count += 1
                if len(key_names) < 3:
                    key_names.append(rule['name'])
        total = ar_count + cd_count
        if total > 0:
            extra_count = total - len(key_names)
            names_str = '; '.join(key_names)
            if extra_count > 0:
                names_str += f'; +{extra_count} more'
            cross_ref.append({
                'Table': tbl, 'AR': ar_count, 'CD': cd_count,
                'Total': total, 'KeyNames': names_str
            })
    cross_ref.sort(key=lambda x: x['Total'], reverse=True)
    ctx['cross_ref'] = cross_ref

    # --- Zero-rule tables (top-20 from Q1) ---
    q1_tables = set(r.get('DataType', '') for r in ctx.get('q1_data', []))
    ref_tables = set(r['Table'] for r in cross_ref)
    zero_rule = sorted(q1_tables - ref_tables)
    ctx['zero_rule_tables'] = zero_rule

    # --- ASIM pattern detection ---
    asim_patterns = []
    asim_re = re.compile(r'(_Im_\w+|_ASim_\w+|imDns|imWebSession|imNetworkSession|imAuthentication|imProcessCreate|imFileEvent|imAuditEvent)', re.IGNORECASE)
    for rule in all_rules:
        matches = asim_re.findall(rule.get('query', ''))
        if matches:
            schemas = sorted(set(matches))
            asim_patterns.append({'Rule': rule['name'], 'Schemas': ', '.join(schemas), 'Source': rule['source']})
    ctx['asim_patterns'] = asim_patterns

    # --- Value-level rule references (EventID, Facility, Process, Activity, Vendor) ---
    def build_value_ref(items, key_field, match_fn):
        refs = []
        for item in items:
            val = str(item.get(key_field, ''))
            if not val:
                continue
            ar_c = cd_c = 0
            kn = []
            for rule in all_rules:
                if match_fn(val, rule.get('query', '')):
                    if rule['source'] == 'AR':
                        ar_c += 1
                    else:
                        cd_c += 1
                    if len(kn) < 3:
                        kn.append(rule['name'])
            tot = ar_c + cd_c
            extra = tot - len(kn)
            ns = '; '.join(kn)
            if extra > 0:
                ns += f'; +{extra} more'
            refs.append({key_field: val, 'AR': ar_c, 'CD': cd_c, 'Total': tot, 'KeyNames': ns})
        return refs

    q5 = all_results.get('ingestion-q5', [])
    ctx['value_ref_eventid'] = build_value_ref(q5, 'EventID',
        lambda v, q: re.search(r'\b' + re.escape(v) + r'\b', q) is not None)

    q6b = all_results.get('ingestion-q6b', [])
    fac_items = []
    seen_fac = set()
    for r in q6b:
        f = r.get('Facility', '')
        if f and f not in seen_fac:
            seen_fac.add(f)
            fac_items.append({'Facility': f})
    ctx['value_ref_facility'] = build_value_ref(fac_items, 'Facility',
        lambda v, q: v.lower() in q.lower())

    q6c = all_results.get('ingestion-q6c', [])
    ctx['value_ref_process'] = build_value_ref(q6c, 'ProcessName',
        lambda v, q: v.lower() in q.lower() if v else False)

    q8 = all_results.get('ingestion-q8', [])
    ctx['value_ref_activity'] = build_value_ref(q8, 'Activity',
        lambda v, q: v.lower() in q.lower() if v else False)

    q7 = all_results.get('ingestion-q7', [])
    ctx['value_ref_vendor'] = build_value_ref(q7, 'DeviceVendor',
        lambda v, q: v.lower() in q.lower() if v else False)

    # --- Detection gaps: rules on DL/Basic tier ---
    tier_map = {}
    for t in q10_data:
        plan = t.get('plan', 'Analytics')
        tier_map[t['name']] = 'Data Lake' if plan in ('Auxiliary', 'auxiliary') else ('Basic' if plan in ('Basic', 'basic') else 'Analytics')

    detection_gaps = []
    for cr in cross_ref:
        tier = tier_map.get(cr['Table'], 'Analytics')
        if tier in ('Data Lake', 'Basic') and cr['Total'] > 0:
            is_xdr = cr['Table'] in XDR_TABLES
            gap_type = 'Detection gap (XDR)' if is_xdr else 'Detection gap (non-XDR)'
            detection_gaps.append({'Table': cr['Table'], 'Rules': cr['Total'],
                                   'Tier': tier, 'Type': gap_type})
    ctx['detection_gaps'] = detection_gaps

    # --- Health summary from Q11 ---
    q11 = all_results.get('ingestion-q11', [])
    if q11 and isinstance(q11, list) and len(q11) > 0:
        s = q11[0]
        total_exec = sf(s.get('TotalExec'))
        total_fail = sf(s.get('TotalFail'))
        osr = s.get('OverallSuccessRate')
        if osr is not None:
            computed_success_rate = sf(osr)
        elif total_exec > 0:
            computed_success_rate = round(100.0 * (total_exec - total_fail) / total_exec, 1)
        else:
            computed_success_rate = 0
        ctx['health'] = {
            'total_rules': int(sf(s.get('TotalRulesInHealth'))),
            'overall_success_rate': computed_success_rate,
            'failing_count': int(sf(s.get('FailingRuleCount'))),
        }
    else:
        ctx['health'] = {'total_rules': 0, 'overall_success_rate': 0, 'failing_count': 0}

    # --- Cross-validation: Q11 vs Q9 ---
    q11_distinct = ctx['health']['total_rules']
    ar_en = ctx.get('ar_enabled', 0)
    gap_pct = round((ar_en - q11_distinct) / ar_en * 100, 1) if ar_en > 0 else 0
    ctx['cross_validation'] = {
        'q11_distinct': q11_distinct, 'q9_ar_enabled': ar_en, 'gap': gap_pct
    }

    print(f"   \u2705 Phase 4: CrossRef={len(cross_ref)}, Gaps={len(detection_gaps)}, "
          f"ASIM={len(asim_patterns)}, ZeroRule={len(zero_rule)}")


def post_process_phase5(all_results, ctx, days, deep_dive_days):
    """Phase 5: Anomaly severity, DL classification, migration, license benefits."""
    print("\U0001f4ca Phase 5 post-processing...")
    cross_ref = ctx.get('cross_ref', [])
    cr_map = {r['Table']: r for r in cross_ref}
    q10_data = ctx.get('q10_data', [])

    # --- Anomaly24h (Q14) — severity classification ---
    def classify_anomaly(dev, max_vol, table_name):
        """Rule A + overrides."""
        if abs(dev) >= 200 and max_vol >= 0.05:
            sev = E_ORANGE
        elif abs(dev) >= 100 and max_vol >= 0.01:
            sev = E_YELLOW
        else:
            sev = E_WHITE
        # Override 1: rule-count (≥5 rules AND ≥40%) → 🟠
        cr = cr_map.get(table_name)
        if cr and cr['Total'] >= 5 and abs(dev) >= 40:
            sev = E_ORANGE
        # Override 2: near-zero (≤-95% AND ≥0.05GB) → 🟠
        if dev <= -95 and max_vol >= 0.05:
            sev = E_ORANGE
        return sev

    q14 = all_results.get('ingestion-q14', [])
    anomaly_24h = []
    for row in (q14 if isinstance(q14, list) else []):
        last24h = sf(row.get('Last24hGB'))
        avg7d = sf(row.get('Avg7dDailyGB'))
        dev = sf(row.get('DeviationPercent'))
        max_vol = max(last24h, avg7d)
        sev = classify_anomaly(dev, max_vol, row.get('DataType', ''))
        anomaly_24h.append({
            'DataType': row.get('DataType', ''), 'Last24hGB': last24h,
            'Avg7dGB': avg7d, 'Deviation': dev, 'Severity': sev
        })
    ctx['anomaly_24h'] = anomaly_24h
    print(f"   \u2705 Anomaly24h: {len(anomaly_24h)} table(s)")

    # --- AnomalyWoW (Q15) ---
    q15 = all_results.get('ingestion-q15', [])
    anomaly_wow = []
    for row in (q15 if isinstance(q15, list) else []):
        this_w = sf(row.get('ThisWeekGB'))
        last_w = sf(row.get('LastWeekGB'))
        change = sf(row.get('ChangePercent'))
        max_vol = max(this_w, last_w)
        sev = classify_anomaly(change, max_vol, row.get('DataType', ''))
        anomaly_wow.append({
            'DataType': row.get('DataType', ''), 'ThisWeekGB': this_w,
            'LastWeekGB': last_w, 'WoWChange': change, 'Severity': sev
        })
    ctx['anomaly_wow'] = anomaly_wow
    print(f"   \u2705 AnomalyWoW: {len(anomaly_wow)} table(s)")

    # --- DL Classification ---
    q16 = all_results.get('ingestion-q16', [])
    q1 = ctx.get('q1_data', [])
    all_table_names = sorted(set(
        [str(r.get('DataType', '')) for r in (q16 if isinstance(q16, list) else [])] +
        [str(r.get('DataType', '')) for r in q1]
    ))

    dl_class = {}
    for t in all_table_names:
        if not t:
            continue
        if t.endswith('_KQL_CL'):
            dl_class[t] = 'KQL'
        elif t.endswith('_CL'):
            dl_class[t] = 'Yes'
        elif t in DL_YES:
            dl_class[t] = 'Yes'
        elif t in DL_NO:
            dl_class[t] = 'No'
        else:
            dl_class[t] = 'Unknown'
    ctx['dl_class'] = dl_class
    yes_c = sum(1 for v in dl_class.values() if v == 'Yes')
    no_c = sum(1 for v in dl_class.values() if v == 'No')
    unk_c = sum(1 for v in dl_class.values() if v == 'Unknown')
    kql_c = sum(1 for v in dl_class.values() if v == 'KQL')
    print(f"   \u2705 DL Classification: {len(dl_class)} tables (Yes={yes_c}, No={no_c}, Unknown={unk_c}, KQL={kql_c})")

    # --- Tier map from Q10 ---
    tier_map = {}
    for t in q10_data:
        plan = t.get('plan', 'Analytics')
        tier_map[t['name']] = 'Data Lake' if plan in ('Auxiliary', 'auxiliary') else ('Basic' if plan in ('Basic', 'basic') else 'Analytics')

    # --- Migration Table ---
    migration_rows = []
    for row in (q16 if isinstance(q16, list) else []):
        table = row.get('DataType', '')
        gb7d = sf(row.get('BillableGB'))
        cr = cr_map.get(table)
        ar_count = cr['AR'] if cr else 0
        cd_count = cr['CD'] if cr else 0
        total = cr['Total'] if cr else 0
        tier = tier_map.get(table, 'Analytics')
        dl_elig = dl_class.get(table, 'Unknown')

        # Category classification
        if table.endswith('_KQL_CL'):
            category = E_BLUE + ' KQL Job'
            sub_table = 'Sub-table 2'
        elif tier == 'Data Lake' and total == 0:
            category = E_BLUE + ' Already DL'
            sub_table = 'Sub-table 4'
        elif tier in ('Data Lake', 'Basic') and total > 0:
            if table in XDR_TABLES:
                category = E_RED + ' Detection gap (XDR)'
            else:
                category = E_RED + ' Detection gap (non-XDR)'
            sub_table = 'Sub-table 3'
        elif total == 0 and dl_elig == 'Yes':
            category = E_RED + ' Strong (DL-eligible)'
            sub_table = 'Sub-table 1'
        elif total == 0 and dl_elig in ('No', 'Unknown'):
            category = E_ORANGE + ' Not eligible/unknown'
            sub_table = 'Sub-table 2'
        elif total in (1, 2) and gb7d >= 5.0 and dl_elig == 'Yes':
            category = E_PURPLE + ' Split candidate'
            sub_table = 'Sub-table 3'
        elif total >= 1:
            category = E_GREEN + f' Keep ({total} rules)'
            sub_table = 'Sub-table 3'
        else:
            category = E_ORANGE + ' Not eligible/unknown'
            sub_table = 'Sub-table 2'

        migration_rows.append({
            'Table': table, 'GB7d': gb7d, 'AR': ar_count, 'CD': cd_count,
            'Total': total, 'Tier': tier, 'DLElig': dl_elig,
            'Category': category, 'SubTable': sub_table
        })
    ctx['migration_rows'] = migration_rows

    dl_cand = sum(1 for r in migration_rows if r['SubTable'] == 'Sub-table 1')
    keep_r = sum(1 for r in migration_rows if r['SubTable'] == 'Sub-table 3')
    already_dl = sum(1 for r in migration_rows if r['SubTable'] == 'Sub-table 4')
    print(f"   \u2705 Migration: {len(migration_rows)} tables — {dl_cand} DL candidates, {keep_r} with rules, {already_dl} already DL")

    # --- License Benefits (Q17) ---
    q17 = all_results.get('ingestion-q17', [])
    if q17 and isinstance(q17, list) and len(q17) > 0:
        dfsp2_vals = [sf(r.get('DFSP2GB')) for r in q17]
        e5_vals = [sf(r.get('E5GB')) for r in q17]
        rem_vals = [sf(r.get('RemainingGB')) for r in q17]
        dfsp2_daily = sum(dfsp2_vals) / len(dfsp2_vals)
        e5_daily = sum(e5_vals) / len(e5_vals)
        rem_daily = sum(rem_vals) / len(rem_vals)
        dfsp2_sum = sum(dfsp2_vals)
        e5_sum = sum(e5_vals)
        rem_sum = sum(rem_vals)

        # Server count from Phase 2 Q4
        q4 = all_results.get('ingestion-q4', [])
        if q4 and isinstance(q4, list) and len(q4) > 0 and q4[0].get('TotalServers'):
            server_count = int(sf(q4[0].get('TotalServers')))
        elif q4 and isinstance(q4, list):
            server_count = len(q4)
        else:
            server_count = 0
        dfsp2_pool = round(server_count * 0.5, 3)

        ctx['license'] = {
            'dfsp2_daily': round(dfsp2_daily, 3), 'e5_daily': round(e5_daily, 3),
            'rem_daily': round(rem_daily, 3),
            'dfsp2_sum': round(dfsp2_sum, 3), 'e5_sum': round(e5_sum, 3),
            'rem_sum': round(rem_sum, 3),
            'server_count': server_count, 'dfsp2_pool': dfsp2_pool
        }
        print(f"   \u2705 License: DfSP2={round(dfsp2_daily, 3)} GB/d, E5={round(e5_daily, 3)} GB/d, "
              f"Remaining={round(rem_daily, 3)} GB/d ({server_count} servers)")
    else:
        ctx['license'] = None
        print("   \u26a0\ufe0f  LicenseBenefits: Q17 returned no data")

    # --- E5 Per-Table (Q17b) ---
    q17b = all_results.get('ingestion-q17b', [])
    ctx['e5_tables'] = q17b if isinstance(q17b, list) else []
    print(f"   \u2705 E5_Tables: {len(ctx['e5_tables'])} E5-eligible tables")

    # --- Failing rules (Q11d) ---
    q11d = all_results.get('ingestion-q11d', [])
    ctx['failing_rules'] = q11d if isinstance(q11d, list) else []

    # --- Alert-producing rules (Q12) ---
    q12 = all_results.get('ingestion-q12', [])
    ctx['alert_rules'] = q12 if isinstance(q12, list) else []


# ═══════════════════════════════════════════════════════════════
# PRERENDERED BLOCKS (Turn 3 replaces this stub)
# ═══════════════════════════════════════════════════════════════

def build_prerendered(ctx, all_results, phases, days, deep, wow, labels):
    """Build all 18 PRERENDERED markdown blocks."""
    if isinstance(labels, tuple):
        labels = {
            'this_period': labels[0] if len(labels) > 0 else '',
            'last_period': labels[1] if len(labels) > 1 else '',
            'wow_change': labels[2] if len(labels) > 2 else '',
            'period': f"{labels[0]} vs {labels[1]}" if len(labels) > 1 else (labels[0] if labels else ''),
        }
    lines = []
    L = lines.append

    cr_map = {r['Table']: r for r in ctx.get('cross_ref', [])}
    q10_data = ctx.get('q10_data', [])
    tier_map = {}
    for t in q10_data:
        plan = t.get('plan', 'Analytics')
        tier_map[t['name']] = 'Data Lake' if plan in ('Auxiliary', 'auxiliary') else ('Basic' if plan in ('Basic', 'basic') else 'Analytics')

    GEQ = '\u2265'; ENDASH = '\u2013'; EMDASH = '\u2014'; MIDDOT = '\u00b7'
    MULT = '\u00d7'; SECT = '\u00a7'

    def vol_badge(gb, thresholds=(500, 100, 10)):
        t1, t2, t3 = thresholds
        if gb >= t1: return E_RED
        if gb >= t2: return E_ORANGE
        if gb >= t3: return E_YELLOW
        return E_GREEN

    def rule_badge_str(total, value_ref_entry=None):
        vr = value_ref_entry
        t = vr['Total'] if vr else total
        kn = vr.get('KeyNames', '') if vr else ''
        if t >= 50: b = E_PURPLE
        elif t >= 10: b = E_GREEN
        elif t >= 3: b = E_YELLOW
        elif t >= 1: b = E_ORANGE
        else: b = '\u26a0\ufe0f'
        s = f"{b} {t}"
        if kn and t >= 1:
            s += f" {EMDASH} {kn}"
        elif t == 0:
            s = f"\u26a0\ufe0f 0 rules"
        return s

    def fmt_count(n):
        try:
            return f"{int(n):,}"
        except (ValueError, TypeError):
            return str(n)

    def fmt_gb(gb):
        if gb > 0 and gb < 0.01: return '< 0.01'
        return f"{gb:.2f}"

    def fmt_pct(p):
        try:
            v = float(p)
            if v != v: return '< 0.1'  # NaN
            return f"{v:.1f}"
        except (ValueError, TypeError):
            return '< 0.1'

    period_label = labels.get('period', '')
    this_period = labels.get('this_period', '')
    last_period = labels.get('last_period', '')
    wow_label = labels.get('wow_change', '')

    # ─── Headings ─────────────────────────────────────────────────────
    L("### Headings")
    L(f"""## 1. Executive Summary
### \U0001f4ca Workspace at a Glance
### \U0001f4b0 Cost Waterfall
### \U0001f6e1\ufe0f Detection Posture
### Overall Assessment
### \U0001f3af Top 3 Recommendations
## 2. Ingestion Overview
### 2a. Top Tables by Volume
### 2b. Tier Classification
## 3. Deep Dives
### 3a. SecurityEvent
### 3b. Syslog
### 3c. CommonSecurityLog
## 4. Anomaly Detection
### 4a. Per-Table Anomaly Summary (24h + WoW)
### 4b. Daily Trend ({days} Days)
## 5. Detection Coverage
### 5a. Rule Inventory & Table Cross-Reference
### 5b. Rule Health & Alerts
## 6. License Benefit Analysis
### 6a. Defender for Servers P2 Pool Detail
### 6b. E5 / Defender XDR Pool Detail
## 7. Optimization Recommendations
### 7a. Data Lake Migration Candidates
### 7b. \u26a1 Quick Wins
### 7c. \U0001f527 Medium-Term Optimizations
### 7d. \U0001f504 Ongoing Maintenance
## 8. Appendix
### 8a. Query Reference
### 8b. Data Freshness
### 8c. Methodology
### 8d. Limitations""")

    # ─── CostWaterfall ────────────────────────────────────────────────
    L("")
    L("### CostWaterfall")
    lic = ctx.get('license')
    if 1 in phases and 5 in phases and lic:
        total_gb = ctx.get('total_gb', 0)
        billable_gb = ctx.get('billable_gb', 0)
        non_bill = ctx.get('non_billable_gb', 0)
        daily_trend = ctx.get('daily_trend', [])
        dc = len(daily_trend) if daily_trend else 30
        t_daily = round(total_gb / max(dc, 1), 3)
        nb_daily = round(non_bill / max(dc, 1), 3)
        gb_daily = round(billable_gb / max(dc, 1), 3)
        e5s = lic['e5_sum']; e5d = lic['e5_daily']
        ds = lic['dfsp2_sum']; dd = lic['dfsp2_daily']
        rs = lic['rem_sum']; rd = lic['rem_daily']
        L(f"""```
                                    {days}-Day (GB)    Avg/Day (GB)
  Total Ingestion                     {total_gb:>7.3f}          {t_daily:>7.3f}
  - Non-Billable                     -{non_bill:>7.3f}         -{nb_daily:>7.3f}
  {'─'*62}
  Gross Billable                      {billable_gb:>7.3f}          {gb_daily:>7.3f}
  - Est. E5/XDR Benefit              -{e5s:>7.3f}         -{e5d:>7.3f}
  - Est. DfS P2 Benefit              -{ds:>7.3f}         -{dd:>7.3f}
  {'─'*62}
  \U0001f3af Est. Net Billable               ~{rs:>7.3f}         ~{rd:>7.3f}
```""")
    else:
        L(f"UNAVAILABLE {EMDASH} requires Phase 1 + Phase 5 data")

    # ─── DailyChart ───────────────────────────────────────────────────
    L("")
    L("### DailyChart")
    daily_trend = ctx.get('daily_trend', [])
    if 1 in phases and daily_trend:
        gen_date = datetime.now().strftime('%Y-%m-%d')
        max_bar = 50
        full_days = [d for d in daily_trend if d['date'].strftime('%Y-%m-%d') != gen_date and d['gb'] >= 0.1]
        if not full_days:
            full_days = daily_trend
        avg_gb = sum(d['gb'] for d in full_days) / max(len(full_days), 1)
        peak = max(full_days, key=lambda d: d['gb'])
        min_d = min(full_days, key=lambda d: d['gb'])
        max_gb = max(d['gb'] for d in daily_trend) or 1

        wd_buckets = {n: [] for n in ('Mon','Tue','Wed','Thu','Fri','Sat','Sun')}
        for d in full_days:
            wd_buckets[d['date'].strftime('%a')] .append(d['gb'])
        wd_parts = []
        for n in ('Mon','Tue','Wed','Thu','Fri','Sat','Sun'):
            vals = wd_buckets[n]
            if vals:
                wd_parts.append(f"{n} {sum(vals)/len(vals):.2f}")
            else:
                wd_parts.append(f"{n} {EMDASH}")

        ws_name = ctx.get('workspace_name', '')
        chart = [
            "```",
            f"Daily Ingestion {EMDASH} {ws_name} ({period_label})",
            f"Date          GB     Trend (max = {max_gb:.2f} GB)",
            '\u2500' * 65
        ]
        for d in daily_trend:
            bar_len = max(1, round(d['gb'] / max_gb * max_bar))
            bar = '\u2588' * bar_len
            ann = ''
            if d['date'] == peak['date']:
                ann = ' \u2190 peak'
            elif d['date'] == min_d['date']:
                ann = ' \u2190 min'
            elif d['date'].strftime('%Y-%m-%d') == gen_date:
                ann = ' \u2190 partial'
            chart.append(f"{d['date'].strftime('%Y-%m-%d')} \u2502 {d['gb']:>6.3f}  {bar}{ann}")
        chart.append('\u2500' * 65)
        chart.append(f"Avg: {avg_gb:.3f} GB/day  Peak: {peak['gb']:.3f} GB ({peak['date'].strftime('%Y-%m-%d')})  Min: {min_d['gb']:.3f} GB ({min_d['date'].strftime('%Y-%m-%d')})")
        chart.append(f"Weekday Avgs: {' | '.join(wd_parts)}")
        chart.append("```")
        L('\n'.join(chart))
    else:
        L(f"UNAVAILABLE {EMDASH} requires Phase 1 data")

    # ─── TopTables ────────────────────────────────────────────────────
    L("")
    L("### TopTables")
    q1 = ctx.get('q1_data', [])
    if 1 in phases and 3 in phases and 4 in phases and q1:
        billable_gb = ctx.get('billable_gb', 1)
        total_gb = ctx.get('total_gb', 0)
        non_bill = ctx.get('non_billable_gb', 0)
        avg_daily_gb = ctx.get('avg_daily_gb', 0)
        ttc = ctx.get('total_table_count', 0)
        dc = len(daily_trend) if daily_trend else 30
        L(f"| Volume | # | DataType | BillableGB ({days}d) | Avg/Day (GB) | % | Rules | Current Tier |")
        L("|--------|---|----------|------------------|--------------|---|-------|--------------|")
        for i, row in enumerate(q1, 1):
            gb = sf(row.get('BillableGB'))
            ve = vol_badge(gb)
            pct = round(gb / billable_gb * 100, 1) if billable_gb > 0 else 0
            cr = cr_map.get(row.get('DataType', ''))
            rt = cr['Total'] if cr else 0
            tier = tier_map.get(row.get('DataType', ''), 'Analytics')
            if rt >= 50: rb = f"{E_PURPLE} {rt}"
            elif rt >= 10: rb = f"{E_GREEN} {rt}"
            elif rt >= 3: rb = f"{E_YELLOW} {rt}"
            elif rt >= 1: rb = f"{E_ORANGE} {rt}"
            elif tier in ('Analytics', 'Basic'): rb = f"\u26a0\ufe0f 0"
            else: rb = "0"
            adg = sf(row.get('AvgDailyGB'))
            if adg == 0:
                adg = round(gb / max(dc, 1), 3)
            L(f"| {ve} | {i} | {row.get('DataType','')} | {gb:.3f} | {adg:.3f} | {pct}% | {rb} | {tier} |")
        pct_bill = round(billable_gb / total_gb * 100, 1) if total_gb > 0 else 0
        L("")
        L(f"**Totals (all {ttc} tables, {days}d):** {total_gb:.3f} GB total, {billable_gb:.3f} GB billable ({pct_bill}%), {non_bill:.3f} GB non-billable, {avg_daily_gb:.3f} GB avg/day")
        L("")
        L(f"{E_RED} {GEQ}500 GB {MIDDOT} {E_ORANGE} 100{ENDASH}499 GB {MIDDOT} {E_YELLOW} 10{ENDASH}99 GB {MIDDOT} {E_GREEN} <10 GB  |  {E_PURPLE} 50+ rules {MIDDOT} {E_GREEN} 10-49 {MIDDOT} {E_YELLOW} 3-9 {MIDDOT} {E_ORANGE} 1-2 {MIDDOT} \u26a0\ufe0f 0 (no detections {EMDASH} Analytics/Basic only)")
    else:
        L(f"UNAVAILABLE {EMDASH} requires Phase 1 + Phase 3 + Phase 4 data")

    # ─── DetectionPosture ─────────────────────────────────────────────
    L("")
    L("### DetectionPosture")
    if 1 in phases and 3 in phases and 4 in phases:
        cross_ref = ctx.get('cross_ref', [])
        tw = tz = 0
        for row in q1:
            cr = cr_map.get(row.get('DataType', ''))
            if cr and cr['Total'] >= 1: tw += 1
            else: tz += 1
        top20 = len(q1)
        ar_en = ctx.get('ar_enabled', 0)
        ar_nrt = ctx.get('ar_nrt', 0)
        cd_en = ctx.get('cd_enabled', 0)
        cd_status = ctx.get('cd_status', '')
        ar_dis = ctx.get('ar_disabled', 0)
        cd_dis = ctx.get('cd_disabled', 0)
        sched = ar_en - ar_nrt
        basic_c = sum(1 for t in q10_data if t.get('plan') == 'Basic')
        dl_c = sum(1 for t in q10_data if t.get('plan') in ('Auxiliary', 'auxiliary'))

        L("| Metric | Value |")
        L("|--------|-------|")
        L(f"| \U0001f6e1\ufe0f Enabled Analytic Rules | {ar_en} ({sched} Scheduled, {ar_nrt} NRT) |")
        if cd_status:
            L(f"| \u26a0\ufe0f Enabled Custom Detections | SKIPPED |")
        else:
            L(f"| \U0001f6e1\ufe0f Enabled Custom Detections | {cd_en} |")
        td = ar_dis + cd_dis
        de = E_YELLOW if td > 0 else '\u2705'
        L(f"| {de} Disabled Rules (AR + CD) | {ar_dis} + {cd_dis} |")
        we = E_GREEN if tw >= 15 else (E_YELLOW if tw >= 10 else E_ORANGE)
        L(f"| {we} Tables with Rules (top-20) | {tw} of {top20} |")
        ze = '\u2705' if tz == 0 else (E_YELLOW if tz <= 5 else E_ORANGE)
        L(f"| {ze} Tables with Zero Rules (top-20) | {tz} of {top20} |")
        L(f"| {E_BLUE} Tables on Basic Tier | {basic_c} |")
        L(f"| {E_BLUE} Tables on Data Lake Tier | {dl_c} |")
    else:
        L(f"UNAVAILABLE {EMDASH} requires Phase 1 + Phase 3 + Phase 4 data")

    # ─── AnomalyTable ─────────────────────────────────────────────────
    L("")
    L("### AnomalyTable")
    if 5 in phases:
        a24 = ctx.get('anomaly_24h', [])
        awow = ctx.get('anomaly_wow', [])
        merged = {}
        for a in a24:
            dt = a['DataType']
            sign = '+' if a['Deviation'] > 0 else ''
            merged[dt] = {
                'l24': a['Last24hGB'], 'a7': a['Avg7dGB'],
                'd24': f"{sign}{a['Deviation']}%", 's24': a['Severity'],
                'tw': EMDASH, 'lw': EMDASH, 'wow': EMDASH, 'sw': None
            }
        for a in awow:
            dt = a['DataType']
            sign = '+' if a['WoWChange'] > 0 else ''
            if dt in merged:
                merged[dt]['tw'] = a['ThisWeekGB']
                merged[dt]['lw'] = a['LastWeekGB']
                merged[dt]['wow'] = f"{sign}{a['WoWChange']}%"
                merged[dt]['sw'] = a['Severity']
            else:
                merged[dt] = {
                    'l24': EMDASH, 'a7': EMDASH, 'd24': EMDASH, 's24': None,
                    'tw': a['ThisWeekGB'], 'lw': a['LastWeekGB'],
                    'wow': f"{sign}{a['WoWChange']}%", 'sw': a['Severity']
                }
        if merged:
            L(f"| DataType | Last 24h (GB) | {deep}d Avg (GB) | 24h Deviation | {this_period} (GB) | {last_period} (GB) | {wow_label} | Severity |")
            L("|----------|---------------|-------------|---------------|----------------|----------------|------------|----------|")

            def sort_key(item):
                v = item[1]
                d = v['d24']
                try: d_val = abs(float(d.replace('%', '')))
                except: d_val = 0
                w = v['wow']
                try: w_val = abs(float(w.replace('%', '')))
                except: w_val = 0
                return (-d_val, -w_val)

            for dt, v in sorted(merged.items(), key=sort_key):
                cs = E_ORANGE if v['s24'] == E_ORANGE or v.get('sw') == E_ORANGE else (
                     E_YELLOW if v['s24'] == E_YELLOW or v.get('sw') == E_YELLOW else E_WHITE)
                L(f"| {dt} | {v['l24']} | {v['a7']} | {v['d24']} | {v['tw']} | {v['lw']} | {v['wow']} | {cs} |")
        else:
            L(f"NONE {EMDASH} no anomalies detected")
    else:
        L(f"UNAVAILABLE {EMDASH} requires Phase 5 data")

    # ─── CrossReference ───────────────────────────────────────────────
    L("")
    L("### CrossReference")
    cross_ref = ctx.get('cross_ref', [])
    if (3 in phases) and (4 in phases) and cross_ref:
        L("| Coverage | Table | AR Rules | CD Rules | Total | Key Rule Names |")
        L("|----------|-------|----------|----------|-------|----------------|")
        for r in sorted(cross_ref, key=lambda x: x['Total'], reverse=True):
            t = r['Total']
            b = E_PURPLE if t >= 50 else (E_GREEN if t >= 10 else (E_YELLOW if t >= 3 else E_ORANGE))
            L(f"| {b} | {r['Table']} | {r['AR']} | {r['CD']} | {t} | {r['KeyNames']} |")
    else:
        L(f"UNAVAILABLE {EMDASH} requires Phase 3 + Phase 4 data")

    # ─── SE_Computer ──────────────────────────────────────────────────
    L("")
    L("### SE_Computer")
    q4 = all_results.get('ingestion-q4', [])
    if 2 in phases and q4:
        L(f"| Volume | Computer | Event Count | Est. GB ({deep}d) | % |")
        L("|--------|----------|-------------|---------------|---|")
        for row in q4:
            gb = sf(row.get('EstimatedGB'))
            ve = vol_badge(gb, (20, 10, 5))
            L(f"| {ve} | {row.get('Computer','')} | {fmt_count(row.get('EventCount'))} | {fmt_gb(gb)} | {fmt_pct(row.get('PercentOfTotal'))}% |")
        sc = int(sf(q4[0].get('TotalServers'))) if q4[0].get('TotalServers') else len(q4)
        L("")
        L(f"ServerCount: {sc}")
        L("")
        L(f"{E_RED} {GEQ}20 GB {MIDDOT} {E_ORANGE} 10{ENDASH}19 GB {MIDDOT} {E_YELLOW} 5{ENDASH}9 GB {MIDDOT} {E_GREEN} <5 GB")
    else:
        L("EMPTY")

    # ─── SE_EventID ───────────────────────────────────────────────────
    L("")
    L("### SE_EventID")
    q5 = all_results.get('ingestion-q5', [])
    vr_eid = {str(v['EventID']): v for v in ctx.get('value_ref_eventid', [])}
    if 2 in phases and 4 in phases and q5:
        L(f"| Volume | EventID | Description | Event Count | Est. GB ({deep}d) | % | Rules Referencing |")
        L("|--------|---------|-------------|-------------|---------------|---|---|")
        for row in q5:
            gb = sf(row.get('EstimatedGB'))
            ve = vol_badge(gb, (50, 10, 1))
            eid = str(row.get('EventID', ''))
            desc = EVENT_ID_DESC.get(eid, '')
            vr = vr_eid.get(eid)
            rc = rule_badge_str(0, vr)
            L(f"| {ve} | {eid} | {desc} | {fmt_count(row.get('EventCount'))} | {fmt_gb(gb)} | {fmt_pct(row.get('PercentOfTotal'))}% | {rc} |")
        L("")
        L(f"{E_RED} {GEQ}50 GB {MIDDOT} {E_ORANGE} 10{ENDASH}49 GB {MIDDOT} {E_YELLOW} 1{ENDASH}9 GB {MIDDOT} {E_GREEN} <1 GB  |  {E_PURPLE} 50+ rules {MIDDOT} {E_GREEN} 10-49 {MIDDOT} {E_YELLOW} 3-9 {MIDDOT} {E_ORANGE} 1-2 {MIDDOT} \u26a0\ufe0f 0 rules")
    else:
        L("EMPTY")

    # ─── SyslogHost ───────────────────────────────────────────────────
    L("")
    L("### SyslogHost")
    q6a = all_results.get('ingestion-q6a', [])
    if 2 in phases and q6a:
        L(f"| Source Host | Event Count | Est. GB ({deep}d) | % | Facilities | Severity Levels |")
        L("|-------------|-------------|---------------|---|------------|-----------------|")
        for row in q6a:
            facs = row.get('Facilities', '')
            if isinstance(facs, list): facs = ', '.join(facs)
            sevs = row.get('SeverityLevels', '')
            if isinstance(sevs, list): sevs = ', '.join(sevs)
            L(f"| {row.get('SourceHost','')} | {fmt_count(row.get('EventCount'))} | {fmt_gb(sf(row.get('EstimatedGB')))} | {fmt_pct(row.get('PercentOfTotal'))}% | {facs} | {sevs} |")
    else:
        L("EMPTY")

    # ─── SyslogFacility ──────────────────────────────────────────────
    L("")
    L("### SyslogFacility")
    q6b = all_results.get('ingestion-q6b', [])
    vr_fac = {v['Facility']: v for v in ctx.get('value_ref_facility', [])}
    if 2 in phases and 4 in phases and q6b:
        fac_agg = {}
        for row in q6b:
            f = row.get('Facility', '')
            if f not in fac_agg:
                fac_agg[f] = {'count': 0, 'gb': 0.0}
            fac_agg[f]['count'] += int(sf(row.get('EventCount')))
            fac_agg[f]['gb'] += sf(row.get('EstimatedGB'))
        syslog_total = sum(v['gb'] for v in fac_agg.values())
        fac_sorted = sorted(fac_agg.items(), key=lambda x: x[1]['gb'], reverse=True)
        L(f"| Badge | Facility | Event Count | Est. GB ({deep}d) | % | Rules |")
        L("|-------|----------|-------------|---------------|---|-------|")
        for f, v in fac_sorted:
            badge = FACILITY_BADGES.get(f, '\U0001f4dd')
            if re.match(r'^local[0-7]$', f):
                badge = '\U0001f4e1'
            pct = round(100.0 * v['gb'] / syslog_total, 1) if syslog_total > 0 else 0
            vr = vr_fac.get(f)
            rc = rule_badge_str(0, vr)
            L(f"| {badge} | {f} | {fmt_count(v['count'])} | {fmt_gb(v['gb'])} | {pct}% | {rc} |")
        L("")
        L(f"\U0001f512 Security-critical {MIDDOT} \u2699\ufe0f System operational {MIDDOT} \U0001f4e1 Network/appliance {MIDDOT} \u23f0 Scheduler {MIDDOT} \U0001f4ec Messaging {MIDDOT} \U0001f4dd General/legacy")
    else:
        L("EMPTY")

    # ─── SyslogFacSev ─────────────────────────────────────────────────
    L("")
    L("### SyslogFacSev")
    if 2 in phases and q6b:
        L(f"| Badge | Facility | Severity Level | Event Count | Est. GB ({deep}d) | % |")
        L("|-------|----------|----------------|-------------|---------------|---|")
        for row in q6b:
            f = row.get('Facility', '')
            sev = row.get('SeverityLevel', '')
            fb = FACILITY_BADGES.get(f, '\U0001f4dd')
            if re.match(r'^local[0-7]$', f): fb = '\U0001f4e1'
            se = SEV_EMOJIS.get(sev, E_WHITE)
            L(f"| {fb} | {f} | {se} {sev} | {fmt_count(row.get('EventCount'))} | {fmt_gb(sf(row.get('EstimatedGB')))} | {fmt_pct(row.get('PercentOfTotal'))}% |")
        L("")
        L(f"{E_RED} Critical {MIDDOT} {E_ORANGE} Error {MIDDOT} {E_YELLOW} Warning {MIDDOT} {E_BLUE} Notice {MIDDOT} {E_WHITE} Info {MIDDOT} {E_BLACK} Debug")
    else:
        L("EMPTY")

    # ─── SyslogProcess ────────────────────────────────────────────────
    L("")
    L("### SyslogProcess")
    q6c = all_results.get('ingestion-q6c', [])
    vr_proc = {v['ProcessName']: v for v in ctx.get('value_ref_process', [])}
    if 2 in phases and 4 in phases and q6c:
        q6c_s = sorted(q6c, key=lambda r: sf(r.get('EstimatedGB')), reverse=True)
        L(f"| Facility | Process Name | Event Count | Est. GB ({deep}d) | % | Rules |")
        L("|----------|--------------|-------------|---------------|---|-------|")
        for row in q6c_s:
            proc = row.get('ProcessName', '') or '(empty)'
            vr = vr_proc.get(row.get('ProcessName', ''))
            rc = rule_badge_str(0, vr)
            L(f"| {row.get('Facility','')} | {proc} | {fmt_count(row.get('EventCount'))} | {fmt_gb(sf(row.get('EstimatedGB')))} | {fmt_pct(row.get('PercentOfTotal'))}% | {rc} |")
    else:
        L("EMPTY")

    # ─── CSL_Vendor ───────────────────────────────────────────────────
    L("")
    L("### CSL_Vendor")
    q7 = all_results.get('ingestion-q7', [])
    vr_vend = {v['DeviceVendor']: v for v in ctx.get('value_ref_vendor', [])}
    if 2 in phases and 4 in phases and q7:
        L(f"| Volume | Device Vendor | Device Product | Event Count | Est. GB ({deep}d) | % | Rules |")
        L("|--------|---------------|----------------|-------------|---------------|---|-------|")
        for row in q7:
            gb = sf(row.get('EstimatedGB'))
            ve = vol_badge(gb, (50, 20, 5))
            vr = vr_vend.get(row.get('DeviceVendor', ''))
            rc = rule_badge_str(0, vr)
            L(f"| {ve} | {row.get('DeviceVendor','')} | {row.get('DeviceProduct','')} | {fmt_count(row.get('EventCount'))} | {fmt_gb(gb)} | {fmt_pct(row.get('PercentOfTotal'))}% | {rc} |")
        L("")
        L(f"{E_RED} {GEQ}50 GB {MIDDOT} {E_ORANGE} 20{ENDASH}49 GB {MIDDOT} {E_YELLOW} 5{ENDASH}19 GB {MIDDOT} {E_GREEN} <5 GB")
    else:
        L("EMPTY")

    # ─── CSL_Activity ─────────────────────────────────────────────────
    L("")
    L("### CSL_Activity")
    q8 = all_results.get('ingestion-q8', [])
    vr_act = {v['Activity']: v for v in ctx.get('value_ref_activity', [])}
    if 2 in phases and 4 in phases and q8:
        L(f"| Volume | Activity | Log Severity | Device Action | Event Count | Est. GB ({deep}d) | % | Rules |")
        L("|--------|----------|--------------|---------------|-------------|---------------|---|-------|")
        for row in q8:
            gb = sf(row.get('EstimatedGB'))
            ve = vol_badge(gb, (50, 20, 5))
            vr = vr_act.get(row.get('Activity', ''))
            rc = rule_badge_str(0, vr)
            L(f"| {ve} | {row.get('Activity','')} | {row.get('LogSeverity','')} | {row.get('DeviceAction','')} | {fmt_count(row.get('EventCount'))} | {fmt_gb(gb)} | {fmt_pct(row.get('PercentOfTotal'))}% | {rc} |")
        L("")
        L(f"{E_RED} {GEQ}50 GB {MIDDOT} {E_ORANGE} 20{ENDASH}49 GB {MIDDOT} {E_YELLOW} 5{ENDASH}19 GB {MIDDOT} {E_GREEN} <5 GB")
    else:
        L("EMPTY")

    # ─── Migration ────────────────────────────────────────────────────
    L("")
    L("### Migration")
    migration_rows = ctx.get('migration_rows', [])
    if migration_rows:
        EXCL = '\u2757'
        BOOK = '\U0001f4d5'
        L("")
        L(f"{E_RED} DL candidate (zero rules, eligible) {MIDDOT} {E_ORANGE} Not eligible/unknown {MIDDOT} {E_GREEN} Keep Analytics (has rules) {MIDDOT} {E_PURPLE} Split candidate {MIDDOT} {EXCL} Detection gap {EMDASH} XDR (CD-convertible) or non-XDR (must move back/disable) {MIDDOT} {E_BLUE} Already on DL {MIDDOT} {BOOK} KQL Job output")
        hdr = f"| DataType | {deep}d GB | AR Rules | CD Rules | Total Rules | Tier | DL Eligible | Category |"
        sep = "|----------|-------|----------|----------|-------------|------|-------------|----------|"
        sub_defs = [
            ('Sub-table 1', f"#### Sub-table 1: {E_RED} DL Migration Candidates"),
            ('Sub-table 2', f"#### Sub-table 2: {E_ORANGE} Zero-Rule Tables {EMDASH} Not Eligible or Unknown"),
            ('Sub-table 3', f"#### Sub-table 3: {E_GREEN} Tables with Rules {EMDASH} Keep on Analytics"),
            ('Sub-table 4', f"#### Sub-table 4: {E_BLUE} Already on Data Lake"),
        ]
        for st_key, st_title in sub_defs:
            L("")
            L(st_title)
            L("")
            st_rows = sorted([r for r in migration_rows if r['SubTable'] == st_key],
                           key=lambda r: r['GB7d'], reverse=True)
            if not st_rows:
                L("*No tables in this category.*")
            else:
                L(hdr)
                L(sep)
                for r in st_rows:
                    daily_gb = r['GB7d'] / max(deep, 1)
                    vb = vol_badge(daily_gb, (1.0, 0.1, 0.01))
                    t = r['Total']
                    if t >= 50: rb = E_PURPLE
                    elif t >= 10: rb = E_GREEN
                    elif t >= 3: rb = E_YELLOW
                    elif t >= 1: rb = E_ORANGE
                    elif r['Tier'] == 'Data Lake': rb = ''
                    else: rb = '\u26a0\ufe0f'
                    dl_d = {
                        'Yes': f'\u2705 Yes', 'No': f'\u274c No',
                        'KQL': f'{BOOK} KQL', 'Unknown': f'\u2753 Unknown'
                    }.get(r['DLElig'], f'\u2753 Unknown')
                    L(f"| {r['Table']} | {vb} {r['GB7d']:.2f} | {r['AR']} | {r['CD']} | {rb} {t} | {r['Tier']} | {dl_d} | {r['Category']} |")
    else:
        L("EMPTY")

    # ─── HealthAlerts ─────────────────────────────────────────────────
    L("")
    L("### HealthAlerts")
    FIRE = '\U0001f525'; CHART = '\U0001f4ca'; SLEEP = '\U0001f4a4'
    L("")
    L(f"{FIRE} 100+ alerts {MIDDOT} {CHART} 10{ENDASH}99 alerts {MIDDOT} {SLEEP} 1{ENDASH}9 alerts  |  {E_RED} High {MIDDOT} {E_ORANGE} Medium {MIDDOT} {E_YELLOW} Low {MIDDOT} {E_BLUE} Informational")

    q12 = ctx.get('alert_rules', [])
    if q12:
        total_alerts = sum(int(sf(r.get('AlertCount'))) for r in q12)
        L("")
        L(f"#### Alert-Producing Rules ({days}d)")
        L("| Volume | Rule Name | Alert Count | Severity | Product Component |")
        L("|--------|-----------|-------------|----------|-------------------|")
        for row in sorted(q12, key=lambda r: int(sf(r.get('AlertCount'))), reverse=True):
            ac = int(sf(row.get('AlertCount')))
            vb = FIRE if ac >= 100 else (CHART if ac >= 10 else SLEEP)
            h = int(sf(row.get('HighSev'))); m = int(sf(row.get('MediumSev')))
            l = int(sf(row.get('LowSev'))); ii = int(sf(row.get('InfoSev')))
            sb = f"{E_RED} High" if h > 0 else (f"{E_ORANGE} Medium" if m > 0 else (f"{E_YELLOW} Low" if l > 0 else f"{E_BLUE} Informational"))
            L(f"| {vb} | {row.get('AlertName','')} | {ac} | {sb} | {row.get('ProductComponentName','')} |")
        L("")
        L(f"Total: {total_alerts} alerts from {len(q12)} rules")
    else:
        L("")
        L(f"#### Alert-Producing Rules ({days}d)")
        L(f"No alerts produced in the last {days} days.")

    q11d = ctx.get('failing_rules', [])
    if q11d:
        L("")
        L("#### Failing Rules")
        L("| Rule Name | Kind | Failures | Last Failure | Status |")
        L("|-----------|------|----------|--------------|--------|")
        for row in q11d:
            name = row.get('SentinelResourceName', '')
            kind = 'NRT' if name.startswith('NRT ') else 'Scheduled'
            failures = row.get('FailureCount', '')
            last_f = str(row.get('LastFailure', ''))[:10]
            L(f"| {name} | {kind} | {failures} | {last_f} | {E_ORANGE} Failing |")
    else:
        L("")
        L("#### Failing Rules")
        L("NONE")

    # ─── BenefitSummary + DfSP2Detail ────────────────────────────────
    L("")
    L("### BenefitSummary")
    if 5 in phases and lic:
        L("")
        L(f"| Category | Avg Daily (GB) | Est. {days}-Day (GB) | License Required |")
        L("|----------|---------------|-------------------|------------------|")
        L(f"| DfS P2-Eligible | {lic['dfsp2_daily']:.3f} | {lic['dfsp2_sum']:.3f} | Defender for Servers P2 |")
        L(f"| E5-Eligible | {lic['e5_daily']:.3f} | {lic['e5_sum']:.3f} | M365 E5 / E5 Security |")
        L(f"| **Remaining (truly billable)** | **{lic['rem_daily']:.3f}** | **{lic['rem_sum']:.3f}** | **Paid ingestion** |")

        L("")
        L("### DfSP2Detail")
        L("")
        sc = lic['server_count']
        pool = lic['dfsp2_pool']
        dd = lic['dfsp2_daily']
        util = round((dd / pool) * 100, 1) if pool > 0 else 0
        L(f"Pool calculation: {sc} servers {MULT} 500 MB/day = {pool:.3f} GB/day ([benefit details](https://learn.microsoft.com/en-us/azure/defender-for-cloud/data-ingestion-benefit))")
        L("")
        L("| Metric | Value |")
        L("|--------|-------|")
        L("| Eligible Table | SecurityEvent |")
        L(f"| Detected Server Count | {sc} |")
        L(f"| Pool Size (500 MB/server/day) | {sc} {MULT} 500 MB = **{pool:.3f} GB/day** |")
        L(f"| Actual Eligible Daily Ingestion | **{dd:.3f} GB/day** |")
        L(f"| Pool Utilization | **{util:.1f}%** |")
        L(f"| {days}-Day DfS P2 Deduction | **{lic['dfsp2_sum']:.3f} GB** |")
        if pool > 0:
            L("")
            if dd < pool * 0.5:
                L(f"**Scenario: Pool far exceeds usage.** If DfS P2 is enabled, the pool of {pool:.3f} GB/day far exceeds actual eligible ingestion of {dd:.3f} GB/day {EMDASH} significant headroom exists. Consider increasing SecurityEvent logging levels (e.g., collecting \"All Events\" instead of \"Common\" or \"Minimal\") to broaden detection coverage at no additional ingestion cost.")
            elif dd <= pool:
                L(f"**Scenario: Pool covers usage.** If DfS P2 is enabled, the pool of {pool:.3f} GB/day covers the current eligible ingestion of {dd:.3f} GB/day. Monitor growth {EMDASH} if SecurityEvent volume approaches the pool ceiling, evaluate which EventIDs drive the increase (see {SECT}3a).")
            else:
                overage = round(dd - pool, 3)
                L(f"**Scenario: Usage exceeds pool.** If DfS P2 is enabled, eligible ingestion ({dd:.3f} GB/day) exceeds the pool ({pool:.3f} GB/day). The overage of ~{overage:.3f} GB/day is billed at standard Analytics rates. Review {SECT}3a EventID breakdown for volume reduction opportunities.")
    else:
        L("NONE")
        L("")
        L("### DfSP2Detail")
        L("NONE")

    # ─── E5Tables ─────────────────────────────────────────────────────
    L("")
    L("### E5Tables")
    e5_tables = ctx.get('e5_tables', [])
    if 5 in phases and e5_tables:
        e5_sorted = sorted(e5_tables, key=lambda r: sf(r.get('VolumeGB')), reverse=True)
        L("")
        L(f"| Table | Volume ({days}d GB) | Tier |")
        L("|-------|----------------|------|")
        e5_total = 0.0
        for row in e5_sorted:
            vol = sf(row.get('VolumeGB'))
            e5_total += vol
            tier = tier_map.get(row.get('DataType', ''), 'Analytics')
            L(f"| {row.get('DataType','')} | {vol:.3f} | {tier} |")
        L(f"| **Total ({len(e5_sorted)} tables)** | **{e5_total:.3f}** | |")

        if lic:
            e5d = lic['e5_daily']
            e5d_mb = e5d * 1024
            break_even = -(-int(e5d_mb) // 5) if e5d_mb > 0 else 0  # ceil division
            L("")
            L(f"**Break-even:** {e5d:.3f} GB/day ({e5d_mb:.1f} MB/day) {EMDASH} requires **{break_even} E5 licenses** to fully cover (at 5 MB/license/day)")
            e5_agg_sum = lic['e5_sum']
            if abs(e5_total - e5_agg_sum) > 0.01:
                L(f"*Per-table sum ({e5_total:.3f} GB) differs from aggregate ({e5_agg_sum:.3f} GB) due to rounding in daily averaging.*")
    else:
        L("NONE")

    # ─── QueryTable ───────────────────────────────────────────────────
    L("")
    L("### QueryTable")
    L("""| Phase | Query ID | Description |
|-------|----------|-------------|
| 1 | Q1 | Usage by DataType |
| 1 | Q2 | Daily ingestion trend |
| 1 | Q3 | Workspace aggregate metrics |
| 2 | Q4 | SecurityEvent by Computer |
| 2 | Q5 | SecurityEvent by EventID |
| 2 | Q6a | Syslog by source host |
| 2 | Q6b | Syslog by Facility\u00d7Severity |
| 2 | Q6c | Syslog by ProcessName |
| 2 | Q7 | CommonSecurityLog by vendor |
| 2 | Q8 | CommonSecurityLog by activity |
| 3 | Q9 | AR inventory (REST API) |
| 3 | Q9b | CD inventory (Graph API) |
| 3 | Q10 | Table tier (Azure CLI) |
| 3 | Q10b | Per-tier volume summary |
| 4 | Q11 | SentinelHealth overview |
| 4 | Q11d | Failing rule details |
| 4 | Q12 | Alert-producing rules |
| 4 | Q13 | Active tables (for CrossRef) |
| 5 | Q14 | 24h anomaly detection |
| 5 | Q15 | Week-over-week changes |
| 5 | Q16 | Migration candidate volumes |
| 5 | Q17 | License benefit analysis |
| 5 | Q17b | E5 per-table breakdown |""")

    # ─── Footer ───────────────────────────────────────────────────────
    L("")
    L("### Footer")
    L(f"*Report generated: {datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')} | Skill: sentinel-ingestion-report v2 | Mode: {days}-day markdown*")

    return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════
# SCRATCHPAD ASSEMBLY (Turn 4 replaces this stub)
# ═══════════════════════════════════════════════════════════════

def build_phase_blocks(ctx, all_results, phases, days, deep, labels):
    """Build PHASE_1..PHASE_5 scratchpad sections."""
    lines = []
    L = lines.append
    EMDASH = '\u2014'

    # ── PHASE_1 — Usage Summary ──────────────────────────────────────
    if 1 in phases:
        L("")
        L("## PHASE_1 \u2014 Usage Summary")
        L("")
        L("### Metrics")
        total_gb = ctx.get('total_gb', 0)
        billable_gb = ctx.get('billable_gb', 0)
        non_bill = ctx.get('non_billable_gb', 0)
        avg_daily = ctx.get('avg_daily_gb', 0)
        peak = ctx.get('peak')
        min_d = ctx.get('min_day')
        L(f"TotalGB: {total_gb:.3f}")
        L(f"BillableGB: {billable_gb:.3f}")
        L(f"NonBillableGB: {non_bill:.3f}")
        L(f"AvgDailyGB: {avg_daily:.3f}")
        if peak:
            L(f"PeakGB: {peak['gb']:.3f}")
            L(f"PeakDate: {peak['date'].strftime('%Y-%m-%d')}")
            L(f"PeakDay: {peak['date'].strftime('%a')}")
        if min_d:
            L(f"MinGB: {min_d['gb']:.3f}")
            L(f"MinDate: {min_d['date'].strftime('%Y-%m-%d')}")
            L(f"MinDay: {min_d['date'].strftime('%a')}")
        L(f"BillableTables: {ctx.get('billable_table_count', 0)}")
        L(f"TotalTables: {ctx.get('total_table_count', 0)}")

        # Tables section from Q1
        q1 = ctx.get('q1_data', [])
        L("")
        L("### Tables")
        L("<!-- DataType | BillableGB | Pct | Solution -->")
        for row in q1:
            gb = sf(row.get('BillableGB'))
            pct = round(100.0 * gb / billable_gb, 1) if billable_gb > 0 else 0
            sol = row.get('Solution', '')
            L(f"{row.get('DataType','')} | {gb:.3f} | {pct:.1f} | {sol}")

        # DailyTrend from Q2
        daily = ctx.get('daily_trend', [])
        L("")
        L("### DailyTrend")
        L("<!-- Date | GB -->")
        for d in daily:
            L(f"{d['date'].strftime('%Y-%m-%d')} | {d['gb']:.3f}")

    # ── PHASE_2 — Deep Dives ────────────────────────────────────────
    if 2 in phases:
        L("")
        L("## PHASE_2 \u2014 Deep Dives")

        # CSL_Vendor raw
        q7 = all_results.get('ingestion-q7', [])
        L("")
        L("### CSL_Vendor")
        if q7:
            L("<!-- DeviceVendor | DeviceProduct | EventCount | EstGB | Pct -->")
            for row in q7:
                gb = sf(row.get('EstimatedGB'))
                est = '< 0.01' if 0 < gb < 0.01 else f"{gb:.1f}"
                pv = sf(row.get('PercentOfTotal'))
                pct = '< 0.1' if pv != pv or pv == 0 else f"{pv:.1f}"
                L(f"{row.get('DeviceVendor','')} | {row.get('DeviceProduct','')} | {row.get('EventCount','')} | {est} | {pct}")
        else:
            L("EMPTY")

        # CSL_Activity raw
        q8 = all_results.get('ingestion-q8', [])
        L("")
        L("### CSL_Activity")
        if q8:
            L("<!-- Activity | LogSeverity | DeviceAction | EventCount | EstGB | Pct -->")
            for row in q8:
                gb = sf(row.get('EstimatedGB'))
                est = '< 0.01' if 0 < gb < 0.01 else f"{gb:.1f}"
                pv = sf(row.get('PercentOfTotal'))
                pct = '< 0.1' if pv != pv or pv == 0 else f"{pv:.1f}"
                L(f"{row.get('Activity','')} | {row.get('LogSeverity','')} | {row.get('DeviceAction','')} | {row.get('EventCount','')} | {est} | {pct}")
        else:
            L("EMPTY")

    # ── PHASE_3 — Rules & Tiers ─────────────────────────────────────
    if 3 in phases:
        L("")
        L("## PHASE_3 \u2014 Rules & Tiers")
        L("")
        L("### RuleInventory")
        L(f"AR_Total: {ctx.get('ar_total', 0)}")
        L(f"AR_Enabled: {ctx.get('ar_enabled', 0)}")
        L(f"AR_Disabled: {ctx.get('ar_disabled', 0)}")
        L(f"AR_Scheduled: {ctx.get('ar_scheduled', 0)}")
        L(f"AR_NRT: {ctx.get('ar_nrt', 0)}")
        L(f"CD_Total: {ctx.get('cd_total', 0)}")
        L(f"CD_Enabled: {ctx.get('cd_enabled', 0)}")
        L(f"CD_Disabled: {ctx.get('cd_disabled', 0)}")
        L(f"Combined_Enabled: {ctx.get('ar_enabled', 0) + ctx.get('cd_enabled', 0)}")
        cd_status = ctx.get('cd_status', '')
        if cd_status:
            L(f"CD_Status: SKIPPED ({cd_status})")

        # Tiers
        q10_data = ctx.get('q10_data', [])
        L("")
        L("### Tiers")
        non_analytics = [t for t in q10_data if t.get('plan') in ('Auxiliary', 'auxiliary', 'Basic', 'basic')]
        if non_analytics:
            L("<!-- Table | Plan -->")
            for t in non_analytics:
                plan = 'Data Lake' if t.get('plan') in ('Auxiliary', 'auxiliary') else t.get('plan', '')
                L(f"{t['name']} | {plan}")
        else:
            L("<!-- All tables on Analytics tier -->")

        # TierSummary
        q10b = all_results.get('ingestion-q10b', [])
        L("")
        L("### TierSummary")
        if q10b and isinstance(q10b, list) and q10b:
            L("<!-- Tier | TotalGB | BillableGB | TableCount | PercentOfTotal -->")
            for row in q10b:
                L(f"{row.get('Tier','')} | {sf(row.get('TotalGB')):.3f} | {sf(row.get('BillableGB')):.3f} | {int(sf(row.get('TableCount')))} | {sf(row.get('PercentOfTotal')):.1f}")
        else:
            L("EMPTY")

    # ── PHASE_4 — Detection Coverage ────────────────────────────────
    if 4 in phases:
        L("")
        L("## PHASE_4 \u2014 Detection Coverage")

        # CrossRef
        cross_ref = ctx.get('cross_ref', [])
        L("")
        L("### CrossRef")
        L("<!-- Table | AR | CD | Total -->")
        if cross_ref:
            for r in sorted(cross_ref, key=lambda x: x['Total'], reverse=True):
                L(f"{r['Table']} | {r['AR']} | {r['CD']} | {r['Total']}")
        else:
            L(f"EMPTY {EMDASH} allRules not available (Phase 3 required)")

        # ZeroRuleTables
        zero = ctx.get('zero_rule_tables', [])
        L("")
        L("### ZeroRuleTables")
        if zero:
            for t in zero:
                L(t)
        else:
            L("NONE")

        # DetectionGaps
        gaps = ctx.get('detection_gaps', [])
        L("")
        L("### DetectionGaps")
        L("<!-- Tables on DL/Basic with rules -->")
        if gaps:
            for g in gaps:
                L(f"{g['Table']} | {g['Tier']} | {g['Rules']} rules")
        else:
            L("NONE")

        # ASIM
        asim = ctx.get('asim_patterns', [])
        L("")
        L("### ASIM")
        L("<!-- Pattern | Count | RuleNames -->")
        if asim:
            for a in asim:
                L(f"{a['Schemas']} | {a['Source']} | {a['Rule']}")
        else:
            L("NONE")

        # ValueRef_Activity
        vr_act = ctx.get('value_ref_activity', [])
        L("")
        L("### ValueRef_Activity")
        if vr_act:
            L("<!-- Activity | AR | CD | Total | RuleNames -->")
            for v in vr_act:
                kn = v.get('KeyNames', '') or EMDASH
                L(f"{v.get('Activity','')} | {v['AR']} | {v['CD']} | {v['Total']} | {kn}")
        else:
            L("EMPTY")

        # ValueRef_Vendor
        vr_vend = ctx.get('value_ref_vendor', [])
        L("")
        L("### ValueRef_Vendor")
        if vr_vend:
            L("<!-- DeviceVendor | AR | CD | Total | RuleNames -->")
            for v in vr_vend:
                kn = v.get('KeyNames', '') or EMDASH
                L(f"{v.get('DeviceVendor','')} | {v['AR']} | {v['CD']} | {v['Total']} | {kn}")
        else:
            L("EMPTY")

        # Health
        health = ctx.get('health', {})
        L("")
        L("### Health")
        if health.get('total_rules', 0) > 0:
            L(f"TotalRulesInHealth: {health['total_rules']}")
            L(f"OverallSuccessRate: {health['overall_success_rate']}%")
            L(f"FailingRuleCount: {health['failing_count']}")
        else:
            L("Status: UNAVAILABLE")

        # CrossValidation
        cv = ctx.get('cross_validation', {})
        L("")
        L("### CrossValidation")
        if cv.get('q11_distinct', 0) > 0:
            L(f"Q11_DistinctRules: {cv['q11_distinct']}")
            L(f"Q9_AR_Enabled: {cv['q9_ar_enabled']}")
            L(f"Gap: {cv['gap']}%")
        else:
            L(f"Q11_DistinctRules: N/A")
            L(f"Q9_AR_Enabled: {ctx.get('ar_enabled', 0)}")
            L(f"Gap: N/A")

    # ── PHASE_5 — Anomalies & Cost ──────────────────────────────────
    if 5 in phases:
        L("")
        L("## PHASE_5 \u2014 Anomalies & Cost")

        # Anomaly24h
        a24 = ctx.get('anomaly_24h', [])
        L("")
        L("### Anomaly24h")
        L("<!-- DataType | Last24hGB | Avg7dGB | Deviation% | Severity -->")
        if a24:
            for a in a24:
                sign = '+' if a['Deviation'] > 0 else ''
                L(f"{a['DataType']} | {a['Last24hGB']} | {a['Avg7dGB']} | {sign}{a['Deviation']} | {a['Severity']}")
        else:
            L(f"NONE {EMDASH} no tables deviate >50% with \u22650.01 GB volume")

        # AnomalyWoW
        awow = ctx.get('anomaly_wow', [])
        L("")
        L("### AnomalyWoW")
        L("<!-- DataType | ThisWeekGB | LastWeekGB | WoWChange% | Severity -->")
        if awow:
            for a in awow:
                sign = '+' if a['WoWChange'] > 0 else ''
                L(f"{a['DataType']} | {a['ThisWeekGB']} | {a['LastWeekGB']} | {sign}{a['WoWChange']} | {a['Severity']}")
        else:
            L(f"NONE {EMDASH} no tables with >20% WoW change or >0.1 GB")

        # DL Classification
        dl_class = ctx.get('dl_class', {})
        L("")
        L("### DL_Script_Output")
        L("<!-- TableName | DL_Eligible -->")
        for t in sorted(dl_class.keys()):
            L(f"{t} | {dl_class[t]}")

        # LicenseBenefits
        lic = ctx.get('license')
        L("")
        L("### LicenseBenefits")
        if lic:
            L(f"DfSP2_DailyGB: {lic['dfsp2_daily']}")
            L(f"E5_DailyGB: {lic['e5_daily']}")
            L(f"Remaining_DailyGB: {lic['rem_daily']}")
            L(f"DfSP2_{days}dGB: {lic['dfsp2_sum']}")
            L(f"E5_{days}dGB: {lic['e5_sum']}")
            L(f"Remaining_{days}dGB: {lic['rem_sum']}")
            L(f"ServerCount: {lic['server_count']}")
            L(f"DfSP2_PoolGB: {lic['dfsp2_pool']}")
        else:
            L("Status: UNAVAILABLE")

    return '\n'.join(lines)


def build_scratchpad(ctx, all_results, phases, days, deep, wow, labels, config, queries, elapsed):
    """Assemble the full scratchpad markdown file."""
    if isinstance(labels, tuple):
        labels = {
            'this_period': labels[0] if len(labels) > 0 else '',
            'last_period': labels[1] if len(labels) > 1 else '',
            'wow_change': labels[2] if len(labels) > 2 else '',
            'period': f"{labels[0]} vs {labels[1]}" if len(labels) > 1 else (labels[0] if labels else ''),
        }
    daily = ctx.get('daily_trend', [])
    ws_name = ctx.get('workspace_name', config.get('workspace_name', ''))
    ws_id = config.get('workspace_id', '')
    period_label = labels.get('period', '')

    # ReportPeriod: excludes partial report-generation day
    gen_date = datetime.now().strftime('%Y-%m-%d')
    if daily:
        last_day = daily[-1]
        if last_day['date'].strftime('%Y-%m-%d') == gen_date and len(daily) > 1:
            end_day = daily[-2]
            dc = len(daily) - 1
            report_period = f"{daily[0]['date'].strftime('%Y-%m-%d')} to {end_day['date'].strftime('%Y-%m-%d')} ({dc} days)"
        else:
            dc = len(daily)
            report_period = f"{daily[0]['date'].strftime('%Y-%m-%d')} to {last_day['date'].strftime('%Y-%m-%d')} ({dc} days)"
    else:
        report_period = 'Unknown'

    phase_blocks = build_phase_blocks(ctx, all_results, phases, days, deep, labels)
    prerendered = build_prerendered(ctx, all_results, phases, days, deep, wow, labels)

    parts = [
        f"# SCRATCHPAD \u2014 Sentinel Ingestion Report",
        f"<!-- Auto-generated by invoke_ingestion_scan.py. DO NOT edit manually. -->",
        "",
        "## META",
        f"Workspace: {ws_name}",
        f"WorkspaceId: {ws_id}",
        f"Period: {period_label}",
        f"ReportPeriod: {report_period}",
        f"Days: {days}",
        f"DeepDiveDays: {deep}",
        f"Generated: {datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"Tool: AzMonitor",
        f"QueryCount: {len(queries)}",
        f"ExecutionTime: {elapsed}s",
        f"Phases: {','.join(str(p) for p in sorted(phases))}",
        phase_blocks,
        "",
        "## PRERENDERED",
        "<!-- Copy these blocks VERBATIM into the report. Do NOT modify content. -->",
        prerendered,
    ]
    return '\n'.join(parts)


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(description='Sentinel Ingestion Report \u2014 Data Gathering Pipeline')
    p.add_argument('--days', type=int, default=30, help='Primary window (1,7,30,60,90)')
    p.add_argument('--phase', type=int, default=0, help='Specific phase (1-5) or 0=all')
    p.add_argument('--output-dir', type=str, default='', help='Output directory (default: temp/)')
    p.add_argument('--workspace-id', type=str, default='')
    p.add_argument('--subscription-id', type=str, default='')
    p.add_argument('--resource-group', type=str, default='')
    p.add_argument('--workspace-name', type=str, default='')
    p.add_argument('--config', type=str, default='')
    p.add_argument('--synthetic-data-dir', type=str, default='', help='Load pre-built JSON for testing')
    p.add_argument('--export-data-dir', type=str, default='', help='Export raw results to dir')
    p.add_argument('--prefetch-dir', default=None, help='Directory with prefetched ingestion-q1.json..ingestion-q17b.json files')
    return p.parse_args()


def main():
    args = parse_args()
    prefetch_dir = Path(args.prefetch_dir) if args.prefetch_dir else None
    config = resolve_config(args)
    days = args.days
    deep, wow, labels = compute_windows(days)
    phases = list(range(1, 6)) if args.phase == 0 else [args.phase]
    script_dir = Path(__file__).resolve().parent
    queries = load_queries(script_dir / 'queries.yaml')
    ws_name = config['workspace_name'] or config['workspace_id'][:8]

    print(f"\n{'='*57}")
    print(f"  Sentinel Ingestion Scan")
    print(f"{'='*57}")
    print(f"  Workspace: {ws_name}")
    print(f"  Days: {days} (deep-dive: {deep}, comparison: {wow})")
    print(f"  Phases: {', '.join(str(p) for p in phases)}")
    print(f"  Queries: {len(queries)}\n")

    all_results = {}
    t0 = time.time()
    all_deferred = []

    if prefetch_dir:
        print(f"\U0001f4c2 Prefetch mode \u2014 reading data from {prefetch_dir}")
        for q in queries:
            fp = prefetch_dir / f"{q['id']}.json"
            if fp.exists():
                with open(fp, 'r', encoding='utf-8') as f:
                    all_results[q['id']] = json.load(f)
                cnt = len(all_results[q['id']]) if isinstance(all_results[q['id']], list) else 'dict'
                print(f"   \u2705 {q['id']}: {cnt} (prefetch)")
            else:
                print(f"   \u26a0\ufe0f  {q['id']}: prefetch file not found")
    elif args.synthetic_data_dir:
        syn = Path(args.synthetic_data_dir)
        print(f"\U0001f4c2 Loading synthetic data from {syn}")
        for q in queries:
            fp = syn / f"{q['id']}.json"
            if fp.exists():
                with open(fp, 'r', encoding='utf-8') as f:
                    all_results[q['id']] = json.load(f)
                print(f"   \u2705 {q['id']}: loaded")
    else:
        for phase in phases:
            phase_qs = [q for q in queries if q.get('phase') == phase]
            print(f"\n\U0001f4e1 Phase {phase}: {len(phase_qs)} queries")
            deferred = execute_phase_queries(phase_qs, config, all_results, days, deep, wow)
            all_deferred.extend(deferred)

    if args.export_data_dir:
        exp = Path(args.export_data_dir)
        exp.mkdir(parents=True, exist_ok=True)
        for qid, data in all_results.items():
            with open(exp / f"{qid}.json", 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        print(f"\n\U0001f4c1 Exported {len(all_results)} files to {exp}")

    elapsed = round(time.time() - t0, 1)

    # Post-processing
    ctx = {'workspace_name': ws_name}
    if 1 in phases:
        post_process_phase1(all_results, ctx, days)
    if 2 in phases:
        post_process_phase2(all_results, ctx, deep)
    if 3 in phases:
        post_process_phase3(all_results, ctx, config, days, deep, wow, all_deferred)
    if 4 in phases:
        post_process_phase4(all_results, ctx, deep)
    if 5 in phases:
        post_process_phase5(all_results, ctx, days, deep)

    # Build scratchpad
    prerendered = build_prerendered(ctx, all_results, phases, days, deep, wow, labels)
    phase_blocks = build_phase_blocks(ctx, all_results, phases, days, deep, labels)
    scratchpad = build_scratchpad(ctx, all_results, phases, days, deep, wow, labels, config, queries, elapsed)

    # Write
    out_dir = Path(args.output_dir) if args.output_dir else Path('temp')
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    sp_path = out_dir / f'ingest_scratch_{ts}.md'
    sp_path.write_text(scratchpad, encoding='utf-8')

    print(f"\n{'='*57}")
    print(f"  \u2705 Scratchpad written successfully")
    print(f"{'='*57}")
    print(f"  \U0001f4c4 Path: {sp_path}")
    print(f"  \U0001f4cf Size: {round(sp_path.stat().st_size / 1024, 1)} KB")
    print(f"  \u23f1\ufe0f  Total time: {elapsed}s")
    print(f"  \U0001f4ca Phases: {', '.join(str(p) for p in phases)}\n")


if __name__ == '__main__':
    main()
