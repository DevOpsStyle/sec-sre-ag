# KQL Enrichment Queries — Identity Posture

These queries run against the **Log Analytics workspace** to enrich Graph API data
with on-prem AD context, sign-in activity, and MDI intelligence.

## How the agent uses this file

1. Run each query via the `monitor-client_monitor_workspace_log_query` tool.
2. Save the `results` array as a JSON file in `output/identity-posture/`.
3. Use the exact filename listed for each query — `analyze-identity-posture.py` expects them.

> **Table availability:** `IdentityInfo` and `IdentityLogonEvents` require the
> Defender XDR data connector in Sentinel. `SigninLogs` and
> `AADNonInteractiveUserSignInLogs` require Entra ID diagnostic settings.
> If a table does not exist the query will fail — skip it and note the gap.

---

## KQL-LA1: AD UAC Flags (Password Policy)

**Purpose:** Count on-prem AD accounts with PasswordNeverExpires / PasswordNotRequired.
**Table:** `IdentityInfo`
**Save as:** `kql_uac_flags_<ts>.json`

```kql
IdentityInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| where isnotnull(UserAccountControl)
| extend PwdNeverExpires = array_index_of(UserAccountControl, "PasswordNeverExpires") != -1,
         PwdNotRequired = array_index_of(UserAccountControl, "PasswordNotRequired") != -1
| summarize
    WithUACData = count(),
    PwdNeverExpiresCount = countif(PwdNeverExpires),
    PwdNotRequiredCount = countif(PwdNotRequired)
```

---

## KQL-LA2: MDI Tags Analysis

**Purpose:** Find accounts tagged Sensitive / Honeytoken by Defender for Identity.
**Table:** `IdentityInfo`
**Save as:** `kql_mdi_tags_<ts>.json`

```kql
IdentityInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| where isnotempty(tostring(Tags)) and tostring(Tags) != "[]"
| mv-expand Tag = parse_json(Tags)
| extend TagName = tostring(Tag)
| summarize
    AccountCount = dcount(AccountObjectId),
    Accounts = make_set(AccountUPN, 10)
    by TagName
| order by AccountCount desc
```

---

## KQL-LA3: IdentityInfo Risk & Blast Radius

**Purpose:** Cross-reference risk levels from IdentityInfo with Graph API risk data.
**Table:** `IdentityInfo`
**Save as:** `kql_identity_risk_<ts>.json`

```kql
IdentityInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| where isnotempty(RiskLevel) and RiskLevel !in ("", "None", "none")
| summarize
    Count = count(),
    EnabledCount = countif(IsAccountEnabled == true)
    by RiskLevel, RiskState
| order by Count desc
```

---

## KQL-LA4: Built-In & Infrastructure Account Audit

**Purpose:** Audit krbtgt, Administrator, Guest, MSOL_*, AAD_*, ADSync* accounts.
**Table:** `IdentityInfo`
**Save as:** `kql_builtin_accounts_<ts>.json`

> **Note:** `Tags` is stored as `string` in IdentityInfo, not `dynamic`.
> `UserAccountControl` is `dynamic` but must also be wrapped in `todynamic()` when
> used inside `iff()` branches to satisfy KQL compile-time type validation.
> Without `todynamic()`, `array_index_of()` fails with `SEM0218`.

```kql
IdentityInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| where isnotempty(AccountName)
| where tolower(AccountName) in ("krbtgt", "administrator", "guest", "admin")
    or tolower(AccountName) startswith "msol_"
    or tolower(AccountName) startswith "aad_"
    or tolower(AccountName) startswith "adsync"
| extend PwdNeverExpires = iff(isnotnull(UserAccountControl),
    array_index_of(todynamic(UserAccountControl), "PasswordNeverExpires") != -1, bool(null)),
         PwdNotRequired = iff(isnotnull(UserAccountControl),
    array_index_of(todynamic(UserAccountControl), "PasswordNotRequired") != -1, bool(null))
| extend Sensitive = iff(isnotnull(Tags), array_index_of(todynamic(Tags), "Sensitive") != -1, false)
| project AccountName, AccountDomain, AccountDisplayName, IsAccountEnabled,
    PwdNeverExpires, PwdNotRequired, Sensitive, RiskLevel
| order by AccountName asc
```

---

## KQL-LA5: SigninLogs — Stale Account Detail (90d)

**Purpose:** Per-user last sign-in timestamps from interactive + non-interactive logs.
**Table:** `SigninLogs`, `AADNonInteractiveUserSignInLogs`
**Save as:** `kql_stale_detail_<ts>.json`

```kql
let InteractiveSignIns = SigninLogs
| where TimeGenerated > ago(90d)
| summarize LastInteractiveSignIn = max(TimeGenerated) by UserPrincipalName;
let NonInteractiveSignIns = AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(90d)
| summarize LastNonInteractiveSignIn = max(TimeGenerated) by UserPrincipalName;
InteractiveSignIns
| join kind=fullouter (NonInteractiveSignIns) on UserPrincipalName
| extend UPN = coalesce(UserPrincipalName, UserPrincipalName1)
| extend LastActivity = max_of(
    coalesce(LastInteractiveSignIn, datetime(1970-01-01)),
    coalesce(LastNonInteractiveSignIn, datetime(1970-01-01)))
| project UPN, LastInteractiveSignIn, LastNonInteractiveSignIn, LastActivity
| order by LastActivity asc
```

---

## KQL-LA5b: Stale Account Summary (Aggregated)

**Purpose:** Aggregated sign-in activity buckets for the score computation.
**Table:** `SigninLogs`, `AADNonInteractiveUserSignInLogs`
**Save as:** `kql_stale_summary_<ts>.json`

```kql
let lastActivity = SigninLogs
| where TimeGenerated > ago(90d)
| summarize LastSignIn = max(TimeGenerated) by UserPrincipalName;
let nonInteractive = AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(90d)
| summarize LastNonInteractive = max(TimeGenerated) by UserPrincipalName;
lastActivity
| join kind=fullouter (nonInteractive) on UserPrincipalName
| extend UPN = coalesce(UserPrincipalName, UserPrincipalName1)
| extend LastAny = max_of(
    coalesce(LastSignIn, datetime(1970-01-01)),
    coalesce(LastNonInteractive, datetime(1970-01-01)))
| summarize
    TotalWithActivity = count(),
    Active30d = countif(LastAny > ago(30d)),
    Active60d = countif(LastAny > ago(60d) and LastAny <= ago(30d)),
    Active90d = countif(LastAny > ago(90d) and LastAny <= ago(60d)),
    Stale90d = countif(LastAny <= ago(90d))
```

---

## KQL-LA7: Service Account Detection

**Purpose:** Find accounts tagged as ServiceAccount or with service-account naming patterns.
**Table:** `IdentityInfo`
**Save as:** `kql_service_accounts_<ts>.json`

```kql
IdentityInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| where Tags has "ServiceAccount"
    or tolower(AccountName) startswith "svc"
    or tolower(AccountName) startswith "sa_"
    or tolower(AccountName) startswith "service"
| project AccountName, AccountDomain, AccountDisplayName, IsAccountEnabled,
    Tags, RiskLevel, AccountUPN
| order by AccountName
```

---

## KQL-LA8: Cross-Domain Summary

**Purpose:** Overview of all accounts in IdentityInfo — totals, risk, domains.
**Table:** `IdentityInfo`
**Save as:** `kql_cross_domain_<ts>.json`

```kql
IdentityInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| summarize
    TotalAccounts = count(),
    EnabledAccounts = countif(IsAccountEnabled == true),
    DisabledAccounts = countif(IsAccountEnabled == false),
    WithRiskLevel = countif(isnotempty(RiskLevel) and RiskLevel !in ("", "None", "none")),
    HighRisk = countif(RiskLevel == "High"),
    Domains = make_set(AccountDomain, 20)
```

---

## Quick-reference: Agent save commands

After each KQL query, the agent saves results to JSON:

```python
# Pattern the agent follows after each KQL tool call:
import json
results = <tool_response>["results"]  # from monitor tool
with open(f"output/identity-posture/kql_<name>_{ts}.json", "w") as f:
    json.dump({"results": results}, f, indent=2)
```

The `analyze-identity-posture.py` script reads files matching `kql_<name>_*.json`
and uses the `results` key.
