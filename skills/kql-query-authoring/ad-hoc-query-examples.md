# Ad-Hoc Query Examples — Canonical Patterns

> **Usage:** Reference these battle-tested patterns before writing KQL from scratch. They encode known pitfalls and correct join/filter strategies.

---

## SecurityAlert.Status Is Immutable — Always Join SecurityIncident

**⚠️ CRITICAL:** The `Status` field on the `SecurityAlert` table is set to `"New"` at creation time and **never changes**. It does NOT reflect whether the alert has been investigated, closed, or classified.

To get the **actual investigation status**, you MUST join with `SecurityIncident`:

```kql
let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has '<ENTITY>'
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;
SecurityIncident
| where CreatedTime between (start .. end)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| summarize Title = any(Title), Severity = any(Severity), Status = any(Status),
    Classification = any(Classification), CreatedTime = any(CreatedTime)
    by ProviderIncidentId
| extend PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId, "?tid=<TENANT_ID>")
| order by CreatedTime desc
```

> 🟢 **Run in:** Sentinel Logs (Azure Portal → Microsoft Sentinel → Logs)

**Key points:**
- Replace `<ENTITY>` with the actual entity value (UPN, IP, hostname, etc.)
- Replace `<TENANT_ID>` with your tenant ID for portal URLs
- Use `CreatedTime` (not `TimeGenerated`) for incident time-windowed queries
- `ProviderIncidentId` maps to the Defender XDR portal incident ID

| Field | Source | Meaning |
|-------|--------|----------|
| `SecurityAlert.Status` | Alert table | **Immutable creation status** — always "New" |
| `SecurityIncident.Status` | Incident table | **Real status** — New/Active/Closed |
| `SecurityIncident.Classification` | Incident table | **Closure reason** — TruePositive/FalsePositive/BenignPositive |

---

## AuditLogs — Dynamic Field Handling

```kql
// Extract actor UPN (Data Lake — parse_json wrapper required)
AuditLogs
| where TimeGenerated > ago(7d)
| where tostring(TargetResources) has "MyApp"
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend TargetName = tostring(parse_json(tostring(TargetResources[0])).displayName)
| project TimeGenerated, Actor, OperationName, TargetName, Result
```

> 🟢 **Run in:** Sentinel Logs (Azure Portal → Microsoft Sentinel → Logs)

**Key points:**
- In Data Lake, `InitiatedBy` and `TargetResources` may be **string-typed** — always use `parse_json(tostring(...))` pattern
- In Advanced Hunting, these are native dynamic — dot-notation works directly
- Use `tostring(TargetResources) has "keyword"` as a pre-filter before `parse_json` for performance

---

## Sign-In Analysis — Platform-Appropriate Queries

### For Advanced Hunting (≤30d) — EntraIdSignInEvents

```kql
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "user@domain.com"
| where ErrorCode == 0  // Successful sign-ins
| summarize
    SignInCount = count(),
    DistinctIPs = dcount(IPAddress),
    Countries = make_set(Country),
    Applications = make_set(Application)
    by AccountUpn
```

> 🔵 **Run in:** Advanced Hunting (`https://security.microsoft.com` → Hunting → Advanced Hunting)

### For Sentinel Data Lake (>30d) — SigninLogs + AADNonInteractiveUserSignInLogs

```kql
let start = ago(90d);
let end = now();
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ "user@domain.com"
| where ResultType == "0"  // Successful sign-ins (string, not int!)
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| summarize
    SignInCount = count(),
    DistinctIPs = dcount(IPAddress),
    Countries = make_set(Country),
    Applications = make_set(AppDisplayName)
    by UserPrincipalName
```

> 🟢 **Run in:** Sentinel Logs (Azure Portal → Microsoft Sentinel → Logs)

**Key column mapping between the two:**

| EntraIdSignInEvents (AH) | SigninLogs (Data Lake) |
|--------------------------|----------------------|
| `Timestamp` | `TimeGenerated` |
| `AccountUpn` | `UserPrincipalName` |
| `ErrorCode` (int) | `ResultType` (string) |
| `Application` | `AppDisplayName` |
| `ApplicationId` | `AppId` |
| `Country` (direct string) | `parse_json(LocationDetails).countryOrRegion` |
| `City` (direct string) | `parse_json(LocationDetails).city` |
| `LogonType` (JSON array) | `IsInteractive` (bool) |

---

## Mailbox Forwarding Rules — OfficeActivity

```kql
OfficeActivity
| where TimeGenerated > ago(30d)
| where OfficeWorkload == "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "UpdateInboxRules")
| extend Params = parse_json(Parameters)
| mv-expand Param = Params
| where tostring(Param.Name) in ("ForwardTo", "RedirectTo", "ForwardingSmtpAddress", "ForwardingAddress", "DeliverToMailboxAndForward")
| project
    TimeGenerated,
    UserId,
    Operation,
    ClientIP,
    ParamName = tostring(Param.Name),
    ParamValue = tostring(Param.Value)
| where isnotempty(ParamValue) and ParamValue != "False"
```

> 🟢 **Run in:** Sentinel Logs (Azure Portal → Microsoft Sentinel → Logs)

**Key points:**
- Mailbox forwarding rules are in `OfficeActivity`, NOT in `AuditLogs`
- Always check `Parameters` for forwarding targets
- Also query `CloudAppEvents` for complementary coverage (ActionType-based summaries)
- MITRE: T1114.003 (Email Forwarding Rule) / T1020 (Automated Exfiltration)

---

## SecurityIncident — Excluding Phantom Incidents

```kql
SecurityIncident
| where CreatedTime > ago(30d)           // Use CreatedTime, NOT TimeGenerated
| where array_length(AlertIds) > 0       // Exclude phantom incidents
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| summarize
    Total = count(),
    Open = countif(Status == "New" or Status == "Active"),
    Closed = countif(Status == "Closed"),
    TruePositive = countif(Classification == "TruePositive"),
    FalsePositive = countif(Classification == "FalsePositive"),
    BenignPositive = countif(Classification == "BenignPositive")
```

> 🟢 **Run in:** Sentinel Logs (Azure Portal → Microsoft Sentinel → Logs)

**Key points:**
- `CreatedTime` = when the incident was created (stable); `TimeGenerated` = last ingested update (changes on every status change)
- `array_length(AlertIds) > 0` filters out phantom incidents (Defender XDR synced incidents with empty alert arrays)
- `ProviderIncidentId` maps to the Defender portal URL: `https://security.microsoft.com/incidents/{ProviderIncidentId}`

---

## Key Vault Operations — AzureDiagnostics

```kql
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where ResourceType == "VAULTS"
| where Resource =~ "<vault-name>"
| where OperationName in ("SecretGet", "SecretList", "Authentication", "VaultGet", "SecretSet", "KeyGet", "CertificateGet")
| project TimeGenerated, OperationName, CallerIPAddress, ResultType, Resource, identity_claim_upn_s
| order by TimeGenerated desc
```

> 🔵 **Run in:** Advanced Hunting (if Data Lake returns "Failed to resolve table" for this legacy table)

**Key points:**
- `AzureDiagnostics` is a legacy table that may not work in Data Lake — try AH as fallback
- NOT the same as `AzureActivity` (which is ARM control plane, not Key Vault data plane)
- `identity_claim_upn_s` contains the caller UPN (column name varies by resource type)
