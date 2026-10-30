# Known Table Pitfalls — Quick Reference

> **Usage:** Read this file before querying any table listed below. These pitfalls encode hard-won lessons about column naming, data types, AH-only availability, deprecated tables, and other gotchas that cause silent failures or wrong results.

---

## ALL Sentinel/LA Tables

**Pitfall:** Column is **`TimeGenerated`**, NOT `Timestamp`. Using `Timestamp` on these tables returns `SemanticError: Failed to resolve column`. This is the **#1 most frequent error**. LLMs default to `Timestamp` from AH query patterns.

**Required Action:**
- **Data Lake / Sentinel Logs:** Always `TimeGenerated`
- **Advanced Hunting:** `Timestamp` for XDR-native tables (Device\*, Email\*, Cloud\*, Alert\*, Identity\*), `TimeGenerated` for Sentinel/LA tables
- When adapting AH queries for Data Lake: replace ALL `Timestamp` → `TimeGenerated`

---

## AADRiskySignIns

**Pitfall:** Table does **NOT exist** in Sentinel Data Lake. Querying it returns `SemanticError: Failed to resolve table`.

**Required Action:** Use `AADUserRiskEvents` instead (contains Identity Protection risk detections). For sign-in-level risk data, use `SigninLogs` with `RiskLevelDuringSignIn` and `RiskState` columns.

---

## AADUserRiskEvents

**Pitfall 1:** **IP column is `IpAddress`** (lowercase 'p'), NOT `IPAddress`. Using `IPAddress` returns `Failed to resolve scalar expression`. LLMs default to `IPAddress` (matching SigninLogs convention).

**Pitfall 2:** **Timestamp column is `ActivityDateTime`**, NOT `TimeGenerated` — using `TimeGenerated` silently returns 0 results (column exists but is ingestion time, not event time).

**Pitfall 3:** `Location` is a **JSON string** — use `parse_json(Location).countryOrRegion`.

**Pitfall 4:** **`suspiciousAuthAppApproval` naming trap.** Despite the name, this detection is about **MFA Authenticator push approval patterns** (MITRE T1621 — MFA Fatigue), **NOT** OAuth app consent grants. The `AdditionalInfo` field contains `"mitreTechniques": "T1621"` confirming MFA focus.

**Required Action:** Always use `IpAddress` (lowercase 'p') and `ActivityDateTime` for time filtering. When `suspiciousAuthAppApproval` appears: investigate MFA patterns, NOT OAuth consent grants.

---

## AIAgentsInfo

**Pitfall:** **Advanced Hunting only** — does NOT exist in Sentinel Data Lake. Multiple records per agent (state snapshots). `KnowledgeDetails` is a string containing a JSON array of JSON strings. `IsGenerativeOrchestrationEnabled` may be null. Table is in **Preview**.

**Required Action:** Query in Advanced Hunting portal. Deduplicate with `summarize arg_max(Timestamp, *) by AIAgentId`. Double-parse KnowledgeDetails: `mv-expand KnowledgeRaw = parse_json(KnowledgeDetails) | extend KnowledgeJson = parse_json(tostring(KnowledgeRaw))`.

---

## AuditLogs

**Pitfall 1:** `InitiatedBy`, `TargetResources` are **dynamic fields** — always wrap in `tostring()` before using `has` operator.

**Pitfall 2:** `OperationName` values vary across providers — e.g., "Reset user password", "Change user password", "Self-service password reset" are all different values. **Consent lifecycle trap:** `"Consent to application"` is only 1 of 4+ operations. `has_any()` requires exact word matches and is unpredictable.

**Required Action:** Use broad `has "keyword"` for discovery (e.g., `has "password"`, `has "role"`), then refine with `summarize count() by OperationName`.

---

## AzureDiagnostics

**Pitfall:** **Legacy table** — Microsoft explicitly documents that querying legacy tables like AzureDiagnostics is not supported in Data Lake. May return `SemanticError: Failed to resolve table` even though it exists in the workspace.

**Important:** This is NOT the same as `AzureActivity`. **AzureDiagnostics** = resource-specific diagnostic logs (Key Vault data plane: `SecretGet`, `Authentication`, `VaultGet`; SQL auditing; Firewall logs; etc.). **AzureActivity** = ARM control plane operations (resource creation/deletion, policy actions, role assignments).

**Required Action:** If Data Lake fails, user should try Advanced Hunting (AH can query Analytics-tier tables). Key columns: `ResourceType` (e.g., `VAULTS`), `OperationName` (e.g., `SecretGet`), `CallerIPAddress`, `ResultType`, `Resource`, `Category`.

---

## BehaviorEntities / BehaviorInfo

**Pitfall:** **Advanced Hunting only** — does NOT exist in Sentinel Data Lake. Table is in **Preview**. Two companion tables: `BehaviorInfo` (1 row per behavior) and `BehaviorEntities` (N rows per behavior). Populated by **MCAS** and **Sentinel UEBA** only. `Categories` and `AttackTechniques` are **JSON strings**, not arrays — must `parse_json()` before `mv-expand`.

**Required Action:** Query in Advanced Hunting portal. Join tables on `BehaviorId`. Key ActionTypes: `ImpossibleTravelActivity`, `MultipleFailedLoginAttempts`, `MassDownload`, `UnusualAdditionOfCredentialsToAnOauthApp`.

---

## CloudAppEvents

**Pitfall 1:** **Extremely high-volume table.** Queries without selective early filters will timeout.

**Pitfall 2:** `RawEventData` is a large JSON blob (5-100+ KB per row). Performance killers:
- `tostring(RawEventData) has "value"` — forces full JSON serialization on every row
- Repeated `parse_json(RawEventData)` calls — re-parses the blob per call
- `AccountDisplayName has "partial"` — substring match without index

**Pitfall 3:** `AccountId` is a **GUID (Entra ObjectId)**, NOT a UPN. Filtering `AccountId in~ ("user@domain.com")` returns 0 results silently. Use `AccountObjectId` (identical GUID) for indexed lookups, or `AccountDisplayName` for display-name filtering.

**Pitfall 4:** `ApplicationId` is **`int`**, NOT `string` — this is a Defender-internal integer, NOT the Entra AppId GUID. Using string GUID arrays with `in` returns `SEM0025: type mismatch`.

**Pitfall 5:** For inbox rule queries (`New-InboxRule`/`Set-InboxRule`/`Set-Mailbox`), **ALWAYS also query `OfficeActivity`** (Exchange workload) — these tables are **complementary, not alternatives**.

**Required Action:** Pre-filter aggressively. Use `AccountObjectId` for user lookups. Parse `RawEventData` once with `let`. Also query `OfficeActivity` for mailbox rule investigations.

---

## DataSecurityEvents

**Pitfall:** **Advanced Hunting only** — requires Insider Risk Management opt-in. `SensitiveInfoTypeInfo` is `Collection(String)` NOT native dynamic — requires double `parse_json()`. Contains SIT **GUIDs** not names. Copilot events can dominate 90%+ of volume. `ObjectId` is the file identifier — `ObjectName`/`ObjectType` do NOT exist. Label columns: `SensitivityLabelId` (string, can be comma-separated).

**Required Action:** Query in Advanced Hunting portal. Double-parse: `mv-expand SIT = parse_json(tostring(SensitiveInfoTypeInfo)) | extend SITJson = parse_json(tostring(SIT))`. Pre-filter with `where SensitiveInfoTypeInfo has "<GUID>"` before `mv-expand`. If table returns 0 rows, check IRM opt-in status.

---

## DeviceCustom\* (CDC Tables)

**Pitfall:** Requires MDE Custom Data Collection (CDC) rules. Tables (`DeviceCustomFileEvents`, `DeviceCustomScriptEvents`, `DeviceCustomImageLoadEvents`, `DeviceCustomNetworkEvents`) do NOT exist in workspaces without CDC policies.

**Required Action:** CDC tables are optional — if "Failed to resolve table", skip gracefully and note the telemetry gap. Query order: standard table first → if 0 results → try CDC equivalent → if CDC doesn't exist → note as telemetry limitation.

---

## DeviceInfo

**Pitfall 1:** Internet-facing detection: `ExposureGraphNodes.rawData.IsInternetFacing`, `rawData.exposedToInternet`, and `rawData.isCustomerFacing` are all **unreliable**. `isCustomerFacing` is a business-function flag (NOT internet exposure).

**Pitfall 2:** **`MachineTags` column renamed.** Old `MachineTags` no longer exists — split into: `DeviceManualTags`, `DeviceDynamicTags`, `RegistryDeviceTag`.

**Required Action:** Use `DeviceInfo.IsInternetFacing == true` (bool column). Extract details from `AdditionalFields`: `extractjson("$.InternetFacingReason", AdditionalFields)`. For tags: use `DeviceManualTags`, `DeviceDynamicTags`, `RegistryDeviceTag` — NEVER `MachineTags`.

---

## DeviceTvmSoftwareVulnerabilities / DeviceTvmSoftwareInventory / DeviceTvmSecureConfigurationAssessment / SecurityRecommendation

**Pitfall 1:** **Advanced Hunting only** — Defender TVM tables do NOT exist in Sentinel Data Lake.

**Pitfall 2:** **DeviceName is stored as FQDN** (e.g., `myserver.contoso.com`), NOT short hostname. Using `DeviceName =~ 'hostname'` returns 0 results.

**Pitfall 3:** `DeviceTvmSoftwareVulnerabilities` and `DeviceTvmSoftwareInventory` are **point-in-time snapshot tables with NO `Timestamp` column** — using `Timestamp` filter returns `Failed to resolve scalar expression`. `DeviceTvmSecureConfigurationAssessment` DOES have `Timestamp`.

**Required Action:** Query in Advanced Hunting portal. Use `DeviceName startswith '<hostname>'` (matches both short and FQDN). No deduplication needed on snapshot tables. For time context, join with `DeviceInfo`.

---

## EntraIdSignInEvents

**Pitfall 1:** **Case-sensitivity:** Capital `I` in `SignIn` — `EntraIdSigninEvents` (lowercase `i`) fails.

**Pitfall 2:** Covers **both interactive AND non-interactive** sign-ins — **default choice over** `SigninLogs` / `AADNonInteractiveUserSignInLogs` for AH queries (≤30d). SPN sign-ins use `EntraIdSpnSignInEvents`.

**Pitfall 3:** **Column mapping vs Sentinel tables:** `ErrorCode` (int) vs `ResultType` (string), `AccountUpn` vs `UserPrincipalName`, `Application`/`ApplicationId` vs `AppDisplayName`/`AppId`, `Country`/`City` as direct strings (no `parse_json(LocationDetails)`).

**Pitfall 4:** `LogonType` is **JSON array string** (`["nonInteractiveUser"]`) — use `has` not `==`.

**Pitfall 5:** `RiskLevelDuringSignIn`/`RiskState` are **int** (use `0`/`1`/`10`/`50`/`100`). `ConditionalAccessStatus` is **int** (`0`=applied, `1`=failed, `2`=not applied).

**Required Action:** AH queries (≤30d): use `EntraIdSignInEvents`. Data Lake / >30d: fall back to `SigninLogs` + `AADNonInteractiveUserSignInLogs` (union). Map column names when adapting.

---

## ExposureGraphNodes / ExposureGraphEdges

**Pitfall:** **Advanced Hunting only** — Exposure Management graph tables do NOT exist in Sentinel Data Lake.

**Required Action:** Query in Advanced Hunting portal. Uses `Timestamp`.

---

## GraphAPIAuditEvents

**Pitfall 1:** **Advanced Hunting only.** `ApplicationId` is **string** (Entra AppId GUID), but `ResponseStatusCode` is **string** — use `toint()` for numeric comparisons or `== "403"` for string matching.

**Pitfall 2:** **Column name mismatches vs `MicrosoftGraphActivityLogs` (Data Lake):** AH uses `ApplicationId` / `AccountObjectId` / `ServicePrincipalId`; Data Lake uses `AppId` / `UserId` / `ServicePrincipalId`.

**Required Action:** For AH: query in Advanced Hunting portal. For >30d: use `MicrosoftGraphActivityLogs` in Data Lake (Sentinel Logs blade). Map column names when switching.

---

## IdentityAccountInfo

**Pitfall 1:** **Advanced Hunting only.** Table is in **Preview**. Many fields not yet populated (`EnrolledMfas`, `CriticalityLevel`, etc.).

**Pitfall 2:** Multiple snapshot records per account. `AssignedRoles` and `GroupMembership` are dynamic arrays.

**Pitfall 3:** `SourceProviderRiskLevel` and `AccountStatus` vocabularies differ across providers (AAD vs Okta vs SailPoint vs CyberArk).

**Pitfall 4:** **IdentityInfo UAC join pitfall:** `array_index_of(null_dynamic, "value")` returns `null` (not `-1`). Since `null != -1` is `true` in KQL, querying without `isnotnull(UserAccountControl)` incorrectly returns true for ALL null-UAC accounts.

**Required Action:** Query in Advanced Hunting portal. Deduplicate with `summarize arg_max(Timestamp, *) by AccountId`. When using UserAccountControl: MUST add `where isnotnull(UserAccountControl)` BEFORE `array_index_of` checks.

---

## OAuthAppInfo

**Pitfall:** **Advanced Hunting only.** Key column is **`OAuthAppId`** (string, Entra AppId GUID), NOT `ApplicationId` — column doesn't exist on this table. Multiple snapshot rows per app.

**Required Action:** Query in Advanced Hunting portal. Deduplicate with `summarize arg_max(Timestamp, *) by OAuthAppId`. Cross-reference with `GraphAPIAuditEvents` via `OAuthAppInfo.OAuthAppId == GraphAPIAuditEvents.ApplicationId`.

---

## OfficeActivity

**Pitfall 1:** Mailbox forwarding/redirect rules live here, **NOT in AuditLogs.** Filter by `OfficeWorkload == "Exchange"` and `Operation in~ ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "UpdateInboxRules")`.

**Pitfall 2:** `Parameters` and `OperationProperties` are **string fields** containing JSON. Use `contains` or `has` for keyword matching, then `parse_json(Parameters)` to extract specific values.

**Required Action:** Check `Parameters` for `ForwardTo`, `RedirectTo`, `ForwardingSmtpAddress`. This table is the **primary source** for detecting email exfiltration via forwarding rules (MITRE T1114.003 / T1020).

---

## SecurityAlert

**Pitfall 1:** `Status` field is **immutable** — always "New" regardless of actual state. MUST join with `SecurityIncident` to get real Status/Classification. See `ad-hoc-query-examples.md` for the canonical join pattern.

**Pitfall 2:** `ProviderName` is an internal identifier (e.g., `MDATP`, `ASI Scheduled Alerts`, `MCAS`) and rolls up to generic names at the incident level. Use **`ProductName`** for product grouping.

---

## SecurityIncident

**Pitfall 1:** `AlertIds` contains **SystemAlertId GUIDs**, NOT usernames, IPs, or entity names. NEVER filter `AlertIds` by entity name. Instead: query `SecurityAlert` first filtering by `Entities has '<entity>'`, then join to `SecurityIncident` on AlertId.

**Pitfall 2:** **Phantom incidents with empty `AlertIds`:** Many Defender XDR-synced incidents have `AlertIds = []` — never appear in the portal. `TimeGenerated > ago(7d)` also captures old incidents with recent status updates.

**Required Action:** For accurate counts: (1) Use `CreatedTime` (not `TimeGenerated`) for time-windowed queries, (2) Add `| where array_length(AlertIds) > 0` to exclude phantom incidents.

---

## SecurityIncident / SecurityAlert

**Pitfall:** `IncidentNumber` and `SystemAlertId` are **Sentinel-local IDs** — Defender XDR uses **different IDs** (`ProviderIncidentId`). Use `ProviderIncidentId` for Defender portal lookups.

---

## SentinelHealth

**Pitfall:** `SentinelResourceType` values use **title-case with a space**: `"Analytics Rule"`, NOT `"Analytic rule"`. LLMs consistently generate the wrong casing/spelling, returning 0 results.

**Required Action:** Always use `SentinelResourceType == "Analytics Rule"` (capital A, capital R, "Analytics" with an 's'). Other valid values: `"Data connector"`, `"Automation rule"`.

---

## SigninLogs / AADNonInteractiveUserSignInLogs

**Pitfall 1:** `DeviceDetail`, `LocationDetails`, `ConditionalAccessPolicies`, `Status` may be **dynamic OR string** depending on workspace. `AADNonInteractiveUserSignInLogs` stores these as **string always**.

**Pitfall 2:** `Location` is a **string** column, NOT dynamic. Dot-notation like `Location.countryOrRegion` will fail.

**Required Action:** Always use `tostring(parse_json(DeviceDetail).operatingSystem)` — works for both types. Use `parse_json(LocationDetails).countryOrRegion` for geographic sub-properties.

---

## Signinlogs_Anomalies_KQL_CL

**Pitfall:** Custom `_CL` table names are **case-sensitive**. Table uses lowercase 'l' in "logs" — `Signinlogs` NOT `SigninLogs`.

**Required Action:** Always copy exact table name `Signinlogs_Anomalies_KQL_CL`. If `SemanticError`, verify casing first. If still fails, table may not exist — skip gracefully.

---

## UnifiedAgentObservability

**Pitfall:** **Sentinel Data Lake system table** (Agent 365 Observability connector). Lake-only — NOT in Advanced Hunting. Uses `TimeGenerated`. `ToolName` is a **top-level column** (NOT inside `AdditionalFields`). `InvokeAgent` rows have `SrcAgentId = "00000000-..."` (zero-GUID). `ActorUsername = "N/A"` on `ExecuteToolBySDK` rows.

**Required Action:** For cross-scope joins with workspace tables, use `workspace("default").UnifiedAgentObservability`. `parse_json()` dynamic columns before dot-access.

---

## Anomalies

**Pitfall:** Sentinel UEBA anomaly rule results. `Tactics` and `Techniques` are **JSON strings**, not arrays — must `parse_json()` before `make_set()`. `AnomalyReasons` is a dynamic array with `IsAnomalous` (bool) and `Name` fields. Score 0.0–1.0: ≥0.7 High, 0.3–0.7 Medium, <0.3 Low. Available in **both** Data Lake and Advanced Hunting.

**Required Action:** Use `UserPrincipalName =~` for user filtering. Always `parse_json(Tactics)` and `parse_json(Techniques)` before aggregation. Filter `AnomalyReasons` with `tobool(reason.IsAnomalous) == true`. Do NOT confuse with `BehaviorInfo` (MCAS, AH-only) or `BehaviorAnalytics` (raw UEBA events, Data Lake-only).
