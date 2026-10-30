# MCP Anomaly Detection — Sentinel Data Lake KQL Jobs

**Created:** 2026-02-08
**Validated:** 2026-02-08 (tested against 90 days of real MCP telemetry)
**Platform:** Microsoft Sentinel Data Lake
**Tables:** MicrosoftGraphActivityLogs, AADNonInteractiveUserSignInLogs, SigninLogs, LAQueryLogs, CloudAppEvents, AzureActivity
**MITRE:** TA0001, TA0003, TA0006, TA0007, TA0009, TA0010, T1078, T1098
**Timeframe:** Rolling daily with 14-day baseline

---

## Validation Results (2026-02-08)

| Job | Test Date | Result | Notes |
|-----|-----------|--------|-------|
| **Job 1** (New Sensitive Endpoint) | Jan 26 | ✅ 3 anomalies detected | Empty baseline = everything new. Fixed two-step regex. |
| **Job 5** (New Azure MCP User) | Jan 14 | ✅ 1 anomaly detected | First-time Azure MCP user correctly flagged. |
| **Job 7** (Sentinel Query Anomalies) | Jan 9 | ✅ Volume spike 12.74x | Fixed `AADEmail` empty for Triage MCP with `AADObjectId` fallback. |
| **Job 8** (Cross-MCP Correlation) | Feb 8 | ✅ Cross-MCP detected | Graph + Azure. Sentinel Triage leg doesn't join by user identity (known limitation). |

### Bugs Found and Fixed

1. **Endpoint extraction regex** (Jobs 1-4, 8): Matched `/graph` from hostname. Fixed with two-step extraction.
2. **`sensitivePatterns` leading slashes** (Job 1): Removed leading `/` for `has_any` match.
3. **Empty `AADEmail`** (Job 7): Fixed with `iff(isnotempty(AADEmail), AADEmail, AADObjectId)` fallback.
4. **Cross-MCP identity mismatch** (Job 8): Sentinel Triage MCP `AADObjectId` = SP Object ID, not end user's. Documented as known limitation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Sentinel Data Lake                      │
│  MicrosoftGraphActivityLogs, AADNonInteractive, etc.     │
│                                                          │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Scheduled KQL Jobs (daily)                      │    │
│  │  - Behavioral baselines (14-day)                 │    │
│  │  - Anomaly detection                             │    │
│  │  - Cross-MCP correlation                         │    │
│  └──────────────┬───────────────────────────────────┘    │
│                 │ promote                                 │
│                 ▼                                         │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Analytics Tier (_KQL_CL tables)                 │    │
│  │  - MCPGraphAnomalies_KQL_CL                      │    │
│  │  - MCPSentinelAnomalies_KQL_CL                   │    │
│  │  - MCPAzureAnomalies_KQL_CL                      │    │
│  │  - MCPCrossMCPCorrelation_KQL_CL                 │    │
│  └──────────────┬───────────────────────────────────┘    │
│                 │ query                                   │
│                 ▼                                         │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Custom Detections (recommended) or Analytics    │    │
│  │  Rules → Incidents                               │    │
│  └──────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### KQL Job Configuration

| Parameter | Recommended Value |
|-----------|-------------------|
| **Schedule** | Daily |
| **Lookback** | 1 day (with 14-day baseline in query) |
| **Delay** | 15 minutes (`now() - 15m`) |
| **Timeout** | 1 hour max |
| **Destination** | Analytics tier, new `_KQL_CL` table |

### Cost Considerations

> ⚠️ These queries project **only anomaly records** (not full event volume) and only the columns needed for alerting. Typical daily output: tens to hundreds of rows.

> ⚠️ `TimeGenerated` is overwritten if older than 2 days. All queries write original timestamp to `DetectedTime`.

---

## Job 1: Graph MCP — New Sensitive Endpoint Detection

**Destination:** `MCPGraphAnomalies_KQL_CL` | **Schedule:** Daily

```kql
// Job 1: Graph MCP — New Sensitive Endpoint Detection
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
let graphMcpAppId = "e8c77dc2-69b3-43f4-bc51-3213c9d915b4";
let sensitivePatterns = dynamic([
    "roleManagement", "identityGovernance", "identity/conditionalAccess",
    "applications", "servicePrincipals", "identityProtection",
    "security/alerts", "security/incidents", "auditLogs",
    "users/authentication", "policies", "privilegedAccess",
    "directoryRoles", "groupLifecyclePolicies",
    "informationProtection", "dataClassification"
]);
let baseline = MicrosoftGraphActivityLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| where EndpointCategory has_any (sensitivePatterns)
| summarize BaselineHits = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by UserId, EndpointCategory;
let recent = MicrosoftGraphActivityLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| where EndpointCategory has_any (sensitivePatterns)
| summarize
    RecentHits = count(),
    DistinctEndpoints = dcount(RequestUri),
    SampleEndpoints = make_set(RequestUri, 5),
    ResponseCodes = make_set(ResponseStatusCode, 10),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserId, EndpointCategory;
recent
| join kind=leftanti baseline on UserId, EndpointCategory
| extend
    AnomalyType = "NewSensitiveEndpoint",
    MCPServer = "GraphMCP",
    Severity = case(
        EndpointCategory has_any ("roleManagement", "identity/conditionalAccess", "privilegedAccess"), "High",
        EndpointCategory has_any ("applications", "servicePrincipals", "identityProtection"), "Medium",
        "Low"),
    Description = strcat("User accessed sensitive Graph endpoint '", EndpointCategory, "' via MCP for the first time")
| project
    DetectedTime, AnomalyType, MCPServer, Severity, UserId,
    EndpointCategory, RecentHits, DistinctEndpoints, SampleEndpoints,
    ResponseCodes, LastActivity, Description
```

---

## Job 2: Graph MCP — Volume Spike Detection

**Destination:** `MCPGraphAnomalies_KQL_CL` | **Schedule:** Daily

```kql
// Job 2: Graph MCP — Volume Spike Detection (3x daily average)
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
let graphMcpAppId = "e8c77dc2-69b3-43f4-bc51-3213c9d915b4";
let spikeThreshold = 3.0;
let minBaselineDays = 3;
let baseline = MicrosoftGraphActivityLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AppId == graphMcpAppId
| summarize DailyCount = count() by UserId, Day = bin(TimeGenerated, 1d)
| summarize
    AvgDailyCount = avg(DailyCount),
    StdDevDailyCount = stdev(DailyCount),
    MaxDailyCount = max(DailyCount),
    BaselineDays = dcount(Day),
    TotalBaselineHits = sum(DailyCount)
    by UserId;
let recent = MicrosoftGraphActivityLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| summarize
    RecentDayCount = count(),
    DistinctEndpoints = dcount(RequestUri),
    TopEndpoints = make_set(EndpointCategory, 10),
    ErrorCount = countif(ResponseStatusCode >= 400),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserId;
recent
| join kind=inner baseline on UserId
| where BaselineDays >= minBaselineDays
| extend SpikeRatio = round(RecentDayCount * 1.0 / AvgDailyCount, 2)
| where SpikeRatio >= spikeThreshold
| extend
    AnomalyType = "VolumeSpike",
    MCPServer = "GraphMCP",
    Severity = case(SpikeRatio >= 10.0, "High", SpikeRatio >= 5.0, "Medium", "Low"),
    Description = strcat("User's Graph MCP volume (", RecentDayCount, ") is ", SpikeRatio, "x their 14-day avg (", round(AvgDailyCount, 0), ")")
| project
    DetectedTime, AnomalyType, MCPServer, Severity, UserId,
    RecentDayCount, AvgDailyCount = round(AvgDailyCount, 1), SpikeRatio,
    MaxDailyCount, BaselineDays, DistinctEndpoints, TopEndpoints,
    ErrorCount, LastActivity, Description
```

---

## Job 3: Graph MCP — Off-Hours Activity Detection

**Destination:** `MCPGraphAnomalies_KQL_CL` | **Schedule:** Daily

```kql
// Job 3: Graph MCP — Off-Hours Activity Detection
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let recentStart = endTime - recentWindow;
let graphMcpAppId = "e8c77dc2-69b3-43f4-bc51-3213c9d915b4";
let businessHoursStart = 7;
let businessHoursEnd = 19;
let timezoneOffsetHours = -8; // PST — adjust for your org
MicrosoftGraphActivityLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| extend LocalHour = hourofday(TimeGenerated + timezoneOffsetHours * 1h)
| where LocalHour < businessHoursStart or LocalHour >= businessHoursEnd
| extend DayOfWeekLocal = dayofweek(TimeGenerated + timezoneOffsetHours * 1h)
| extend IsWeekend = DayOfWeekLocal in (6d, 0d)
| summarize
    OffHoursCallCount = count(),
    DistinctEndpoints = dcount(RequestUri),
    TopEndpoints = make_set(EndpointCategory, 10),
    HoursActive = make_set(LocalHour, 24),
    WeekendActivity = countif(IsWeekend),
    ErrorCount = countif(ResponseStatusCode >= 400),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserId
| where OffHoursCallCount >= 5
| extend
    AnomalyType = "OffHoursActivity",
    MCPServer = "GraphMCP",
    Severity = case(
        WeekendActivity > 0 and OffHoursCallCount >= 50, "High",
        OffHoursCallCount >= 50, "Medium", "Low"),
    Description = strcat("User made ", OffHoursCallCount, " Graph MCP calls outside business hours. Weekend: ", WeekendActivity)
| project
    DetectedTime, AnomalyType, MCPServer, Severity, UserId,
    OffHoursCallCount, WeekendActivity, DistinctEndpoints, TopEndpoints,
    HoursActive, ErrorCount, LastActivity, Description
```

---

## Job 4: Graph MCP — Error Rate Anomaly

**Destination:** `MCPGraphAnomalies_KQL_CL` | **Schedule:** Daily

```kql
// Job 4: Graph MCP — Error Rate Anomaly
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
let graphMcpAppId = "e8c77dc2-69b3-43f4-bc51-3213c9d915b4";
let errorRateThreshold = 0.30;
let spikeMultiplier = 2.0;
let baseline = MicrosoftGraphActivityLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AppId == graphMcpAppId
| summarize
    BaselineTotalCalls = count(),
    BaselineErrors = countif(ResponseStatusCode >= 400),
    BaselineDays = dcount(bin(TimeGenerated, 1d))
    by UserId
| extend BaselineErrorRate = round(BaselineErrors * 1.0 / BaselineTotalCalls, 4);
let recent = MicrosoftGraphActivityLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| summarize
    RecentTotalCalls = count(),
    RecentErrors = countif(ResponseStatusCode >= 400),
    TopErrorEndpoints = make_set_if(EndpointCategory, ResponseStatusCode >= 400, 10),
    TopErrorCodes = make_set_if(ResponseStatusCode, ResponseStatusCode >= 400, 10),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserId
| extend RecentErrorRate = round(RecentErrors * 1.0 / RecentTotalCalls, 4);
recent
| join kind=leftouter baseline on UserId
| extend
    ErrorRateSpike = iff(isnotnull(BaselineErrorRate) and BaselineErrorRate > 0,
        round(RecentErrorRate / BaselineErrorRate, 2), 0.0),
    IsNewUser = isnull(BaselineTotalCalls)
| where RecentErrorRate >= errorRateThreshold
    or (ErrorRateSpike >= spikeMultiplier and RecentErrors >= 10)
    or (IsNewUser and RecentErrors >= 5)
| extend
    AnomalyType = case(IsNewUser, "NewUserHighErrors", ErrorRateSpike >= spikeMultiplier, "ErrorRateSpike", "HighErrorRate"),
    MCPServer = "GraphMCP",
    Severity = case(
        RecentErrorRate >= 0.5 and RecentErrors >= 50, "High",
        RecentErrorRate >= 0.3 or ErrorRateSpike >= 5.0, "Medium", "Low"),
    Description = strcat("Error rate: ", round(RecentErrorRate * 100, 1), "% (", RecentErrors, "/", RecentTotalCalls, "). ",
        iff(IsNewUser, "NEW USER. ", strcat("Baseline: ", round(BaselineErrorRate * 100, 1), "%, spike: ", ErrorRateSpike, "x. ")),
        "Top error endpoints: ", tostring(TopErrorEndpoints))
| project
    DetectedTime, AnomalyType, MCPServer, Severity, UserId,
    RecentTotalCalls, RecentErrors, RecentErrorRate, BaselineErrorRate,
    ErrorRateSpike, TopErrorEndpoints, TopErrorCodes, IsNewUser,
    LastActivity, Description
```

---

## Job 5: Azure MCP Server — New User Detection

**Destination:** `MCPAzureAnomalies_KQL_CL` | **Schedule:** Daily

```kql
// Job 5: Azure MCP Server — New User Detection
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
let azureMcpAppId = "1950a258-227b-4e31-a9cf-717495945fc2";
let baselineUsers = AADNonInteractiveUserSignInLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AppId == azureMcpAppId
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| distinct UserId, UserPrincipalName;
let recentUsers = AADNonInteractiveUserSignInLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == azureMcpAppId
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| summarize
    SessionCount = dcount(CorrelationId),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 5),
    Resources = make_set(ResourceDisplayName, 10),
    ResultTypes = make_set(ResultType, 10),
    UserAgent = take_any(UserAgent),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by UserId, UserPrincipalName;
recentUsers
| join kind=leftanti baselineUsers on UserId
| extend
    AnomalyType = "NewAzureMCPUser",
    MCPServer = "AzureMCP",
    Severity = case(DistinctIPs > 1, "High", "Medium"),
    Description = strcat("New Azure MCP Server user: ", UserPrincipalName, ". ", SessionCount, " session(s) from ", DistinctIPs, " IP(s).")
| project
    DetectedTime, AnomalyType, MCPServer, Severity, UserId,
    UserPrincipalName, SessionCount, DistinctIPs, IPs, Resources,
    ResultTypes, UserAgent, LastActivity, Description
```

---

## Job 6: Azure MCP Server — New Resource Target Detection

**Destination:** `MCPAzureAnomalies_KQL_CL` | **Schedule:** Daily

```kql
// Job 6: Azure MCP Server — New Resource Target Detection
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
let azureMcpAppId = "1950a258-227b-4e31-a9cf-717495945fc2";
let baseline = AADNonInteractiveUserSignInLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AppId == azureMcpAppId
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| summarize BaselineHits = count()
    by UserId, UserPrincipalName, ResourceDisplayName;
let recent = AADNonInteractiveUserSignInLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == azureMcpAppId
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| summarize
    RecentHits = count(),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated),
    IPs = make_set(IPAddress, 5),
    ResultTypes = make_set(ResultType, 10)
    by UserId, UserPrincipalName, ResourceDisplayName;
recent
| join kind=leftanti baseline on UserId, ResourceDisplayName
| extend
    AnomalyType = "NewResourceTarget",
    MCPServer = "AzureMCP",
    Severity = case(
        ResourceDisplayName has_any ("Key Vault", "Microsoft Graph", "Azure Key Vault"), "High",
        ResourceDisplayName has "Azure Resource Manager", "Medium", "Low"),
    Description = strcat("Azure MCP user '", UserPrincipalName, "' accessed new resource '", ResourceDisplayName, "'. Hits: ", RecentHits)
| project
    DetectedTime, AnomalyType, MCPServer, Severity, UserId,
    UserPrincipalName, ResourceDisplayName, RecentHits, IPs,
    ResultTypes, LastActivity, Description
```

---

## Job 7: Sentinel MCP — Workspace Query Anomalies

**Destination:** `MCPSentinelAnomalies_KQL_CL` | **Schedule:** Daily

```kql
// Job 7: Sentinel MCP — Workspace Query Anomalies
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let baselineWindow = 14d;
let recentStart = endTime - recentWindow;
let baselineStart = endTime - baselineWindow;
let mcpAppIds = dynamic([
    "6574a0f8-d39b-4090-abbe-6c64ec9003f0",
    "1950a258-227b-4e31-a9cf-717495945fc2"
]);
let baselineTables = LAQueryLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AADClientId in (mcpAppIds)
| extend AADEmail = iff(isnotempty(AADEmail), AADEmail, AADObjectId)
| extend PrimaryTable = extract("^\\s*([A-Za-z_]+)", 1, QueryText)
| where isnotempty(PrimaryTable)
| summarize BaselineQueryCount = count() by AADEmail, PrimaryTable, AADClientId;
let baselineVolume = LAQueryLogs
| where TimeGenerated between (baselineStart .. recentStart)
| where AADClientId in (mcpAppIds)
| extend AADEmail = iff(isnotempty(AADEmail), AADEmail, AADObjectId)
| summarize DailyQueries = count() by AADEmail, Day = bin(TimeGenerated, 1d)
| summarize
    AvgDailyQueries = avg(DailyQueries),
    MaxDailyQueries = max(DailyQueries),
    BaselineDays = dcount(Day)
    by AADEmail;
let recentTables = LAQueryLogs
| where TimeGenerated between (recentStart .. endTime)
| where AADClientId in (mcpAppIds)
| extend AADEmail = iff(isnotempty(AADEmail), AADEmail, AADObjectId)
| extend PrimaryTable = extract("^\\s*([A-Za-z_]+)", 1, QueryText)
| where isnotempty(PrimaryTable)
| summarize
    RecentQueryCount = count(),
    TotalRowsReturned = sum(ResponseRowCount),
    AvgRowsReturned = avg(ResponseRowCount),
    MaxRowsReturned = max(ResponseRowCount),
    SampleQueries = make_set(substring(QueryText, 0, 200), 3),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by AADEmail, PrimaryTable, AADClientId;
let newTableAnomalies = recentTables
| join kind=leftanti baselineTables on AADEmail, PrimaryTable
| extend
    AnomalyType = "NewTableQueried",
    MCPServer = case(
        AADClientId == "6574a0f8-d39b-4090-abbe-6c64ec9003f0", "SentinelTriageMCP",
        AADClientId == "1950a258-227b-4e31-a9cf-717495945fc2", "AzureMCP", "UnknownMCP"),
    Severity = case(
        PrimaryTable has_any ("SecurityIncident", "SecurityAlert", "AuditLogs", "IdentityInfo"), "High",
        PrimaryTable has_any ("SigninLogs", "AADNonInteractiveUserSignInLogs", "DeviceEvents"), "Medium", "Low"),
    Description = strcat("MCP user '", AADEmail, "' queried table '", PrimaryTable, "' for the first time. Rows: ", TotalRowsReturned);
let recentVolume = LAQueryLogs
| where TimeGenerated between (recentStart .. endTime)
| where AADClientId in (mcpAppIds)
| extend AADEmail = iff(isnotempty(AADEmail), AADEmail, AADObjectId)
| summarize RecentDayQueries = count(), DetectedTime = min(TimeGenerated), LastActivity = max(TimeGenerated) by AADEmail;
let volumeAnomalies = recentVolume
| join kind=inner baselineVolume on AADEmail
| where BaselineDays >= 3
| extend SpikeRatio = round(RecentDayQueries * 1.0 / AvgDailyQueries, 2)
| where SpikeRatio >= 3.0
| extend
    AnomalyType = "QueryVolumeSpike",
    MCPServer = "SentinelMCP",
    PrimaryTable = "N/A",
    AADClientId = "multiple",
    RecentQueryCount = RecentDayQueries,
    TotalRowsReturned = long(0),
    SampleQueries = dynamic([]),
    Severity = case(SpikeRatio >= 10.0, "High", SpikeRatio >= 5.0, "Medium", "Low"),
    Description = strcat("MCP user '", AADEmail, "' query volume (", RecentDayQueries, ") is ", SpikeRatio, "x their 14-day avg (", round(AvgDailyQueries, 0), ")");
let largeResultAnomalies = LAQueryLogs
| where TimeGenerated between (recentStart .. endTime)
| where AADClientId in (mcpAppIds)
| extend AADEmail = iff(isnotempty(AADEmail), AADEmail, AADObjectId)
| where ResponseRowCount >= 10000
| extend PrimaryTable = extract("^\\s*([A-Za-z_]+)", 1, QueryText)
| summarize
    RecentQueryCount = count(),
    TotalRowsReturned = sum(ResponseRowCount),
    MaxSingleQuery = max(ResponseRowCount),
    SampleQueries = make_set(substring(QueryText, 0, 200), 3),
    DetectedTime = min(TimeGenerated),
    LastActivity = max(TimeGenerated)
    by AADEmail, AADClientId
| extend
    AnomalyType = "LargeResultSet",
    MCPServer = case(AADClientId == "6574a0f8-d39b-4090-abbe-6c64ec9003f0", "SentinelTriageMCP", "AzureMCP"),
    PrimaryTable = "Multiple",
    Severity = case(TotalRowsReturned >= 100000, "High", "Medium"),
    Description = strcat("MCP user '", AADEmail, "' retrieved ", TotalRowsReturned, " total rows. Largest single: ", MaxSingleQuery);
union newTableAnomalies, volumeAnomalies, largeResultAnomalies
| project
    DetectedTime, AnomalyType, MCPServer, Severity, AADEmail,
    PrimaryTable, AADClientId, RecentQueryCount, TotalRowsReturned,
    SampleQueries, LastActivity, Description
```

---

## Job 8: Cross-MCP Correlation — Multi-Server Activity Chains

**Destination:** `MCPCrossMCPCorrelation_KQL_CL` | **Schedule:** Daily

> ⚠️ **Known Limitation:** Sentinel Triage MCP `AADObjectId` = SP Object ID, not end user's. Graph+Azure correlation works correctly; Sentinel leg may not join by user identity.

```kql
// Job 8: Cross-MCP Correlation
let delay = 15m;
let endTime = now() - delay;
let recentWindow = 1d;
let recentStart = endTime - recentWindow;
let graphMcpAppId = "e8c77dc2-69b3-43f4-bc51-3213c9d915b4";
let azureMcpAppId = "1950a258-227b-4e31-a9cf-717495945fc2";
let triageMcpAppId = "6574a0f8-d39b-4090-abbe-6c64ec9003f0";
let graphActivity = MicrosoftGraphActivityLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == graphMcpAppId
| extend ApiPath = extract("microsoft.com/[^/]+/(.*?)(?:\\?|$)", 1, RequestUri)
| extend EndpointCategory = extract("^([a-zA-Z]+(?:/[a-zA-Z]+)?)", 1, ApiPath)
| summarize
    GraphCallCount = count(),
    GraphEndpoints = make_set(EndpointCategory, 10),
    GraphSensitive = countif(EndpointCategory has_any ("roleManagement", "conditionalAccess", "applications", "identityProtection")),
    GraphFirstSeen = min(TimeGenerated),
    GraphLastSeen = max(TimeGenerated)
    by UserId;
let azureActivity = AADNonInteractiveUserSignInLogs
| where TimeGenerated between (recentStart .. endTime)
| where AppId == azureMcpAppId
| where UserAgent has "azsdk-net-Identity" and UserAgent has "Microsoft Windows"
| summarize
    AzureSessionCount = dcount(CorrelationId),
    AzureResources = make_set(ResourceDisplayName, 10),
    AzureFirstSeen = min(TimeGenerated),
    AzureLastSeen = max(TimeGenerated)
    by UserId;
let sentinelActivity = LAQueryLogs
| where TimeGenerated between (recentStart .. endTime)
| where AADClientId == triageMcpAppId
| extend UserId = coalesce(AADEmail, AADObjectId)
| summarize
    SentinelQueryCount = count(),
    SentinelTables = make_set(extract("^\\s*([A-Za-z_]+)", 1, QueryText), 10),
    SentinelTotalRows = sum(ResponseRowCount),
    SentinelFirstSeen = min(TimeGenerated),
    SentinelLastSeen = max(TimeGenerated)
    by UserId;
let azureQueries = LAQueryLogs
| where TimeGenerated between (recentStart .. endTime)
| where AADClientId == azureMcpAppId
| where RequestClientApp has "csharpsdk"
| extend UserId = coalesce(AADEmail, AADObjectId)
| summarize
    AzureQueryCount = count(),
    AzureQueryTables = make_set(extract("^\\s*([A-Za-z_]+)", 1, QueryText), 10),
    AzureQueryRows = sum(ResponseRowCount)
    by UserId;
graphActivity
| join kind=fullouter azureActivity on UserId
| join kind=fullouter sentinelActivity on UserId
| join kind=fullouter azureQueries on UserId
| extend UserId = coalesce(UserId, UserId1, UserId2, UserId3)
| extend MCPServersUsed = (iff(isnotnull(GraphCallCount), 1, 0)
    + iff(isnotnull(AzureSessionCount), 1, 0)
    + iff(isnotnull(SentinelQueryCount) or isnotnull(AzureQueryCount), 1, 0))
| where MCPServersUsed >= 2
| extend
    DetectedTime = min_of(
        coalesce(GraphFirstSeen, datetime(9999-12-31)),
        coalesce(AzureFirstSeen, datetime(9999-12-31)),
        coalesce(SentinelFirstSeen, datetime(9999-12-31))),
    AnomalyType = "CrossMCPActivity",
    Severity = case(
        GraphSensitive > 0 and isnotnull(AzureSessionCount), "High",
        MCPServersUsed >= 3, "High",
        coalesce(GraphCallCount, 0) + coalesce(SentinelQueryCount, 0) + coalesce(AzureQueryCount, 0) >= 50, "Medium",
        "Low"),
    MCPServerList = strcat(
        iff(isnotnull(GraphCallCount), "GraphMCP,", ""),
        iff(isnotnull(AzureSessionCount), "AzureMCP,", ""),
        iff(isnotnull(SentinelQueryCount), "SentinelTriageMCP,", ""),
        iff(isnotnull(AzureQueryCount), "AzureMCP-Queries,", "")),
    Description = strcat("User '", UserId, "' used ", MCPServersUsed, " MCP servers. ",
        iff(isnotnull(GraphCallCount), strcat("Graph: ", GraphCallCount, " calls", iff(GraphSensitive > 0, strcat(" (", GraphSensitive, " sensitive)"), ""), ". "), ""),
        iff(isnotnull(AzureSessionCount), strcat("Azure: ", AzureSessionCount, " sessions. "), ""),
        iff(isnotnull(SentinelQueryCount), strcat("Sentinel: ", SentinelQueryCount, " queries. "), ""),
        iff(isnotnull(AzureQueryCount), strcat("Azure queries: ", AzureQueryCount, ". "), ""))
| project
    DetectedTime, AnomalyType, MCPServer = "CrossMCP", Severity, UserId,
    MCPServersUsed, MCPServerList,
    GraphCallCount = coalesce(GraphCallCount, 0),
    GraphSensitive = coalesce(GraphSensitive, 0), GraphEndpoints,
    AzureSessionCount = coalesce(AzureSessionCount, 0), AzureResources,
    SentinelQueryCount = coalesce(SentinelQueryCount, 0), SentinelTables,
    AzureQueryCount = coalesce(AzureQueryCount, 0), AzureQueryTables,
    Description
```

---

## Companion Detection Rules

Create these as **Custom Detections** (recommended) in the Defender portal.

### Rule 1: New Sensitive Graph Endpoint via MCP

| Setting | Value |
|---------|-------|
| **Name** | `MCP Graph New Sensitive Endpoint` |
| **Severity** | Medium |
| **Category** | InitialAccess |
| **Frequency** | Every 1 hour |

```kql
MCPGraphAnomalies_KQL_CL
| where AnomalyType == "NewSensitiveEndpoint"
| where Severity in ("High", "Medium")
| project TimeGenerated, UserId, EndpointCategory, Severity, RecentHits,
    DistinctEndpoints, SampleEndpoints, ResponseCodes, LastActivity, Description
```

### Rule 2: MCP Volume Spike

| Setting | Value |
|---------|-------|
| **Name** | `MCP Graph Volume Spike` |
| **Severity** | Medium |
| **Category** | Collection |
| **Frequency** | Every 1 hour |

```kql
MCPGraphAnomalies_KQL_CL
| where AnomalyType == "VolumeSpike"
| where Severity in ("High", "Medium")
| project TimeGenerated, UserId, Severity, RecentDayCount, AvgDailyCount,
    SpikeRatio, MaxDailyCount, BaselineDays, DistinctEndpoints, TopEndpoints,
    ErrorCount, LastActivity, Description
```

### Rule 3: Cross-MCP Suspicious Activity Chain

| Setting | Value |
|---------|-------|
| **Name** | `MCP Cross Server Suspicious Chain` |
| **Severity** | High |
| **Category** | LateralMovement |
| **Frequency** | Every 1 hour |

```kql
MCPCrossMCPCorrelation_KQL_CL
| where AnomalyType == "CrossMCPActivity"
| where Severity == "High"
| project TimeGenerated, UserId, Severity, MCPServersUsed, MCPServerList,
    GraphCallCount, GraphSensitive, GraphEndpoints, AzureSessionCount,
    AzureResources, SentinelQueryCount, SentinelTables, AzureQueryCount, Description
```

### Rule 4: New Azure MCP Server User

| Setting | Value |
|---------|-------|
| **Name** | `MCP Azure New User Detected` |
| **Severity** | Medium |
| **Category** | InitialAccess |
| **Frequency** | Every 1 hour |

```kql
MCPAzureAnomalies_KQL_CL
| where AnomalyType == "NewAzureMCPUser"
| project TimeGenerated, UserId, UserPrincipalName, Severity, SessionCount,
    DistinctIPs, IPs, Resources, ResultTypes, UserAgent, LastActivity, Description
```

### Rule 5: Large Data Retrieval via MCP

| Setting | Value |
|---------|-------|
| **Name** | `MCP Large Data Retrieval` |
| **Severity** | Medium |
| **Category** | Exfiltration |
| **Frequency** | Every 1 hour |

```kql
MCPSentinelAnomalies_KQL_CL
| where AnomalyType == "LargeResultSet"
| where Severity in ("High", "Medium")
| project TimeGenerated, AADEmail, Severity, MCPServer, AADClientId,
    RecentQueryCount, TotalRowsReturned, SampleQueries, LastActivity, Description
```

---

## Deployment Checklist

1. **Prerequisites:**
   - [ ] Sentinel Data Lake onboarded
   - [ ] Log Analytics Contributor role assigned
   - [ ] `MicrosoftGraphActivityLogs` diagnostic setting enabled
   - [ ] `LAQueryLogs` diagnostic settings enabled
   - [ ] `CloudAppEvents` connector active (optional)

2. **Create KQL Jobs:**
   - [ ] Job 1-4 → `MCPGraphAnomalies_KQL_CL` (daily)
   - [ ] Job 5-6 → `MCPAzureAnomalies_KQL_CL` (daily)
   - [ ] Job 7 → `MCPSentinelAnomalies_KQL_CL` (daily)
   - [ ] Job 8 → `MCPCrossMCPCorrelation_KQL_CL` (daily)

3. **Create Detection Rules (Custom Detections — recommended):**
   - [ ] Rules 1-5

4. **Validation:**
   - [ ] Run each job manually
   - [ ] Confirm `_KQL_CL` tables appear
   - [ ] Test detection rules fire
   - [ ] Review cost after 7 days

---

## MITRE ATT&CK Coverage

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| Job 1 | T1087 (Account Discovery) | Agent probing identity/role APIs |
| Job 2 | T1119 (Automated Collection) | Bulk data harvesting |
| Job 3 | T1078 (Valid Accounts) | Stolen credentials used off-hours |
| Job 4 | T1078.004 (Cloud Accounts) | Permission boundary probing |
| Job 5 | T1078 (Valid Accounts) | New tool adoption or compromised credential |
| Job 6 | T1526 (Cloud Service Discovery) | Infrastructure reconnaissance |
| Job 7 | T1530 (Data from Cloud Storage) | Exfiltration via large queries |
| Job 8 | Full Kill Chain | Multi-stage attack across MCP servers |
