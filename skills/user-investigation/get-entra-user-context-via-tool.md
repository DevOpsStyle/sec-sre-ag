# Entra User Context via RunAzCliReadCommands Tool

## Purpose

This document provides the exact `RunAzCliReadCommands` tool calls to retrieve Entra ID
user context when Graph API permissions are available. This is the **primary method**
for collecting user profile, MFA, devices, and Identity Protection data.

If Graph API returns **403 Forbidden**, skip this entirely and use the
**KQL Fallback Queries (Q0a, Q0b, Q0c)** documented in SKILL.md.

---

## ⛔ Critical: Tool Selection

> **ALWAYS** use `RunAzCliReadCommands` for ALL calls in this document.
>
> **NEVER** use `RunAzCliWriteCommands` — even though the calls are `az rest --method GET` (read-only), `RunAzCliWriteCommands` has a different authorization flow:
> 1. It first tries Managed Identity (same as `RunAzCliReadCommands`)
> 2. If MI returns 403, it falls back to **On-Behalf-Of (OBO)** flow
> 3. OBO requires **Delegated permissions** which are NOT configured → **403 error**
>
> `RunAzCliReadCommands` uses MI directly with **Application permissions** → works correctly.
>
> **NEVER** use `RunInTerminal` with `az` commands — the `az` binary is not in the shell PATH.

---

## Decision Flow

```
Can I use RunAzCliReadCommands tool?
  ├─ YES → Use the calls below (this document)
  │         └─ If 403 on Step 1 → Stop. Use KQL Fallback (Q0)
  └─ NO → Use KQL Fallback (Q0) directly
```

---

## Step-by-Step Tool Calls

### Step 1: User Profile (MUST be first — provides user_id)

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://graph.microsoft.com/v1.0/users/<UPN>?$select=id,displayName,userPrincipalName,mail,userType,jobTitle,department,officeLocation,accountEnabled,onPremisesSecurityIdentifier" --subscription <SUBSCRIPTION_ID>
```

**Extract from response:**
- `user_id` = response `id` field (Entra Object ID GUID)
- `user_sid` = response `onPremisesSecurityIdentifier` field (Windows SID, may be null)
- All profile fields: displayName, department, jobTitle, officeLocation, accountEnabled, userType

**If this returns 403:** STOP all Graph API calls. Proceed to KQL Fallback (Q0).

---

### Step 2: MFA Authentication Methods (requires user_id from Step 1)

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://graph.microsoft.com/v1.0/users/<USER_ID>/authentication/methods?$top=10" --subscription <SUBSCRIPTION_ID>
```

**Extract from response:**
- `mfa_methods` = response `value` array
- Look for `@odata.type` values:
  - `#microsoft.graph.microsoftAuthenticatorAuthenticationMethod` → Authenticator App
  - `#microsoft.graph.fido2AuthenticationMethod` → FIDO2/Passkey
  - `#microsoft.graph.phoneAuthenticationMethod` → Phone/SMS
  - `#microsoft.graph.passwordAuthenticationMethod` → Password (always present)
  - `#microsoft.graph.windowsHelloForBusinessAuthenticationMethod` → Windows Hello

---

### Step 3: Registered Devices (requires user_id from Step 1)

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://graph.microsoft.com/v1.0/users/<USER_ID>/ownedDevices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,registrationDateTime,isCompliant,isManaged,trustType,approximateLastSignInDateTime&$orderby=approximateLastSignInDateTime desc&$top=5" --headers "ConsistencyLevel=eventual" --subscription <SUBSCRIPTION_ID>
```

---

### Step 4: Identity Protection Risk Profile (requires user_id from Step 1)

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/<USER_ID>" --subscription <SUBSCRIPTION_ID>
```

**If 404:** User is NOT in the risky users list (expected for clean users). Set:
```json
{"riskLevel": "none", "riskState": "none", "riskDetail": "none"}
```

---

### Step 5: Risk Detections (requires user_id from Step 1)

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$filter=userId eq '<USER_ID>'&$select=id,detectedDateTime,riskEventType,riskLevel,riskState,riskDetail,ipAddress,location,activity,activityDateTime&$orderby=detectedDateTime desc&$top=10" --subscription <SUBSCRIPTION_ID>
```

---

### Step 6: Risky Sign-ins (requires user_id from Step 1, uses beta endpoint)

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://graph.microsoft.com/beta/auditLogs/signIns?$filter=userId eq '<USER_ID>' and (riskState eq 'atRisk' or riskState eq 'confirmedCompromised')&$select=id,createdDateTime,userPrincipalName,appDisplayName,ipAddress,location,riskState,riskLevelDuringSignIn,riskEventTypes_v2,riskDetail,status&$orderby=createdDateTime desc&$top=5" --subscription <SUBSCRIPTION_ID>
```

---

## Error Reference

| Error | Meaning | Action |
|-------|---------|--------|
| 403 Forbidden | Agent identity lacks Graph permissions | Use KQL Fallback (Q0) |
| 403 Forbidden (from `RunAzCliWriteCommands`) | Wrong tool used — OBO fallback failed | Switch to `RunAzCliReadCommands` |
| 404 Not Found (user) | UPN does not exist in this tenant | Verify UPN spelling |
| 404 Not Found (riskyUsers) | User not in risky list | Normal — set riskLevel: "none" |
| 401 Unauthorized | Token expired or wrong tenant | Check subscription parameter |
