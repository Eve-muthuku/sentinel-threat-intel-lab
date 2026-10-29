# Build & Use Threat Intelligence in Microsoft Sentinel

A hands-on lab where I turn suspicious IPs found in my own logs into threat intelligence (TI) indicators, then use those indicators to find repeat attacker activity in Microsoft Sentinel.

**Skills practiced:** KQL, threat hunting, TI indicator management, detection engineering, Microsoft Sentinel

## Workflow

Find suspicious IPs in logs → create TI indicators → confirm they are in the table → match them in queries → build an analytics rule

## Environment

- Microsoft Sentinel on a Log Analytics workspace (Azure-based cyber range)
- Tables used: `DeviceLogonEvents`, `ThreatIntelIndicators`, `NTANetAnalytics`

## Naming convention

Every indicator is named **Malicious activity**. All queries filter on this exact name. KQL's `==` is case-sensitive, so `"Malicious Activity"` returns nothing. `=~` ignores case.

---

## Step 1: Find suspicious IPs

I looked for remote IPs with the most failed logons, a sign of brute-force attempts.

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize Count = count() by RemoteIP, ActionType
| order by Count desc
```

**My prediction:** I would be able to identify which IPs made the most failed logon attempts against the cyber range.

**What I saw:** About 1,793 distinct IPs had failed logons. The top IP had 8,253 attempts.

## Step 2: Create the TI indicators

In the Defender portal: **Microsoft Sentinel → Threat intelligence → Intel management → + Add TI object**
(`https://security.microsoft.com/sentinel/threatintelligence`)

| Field | Value |
|---|---|
| Type | IP address |
| Value | the suspicious IP |
| Name | Malicious activity |
| Confidence | 87 |
| Valid until | 23 Nov 2026 for 144.76.201.165, 31 Dec 2026 for 47.184.58.103 |

I created indicators for two IPs: `47.184.58.103` and `144.76.201.165`.

**Why 87:** I set confidence based on the number of attempted logins.

## Step 3: Confirm the indicators are in the table

```kql
ThreatIntelIndicators
| where Data.name == "Malicious activity"
| project ObservableValue, IsActive, ValidUntil
```

**My prediction:** one row per IP, `IsActive` = true, `ValidUntil` in the future.

**What I saw:** 5 rows, all active. One IP is valid until 23 November and the other until 31 December.

**Why 5 rows for 2 IPs:** `47.184.58.103` appears once (valid until 31 Dec 2026) and `144.76.201.165` appears 4 times with identical values (valid until 23 Nov 2026). The extra rows are duplicate records of the same indicator, most likely from saving it more than once. The Step 4 queries are unaffected because `make_set()` keeps only unique values.

## Step 4: Match indicators against my data

The indicator IPs are stored in a variable (`BadIPs`) and compared against other tables.

**Against network traffic**

```kql
let BadIPs = toscalar(
    ThreatIntelIndicators
    | where TimeGenerated > ago(365d)
    | where Data.name == "Malicious activity"
    | summarize make_set(ObservableValue));
NTANetAnalytics
| where isnotempty(SrcPublicIps)
| extend RemoteIP = tostring(split(SrcPublicIps, "|")[0])
| where RemoteIP in (BadIPs)
| project TimeGenerated, RemoteIP, DestPort, FlowDirection, FlowType
```

`SrcPublicIps` can hold several IPs separated by `|`, so `split(...)[0]` takes the first one.

**Result:** 3,168 inbound flows (2,559 unique after removing exact duplicates).

| RemoteIP | Port | Flows | First seen | Last seen |
|---|---|---|---|---|
| 47.184.58.103 | 22 (SSH) | 1,567 | 3 Jul 2026 | 5 Oct 2026 |
| 144.76.201.165 | 3389 (RDP) | 1,601 | 24 Jul 2026 | 26 Aug 2026 |

All flows are `Inbound` and `ExternalPublic`. One IP targeted SSH and the other RDP.

**Against logins**

```kql
let BadIPs = toscalar(
    ThreatIntelIndicators
    | where TimeGenerated > ago(365d)
    | where Data.name == "Malicious activity"
    | summarize make_set(ObservableValue));
DeviceLogonEvents
| where RemoteIP in (BadIPs)
```

**Result:** 2,713 logon events from the two IPs.

| RemoteIP | Events | Window | Targets | Accounts tried | Pattern |
|---|---|---|---|---|---|
| 47.184.58.103 | 1,983 | 25 Sep to 4 Oct 2026 | 1 Linux VM (sshd) | `root` | SSH brute force, all failed. Peak was 701 attempts on 29 Sep |
| 144.76.201.165 | 730 | 24 Jul to 24 Aug 2026 | 11 Windows hosts | 10 (administrator, admin, server, user, test, support, remote, and others) | Password spraying over NTLM |

For 144.76.201.165, failures were mostly bad passwords (554), plus 158 unauthorized logon types and 13 locked accounts.

### Step 4b: Did any attempt succeed?

```kql
let BadIPs = toscalar(
    ThreatIntelIndicators
    | where TimeGenerated > ago(365d)
    | where Data.name == "Malicious activity"
    | summarize make_set(ObservableValue));
DeviceLogonEvents
| where RemoteIP in (BadIPs)
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP
```

**Result:** 4 successful logons, all from 144.76.201.165 using the `administrator` account, on 2 Windows hosts (2 Aug and 19 Aug 2026). Two were network logons over NTLM. In a production environment, a success from a flagged IP after a spray would be escalated and investigated.

## Step 5: Turn it into analytics rules

Sentinel → Analytics → Create → Scheduled query rule. I built two rules with different severity levels.

**Rule 1: failed logons from a TI IP (Medium)**

```kql
let BadIPs = toscalar(
    ThreatIntelIndicators
    | where TimeGenerated > ago(365d)
    | where Data.name == "Malicious activity"
    | where IsActive == true
    | summarize make_set(ObservableValue));
DeviceLogonEvents
| where TimeGenerated > ago(1h)
| where ActionType == "LogonFailed"
| where RemoteIP in (BadIPs)
| project TimeGenerated, DeviceName, AccountName, RemoteIP, ActionType
```

**Rule 2: successful logon from a TI IP (High)**

```kql
let BadIPs = toscalar(
    ThreatIntelIndicators
    | where TimeGenerated > ago(365d)
    | where Data.name == "Malicious activity"
    | where IsActive == true
    | summarize make_set(ObservableValue));
DeviceLogonEvents
| where TimeGenerated > ago(1h)
| where ActionType == "LogonSuccess"
| where RemoteIP in (BadIPs)
| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP
```

| Setting | Value |
|---|---|
| Run query every | 1 hour |
| Lookup data from the last | 1 hour |
| Alert threshold | greater than 0 results |
| Entity mapping | IP → `RemoteIP`, Account → `AccountName`, Host → `DeviceName` |

**Testing note:** the last successful logon from a flagged IP was on 19 Aug 2026. With today at 29 Oct 2026, a 1-hour window returns nothing, so to test the queries I widened the time filter (for example `ago(90d)`). In production the rules keep `ago(1h)`.

**Result:** I built both rules in my Sentinel workspace and both worked.

## Findings

- **Volume:** about 1,793 IPs had failed logons, and the top IP had 8,253 attempts.
- **Two distinct attack styles:** a focused SSH brute force against `root` on one Linux VM (47.184.58.103) and a password spray across 11 Windows hosts using common usernames (144.76.201.165).
- **A success matters most:** 4 of 2,713 logon events succeeded, all for `administrator` from 144.76.201.165. That is why I added a separate high-severity rule for successes.
- **Case sensitivity broke my first queries.** I wrote `"Malicious Activity"` but created the indicator as `"Malicious activity"`. `==` returned nothing, with no error. `=~` is safer.
- **Prediction vs result:** I expected one row per IP in `ThreatIntelIndicators` but got 5 rows for 2 IPs, because `144.76.201.165` was stored 4 times.
- **Timeline gap:** network flows from 47.184.58.103 start on 3 Jul, but failed logons from that IP only start on 25 Sep.

**Timeline gap theory (untested):** the IP may have changed ownership. Traffic from 3 Jul to 24 Sep could have come from a different owner than the one that began the SSH brute force against `root` on 25 Sep.

## What I learned

- TI indicators act as a reference list of known bad actors. Detections compare live data against that list, so they stay current when indicators are added or expire, without rewriting the queries.
- `IsActive` shows whether the indicator is still valid: not expired (`ValidUntil` is in the future) and not revoked. It describes the indicator, not whether the IP is attacking right now.
- `make_set()` collapses the matching rows into one list of unique IPs, `toscalar()` turns that single result into a variable (`BadIPs`), and `in (BadIPs)` checks whether each row's IP is on the list.


