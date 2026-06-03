# 🔍 Production-Ready KQL Detection & Visualisation Queries

This document highlights the core analytical engine behind the Azure SOC lab. These Kusto Query Language (KQL) queries were designed and deployed within Microsoft Sentinel to verify ingestion telemetry, execute threat-focused filtering, and power interactive intelligence workbooks.

## 1. Initial Ingestion Verification
Following the deployment of the Data Collection Rule (DCR) and Azure Monitor Agent (AMA), this query was executed to validate that the Log Analytics workspace was actively receiving and indexing raw Windows Security Event telemetry.

```kql
SecurityEvent
```

### Analytical Objective:
Provides ground-truth confirmation that the data pipeline is functional, returning raw XML-formatted event details, timestamps, and target hostnames before any filtering is applied.

---

## 2. High-Fidelity Brute Force Detection (Scheduled Analytics Rule)
This query serves as the precise logical threshold for the automated SOAR response pipeline. It monitors the `SecurityEvent` table, clusters authentication failures by source IP within a sliding 5-minute window, and fires an alert only when a high-density attack pattern is recognized.

```kql
// Tactic: Credential Access (MITRE ATT&CK T1110)
SecurityEvent
| where EventID == 4625 // Filter exclusively for Failed Logon events
| summarize FailureCount = count() by IpAddress, bin(TimeGenerated, 5m)
| where FailureCount >= 10 // Threshold: 10 or more failures in a 5-minute window
```

### Analytical Objective:
By utilizing the `bin()` function to group events into strict intervals, this detection isolates aggressive automated script behavior from standard human error (e.g., typing a password wrong twice), minimizing false positives and alert fatigue in the SOC.

---

## 3. Threat-Focused Authentication Audit (Surgical Field Projection)
Used during active incident triage, this query discards generic system noise and maps raw log schemas down to essential interactive logon identifiers.

```kql
SecurityEvent 
| project AccountType, IpAddress, TimeGenerated, EventID, Activity 
| where AccountType == "User" // Filters out automated Machine/Service account telemetry
```

### Analytical Objective:
Limits data transfer speeds and optimizes performance across high-volume log analytics indices, allowing analysts to manually correlate failed attempts (`4625`), credential validation loops (`4776`), and elevated privilege assignments (`4672`) quickly during live triage.

---

## 4. GeoIP Threat Intelligence Enrichment (Workbook Map Engine)
This query powers the **Windows VM Attack Map** visualization by performing a stateful IP address lookup against a dynamic infrastructure watchlist.

```kql
// Ingest the GeoIP CIDR lookup infrastructure mapping table
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;

WindowsEvents
| where EventID == 4625
| order by TimeGenerated desc
// Perform cross-table IPv4 subnet validation matching
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, city_name, country_name
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = city_name, country = country_name, friendly_location = strcat(city_name, " (", country_name, ")")
```

### Analytical Objective:
Transforms flat, un-parsed string data into spatial coordinates. The query combines the output variables (`latitude`, `longitude`, `FailureCount`) into an explicit JSON array to programmatically draw the global green-to-red live attack heatmap within the Azure Sentinel portal dashboard.
