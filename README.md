1. Objective

To design, implement, and validate a custom brute-force detection use case in Microsoft Sentinel. The primary goal was to detect high-velocity failed authentication attempts against Microsoft Entra ID (formerly Azure AD) user accounts, automatically generate security alerts, and streamline the incident response process.

2. Scenario & Threat Model

A simulated brute-force attack was conducted against a test user account to validate the detection logic and alert generation pipeline. The exercise focused on identifying:

Volume-based Anomalies: Multiple failed login attempts occurring within a short, defined timeframe.
Source-Based Patterns: A high density of failures originating from a single source IP address targeting a specific user.
This scenario maps directly to the threat of credential stuffing or password guessing attacks (MITRE ATT&CK T1110).

3. Tools & Technologies

SIEM Platform: Microsoft Sentinel
Data Source: Microsoft Entra ID Sign-in Logs (SigninLogs)
Query Language: Kusto Query Language (KQL)
Threat Intelligence Framework: MITRE ATT&CK
4. Detection Logic & KQL Implementation

A custom analytics rule was created in Microsoft Sentinel using the following KQL query. The query identifies all failed sign-in attempts (ResultType != 0), aggregates them by user, source IP, and 5-minute time bins, then filters for thresholds indicating malicious activity.

Detection Logic Breakdown:

Step 1: Filter for all failed sign-in events (ResultType != 0).
Step 2: Aggregate counts by user, source IP, and 5-minute time windows.
Step 3: Retain only results where failed attempts meet or exceed the threshold (≥5).
Analytics Rule Settings:

Rule Frequency: Run query every 5 minutes.
Lookback Period: Look at data from the last 5 minutes.
Alert Threshold: Generate alert when query results > 0 (i.e., when any row meets the ≥5 condition).
KQL Query (queries/brute-force.kql):

kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count()
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
Query Explanation:

Component	Purpose
where ResultType != 0	Filters for all failed sign-in attempts (non-zero result codes)
summarize FailedAttempts = count()	Counts the number of failures
by UserPrincipalName, IPAddress	Groups by specific user and source IP
bin(TimeGenerated, 5m)	Creates 5-minute time windows for aggregation
where FailedAttempts >= 5	Threshold filter—alerts on 5+ failures in 5 minutes
