# sentinel-brute-force-detection-lab
Microsoft Sentinel detection engineering lab – brute force detection using KQL.
This lab demonstrates how to design and validate a brute-force detection rule using Microsoft Sentinel and Azure AD sign-in logs.
Azure AD → Log Analytics Workspace → Microsoft Sentinel → Scheduled Analytics Rule → Alert → Incident

## Environment Setup

### 1. Log Analytics Workspace Creation

- Navigated to Azure Portal
- Searched for **Log Analytics Workspaces**
- Clicked **Create**
- Selected subscription
- Created resource group
- Selected region (West Europe)
- Named workspace: <sentinel-weu-lab-01>

Purpose:
The workspace stores and indexes log data used by Microsoft Sentinel.

---

### 2. Microsoft Sentinel Enablement

- Opened Microsoft Sentinel from Azure Portal
- Selected the created Log Analytics Workspace
- Clicked **Add Microsoft Sentinel**

Purpose:
Sentinel was enabled to provide SIEM capabilities on top of the workspace.

---

### 3. Azure AD Sign-In Logs Connector

- Opened Microsoft Sentinel
- Navigated to **Data Connectors**
- Selected **Microsoft Entra ID**
- Enabled **Sign-in logs**
- Clicked **Apply Changes**

Purpose:
This allows Azure AD authentication logs to flow into the workspace for detection use cases.

## Detection Logic

The detection query used in this lab is available in:

`/queries/brute-force.kql`

### Logic Breakdown

**ResultType != 0**

In Azure AD sign-in logs, ResultType = 0 indicates a successful login.
Filtering with ResultType != 0 isolates failed authentication attempts.

**bin(TimeGenerated, 5m)**

The bin() function groups events into 5-minute time windows.
This allows detection of multiple failed attempts occurring within a short time frame.

**FailedAttempts >= 5**

The threshold triggers the rule when 5 or more failed logins occur for the same user and IP within 5 minutes.
This behavior is consistent with brute-force attack patterns.

## Validation and Testing

### Step 1 – Simulated Brute-Force Behavior

To simulate a brute-force attack scenario:

- Opened a private browser session
- Attempted multiple failed logins against a test user account
- Ensured attempts occurred within a 5-minute window

Purpose:
To generate failed authentication logs in Azure AD.
### Step 2 – Waited for Scheduled Rule Execution

The analytics rule was configured to run every 5 minutes.
After generating failed login attempts, I waited for the rule evaluation cycle to complete.
### Step 3 – Verified Alert Generation

After the rule executed:

- Confirmed that an alert was generated
- Verified that the alert contained the affected user and IP address
- ### Step 4 – Verified Incident Creation

Incident creation was enabled in the rule configuration.
Confirmed that the alert was automatically grouped into an incident.
### Step 5 – Investigated Entity Mapping

Opened the generated incident and reviewed:

- Mapped account entity
- Source IP address
- Related log entries

Entity mapping enabled enriched investigation context inside Sentinel.

![Incident Screenshot](screenshots/incident.jpg)

## Lessons Learned

- Detection rules require proper log ingestion before deployment.
- Evaluation frequency affects incident timing.
- Lower thresholds increase alert noise.
- Entity mapping improves investigation context.
