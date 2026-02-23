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
