# ⚡ SOAR Playbook: Automated Threat Mitigation

This document outlines the architecture and execution logic of the custom Azure Logic App deployed in this SOC environment. The playbook serves as the enforcement arm of the SIEM, designed to ingest High-Severity brute-force incidents and autonomously block the attacker's IP address at the network edge.

## 🔄 Workflow Overview
The playbook executes sequentially without human intervention. The total execution time from incident creation to network block is consistently **under 2 minutes**.

```text
[Trigger] Microsoft Sentinel Incident
   ↓
[Step 1]  Delay (45 seconds)
   ↓
[Step 2]  Entities - Get IPs
   ↓
[Step 3]  Initialize Variable (MaxPriority = 100)
   ↓
[Step 4]  HTTP GET: Fetch Existing NSG Rules
   ↓
[Step 5]  For Each (Read Phase): Compute highest existing rule priority
   ↓
[Step 6]  Delay (5 seconds)
   ↓
[Step 7]  For Each (Write Phase): HTTP PUT Deny Rule per Attacker IP
   ↓
[Step 8]  Update Sentinel Incident (Close & Audit)
```

---

## 🛠️ Step-by-Step Execution Logic

### 1. The Trigger & Entity Propagation Delay
* **Trigger:** Listens specifically for `incident-creation` webhooks from Microsoft Sentinel, passing the alert payload to the Logic App. Concurrency is limited to 1 to prevent race conditions during NSG rule modification.
* **45-Second Delay:** Sentinel APIs require a brief window to fully commit related entity metadata (like IP addresses) to the database. This delay ensures the playbook does not query for IPs before they are fully available.

### 2. Entity Extraction
The playbook calls the Sentinel API (`/entities/ip`) using a Managed Service Identity (MSI) to parse the incident payload and extract the raw attacker IP addresses into a structured JSON array.

### 3. Safe NSG Rule Insertion (The "Read" Phase)
Azure Network Security Group (NSG) rules require unique priority integers. Hardcoding a priority risks overwriting an existing rule or causing the API to reject the request. 
1. **Initialize Variable:** A tracking integer (`MaxPriority`) is set to a baseline of 100.
2. **HTTP GET:** The playbook queries the Azure Resource Manager API to retrieve the current state of the target NSG (`CORP-NET-EAST-nsg`).
3. **Compute Loop:** The playbook iterates through every existing rule. If a rule's priority is higher than the current `MaxPriority`, the variable is updated. By the end of the loop, the playbook knows exactly where to safely insert the new block rule (`MaxPriority + 1`).

### 4. API Rate Limiting Buffer
* **5-Second Delay:** Placed between the Read (GET) and Write (PUT) phases to prevent hitting Azure Resource Manager API throttling limits (HTTP 429 errors).

### 5. Surgical Blocking (The "Write" Phase)
For every attacker IP extracted in Step 2, the playbook issues an authenticated `HTTP PUT` request to the Azure REST API to create a new, surgical Deny rule.

**API Payload Design:**
```json
{
  "properties": {
    "protocol": "*",
    "sourcePortRange": "*",
    "destinationPortRange": "*",
    "sourceAddressPrefix": "@{item()?['Address']}",
    "destinationAddressPrefix": "*",
    "access": "Deny",
    "priority": "@add(variables('MaxPriority'), 1)",
    "direction": "Inbound",
    "description": "Auto-blocked by Sentinel Playbook LOG-SOC-lab"
  }
}
```
*Design Note: The rule drops all protocols across all ports for the specific offending IP, effectively neutralizing the threat actor's ability to pivot to other exposed services.*

### 6. Incident Closure & Auditing
Once the network block is confirmed by the Azure API, the playbook calls back to Microsoft Sentinel to close the loop:
* **Status:** Closed
* **Classification:** `TruePositive - SuspiciousActivity`
* **Audit Trail:** Injects a closing comment detailing that the Logic App successfully neutralized the threat. This keeps the SOC queue clean and maintains strict accountability.

---
### 🔐 Security & Authentication
* **Zero-Credential Architecture:** This Logic App utilizes a **System-Assigned Managed Identity (MSI)** scoped strictly to the target Resource Group. No API keys, secrets, or passwords are hardcoded or stored in the playbook, eliminating credential leakage risks.
