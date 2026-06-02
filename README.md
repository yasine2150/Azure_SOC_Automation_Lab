# 🛡️ Azure Cloud-Native SOC & SOAR Automation Lab

## 📋 Project Overview
This repository documents the architecture, deployment, and operational results of a fully functional, cloud-native Security Operations Center (SOC) built on Microsoft Azure. The primary objective of this project was to design an end-to-end **Detect-to-Block automation pipeline** capable of identifying and mitigating live RDP brute-force attacks with **zero human intervention**.

By intentionally exposing a Windows Server virtual machine to the public internet, this lab attracted real-world botnet traffic, allowing for the practical configuration of Microsoft Sentinel (SIEM), Kusto Query Language (KQL) detections, and an Azure Logic App (SOAR) response playbook.

## 🏗️ Architecture & Technology Stack
* **SIEM:** Microsoft Sentinel, Log Analytics Workspace
* **SOAR:** Azure Logic Apps, Azure REST API
* **Infrastructure:** Azure Virtual Machines (Windows Server 2022), Virtual Networks (VNet), Network Security Groups (NSG)
* **Telemetry & Ingestion:** Azure Monitor Agent (AMA), Windows Security Events
* **Data Parsing & Detection:** Kusto Query Language (KQL), GeoIP Watchlists

## ⚙️ The Detect-to-Block Pipeline (Workflow)
The automated incident response pipeline was engineered with a strict 3-layer architecture:

1. **Exposure & Ingestion (The Honeypot):** A Windows Server VM (`CORP-NET-EAST`) was deployed with a deliberately permissive NSG rule exposing Port 3389 (RDP) to the internet. Windows Security Events (specifically Event ID 4625: Failed Logon) were forwarded to a Log Analytics workspace via the Azure Monitor Agent.
2. **Threat Detection (SIEM):** A custom KQL analytics rule (`Brute Force - Auto Block IP`) was scheduled in Microsoft Sentinel to trigger an incident if a single IP address generated $\ge10$ failed authentication attempts within a 5-minute window.
3. **Automated Response (SOAR):** Upon incident creation, an Azure Logic App playbook automatically executed the following steps:
   * Extracted the attacker's IP address from the Sentinel incident entities.
   * Queried the Azure REST API to read existing NSG rules and dynamically calculate the next available security priority integer.
   * Injected a surgical `Deny` rule into the NSG targeting only the attacker's IP across all ports and protocols.
   * Closed the Sentinel incident with a detailed resolution audit trail.
   * *Total execution time: < 2 minutes.*

## 📊 Live Traffic Results & Metrics
The pipeline was validated against live, unscripted threat actor botnets. Within hours of exposure, the environment successfully absorbed, analyzed, and mitigated sustained brute-force waves.

| Metric | Operational Result |
| :--- | :--- |
| **Top Attack Volume** | 39,400+ failed logons from a single source (Jordanow, Poland) |
| **Sentinel Incidents Generated** | 33+ High Severity Incidents (Mapped to MITRE ATT&CK T1110) |
| **Unique Threat Actors Blocked** | 7 discrete IPs surgically denied via API |
| **SOC Analyst Interventions** | **0 (100% Automated)** |

## 🗺️ Visual Intelligence
To provide immediate situational awareness without requiring manual KQL execution, a custom **Attack Map Workbook** was engineered. By utilizing a `ipv4_lookup` join between the ingested security events and a custom GeoIP watchlist, the workbook renders a live, interactive heatmap of global attack origins based on failure count intensity.

---
*Disclaimer: This repository represents a controlled laboratory environment. The deliberate exposure of RDP and highly permissive NSG rules were implemented strictly for the generation of educational security telemetry and should never be replicated in production environments.*
