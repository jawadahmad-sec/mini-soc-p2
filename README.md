# 🛡️ Mini SOC: Entity-Aware Alert Correlation Engine

![Wazuh](https://img.shields.io/badge/Wazuh-4.14.8-blue?style=flat-square&logo=wazuh)
![Suricata](https://img.shields.io/badge/Suricata-7.0.3-red?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.12-yellow?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## 📖 Overview
A fully open-source, resource-constrained Security Operations Center (SOC) designed to detect, correlate, and prioritize internal network threats. This project addresses **alert fatigue** in small organizations by utilizing a custom, lightweight Python correlation engine that groups raw alerts into actionable incidents.

This repository serves as the **Project 2 (Lab Build)** environment, designed for high-scalability testing across multiple heterogeneous endpoints (Ubuntu, Windows, and Linux targets).

## 🚀 Key Features
*   **Entity-Aware Resolution:** Solves the "missing Source-IP" problem in Windows-native events by utilizing the cryptographic `agent.id` as the primary fallback, preventing hostname spoofing and ensuring accurate incident grouping.
*   **Multi-Vector Detection:** Integrates Suricata (Network IDS) and Wazuh (Host SIEM) to capture both network-layer scans and host-layer anomalies.
*   **Automated Risk Scoring:** Incidents are scored out of 100 based on Wazuh rule severity, alert volume, and MITRE ATT&CK presence.
*   **Massive Scalability:** Tested and validated on a **13-entity laboratory** (1 SOC-Server, 6 Ubuntu Agents, 2 Windows Targets, Kali Linux, and Metasploitable 3) running on a single consumer laptop.
*   **MITRE ATT&CK Mapping:** Full traceability from raw logs to specific adversary tactics and techniques.

## 🏗️ Architecture Stack
| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **SIEM** | Wazuh 4.14.8 | Manager, Indexer, and Dashboard for host telemetry. |
| **Network IDS** | Suricata 7.0.3 | Deep packet inspection and network alerting. |
| **Correlation** | Python 3.12 | Custom engine for entity resolution and risk scoring. |
| **Log Shipper** | Filebeat 7.10.2 | Reliable transport from Manager to Indexer. |

## 📂 Repository Structure
```text
mini-soc-p2/
├── configs/          # Wazuh and Suricata configuration files
├── dashboard/        # Django analyst dashboard code
├── docs/             # Lab documentation and setup guides
├── reports/          # Generated experiment CSV and analysis
├── rules/            # Custom Suricata rules (local.rules)
├── screenshots/      # Visual evidence of the lab and alerts
├── scripts/          # Python correlation engine and test scripts
│   ├── correlation_engine_v2.py  # Core grouping and scoring logic
│   └── test_connection.py        # OpenSearch connectivity test
├── run_scenarios.sh  # Automated MITRE ATT&CK attack script
├── requirements.txt  # Python dependencies
└── .env.example      # Environment variable template
