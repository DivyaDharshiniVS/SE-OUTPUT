# AI-Based Network Intrusion Detection System
## Software Engineering Capstone — Confluence Documentation Pack: Volume 1
### Project Overview & Software Requirements Specification (SRS)

---

### 1. Document Control
* **Document Version:** 2.0.0
* **Project Title:** AI-Based Network Intrusion Detection System
* **Academic Level:** Computer Science Engineering Capstone
* **Technology Stack:** Python 3.11/3.13, Streamlit, Scikit-Learn, Pandas, SQLite, Plotly, Pytest, Docker, Kubernetes, GitHub Actions

---

### 2. Executive Summary & Problem Statement
Modern corporate and cloud computer networks face sophisticated cyber threats:
1. **Volumetric Denial of Service (DoS):** Flooding infrastructure with SYN/Smurf packets overwhelms firewalls.
2. **Reconnaissance & Port Scanning:** Stealthy probes scan ports to locate unpatched vulnerabilities.
3. **Unauthorized Incursions:** Exploits and brute-force access attempts bypass perimeter defenses.
4. **Alert Fatigue & Slow Remediation:** SOC analysts are flooded with raw packet logs without explainable AI classifications or actionable mitigation playbooks.

**Solution:** The **AI-Based Network Intrusion Detection System** addresses these vulnerabilities through an intelligent machine learning architecture:
* **Module 01: Network Traffic Analysis** — Validates NetFlow schemas (12 flow features) and visualizes traffic distributions.
* **Module 02: AI-Based Intrusion Detection** — Employs a genuine Scikit-Learn `RandomForestClassifier` yielding high accuracy, precision, and recall on held-out test splits.
* **Module 03: Security Dashboard, Alerts & Reports** — Real-time cyber defense KPIs, text-based incident alerts with actionable firewall mitigation playbooks, and SQLite audit persistence.

---

### 3. Stakeholder Profiles
| Stakeholder Role | Description | Key Needs |
|---|---|---|
| **Security Operations Center (SOC) Analyst** | Monitors ingress network traffic for anomalies | Real-time classification, confidence scores, threat categories |
| **Incident Response Engineer** | Mitigates confirmed network incursions | Actionable firewall rules, mitigation commands, packet audit trail |
| **Academic Faculty & Evaluators** | Engineering project jury and reviewers | Real Scikit-Learn ML models, zero hardcoding, automated test suite, 8 SE tools |

---

### 4. Functional Requirements (FR)

* **FR-01: Multi-Screen Navigation Hub**
  * Screen 0: Source Code Inspector with dual-pane compiler exploration.
  * Screen 7: Main Network Intrusion Platform hosting the 3 core NIDS modules.
  * Screen 3: Software Engineering Tools Dashboard hosting all 8 tools.
  * Screen 8: Network Traffic Scanner with dual-column layout, animated radar, and downloadable CSV reports.

* **FR-02: Network Traffic Ingestion & Validation (Module 01)**
  * Ingests CSV packet capture logs and validates 12 core NetFlow features.
  * Renders 4 interactive dark emerald Plotly charts for protocols, services, TCP flags, and payload bytes.

* **FR-03: Machine Learning Model Training & Inference (Module 02)**
  * Trains a Scikit-Learn `RandomForestClassifier` (100 trees).
  * Evaluates dynamically on an independent held-out 25% test split (500 records).
  * Generates interactive confusion matrix and feature importance rankings.

* **FR-04: Security Alerting & Actionable Remediation (Module 03)**
  * Synthesizes text-based alerts with threat classifications and specific firewall rules.
  * Persists scan sessions and incident alerts into local SQLite database.
  * Provides one-click CSV security audit report export.
