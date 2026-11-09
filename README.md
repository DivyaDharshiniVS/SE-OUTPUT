# AI-Based Network Intrusion Detection System
### "Real-Time Packet Inspection. Intelligent Anomaly Detection. Robust Cyber Defense."
#### Academic Software Engineering Capstone Project • Computer Science & Engineering (CSE)

[![Vercel Deployment](https://img.shields.io/badge/Vercel-Live%20Portal-black?style=for-the-badge&logo=vercel)](https://ai-nids-platform-ashy.vercel.app)
[![GitHub Repository](https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github)](https://github.com/DivyaDharshiniVS/ai-nids-platform)
[![Python 3.11](https://img.shields.io/badge/Python-3.11%20%7C%203.13-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.39-FF4B4B?style=for-the-badge&logo=streamlit)](https://streamlit.io)

🌐 **Official Live Edge Portal:** [https://ai-nids-platform-ashy.vercel.app](https://ai-nids-platform-ashy.vercel.app)  
📦 **Official GitHub Repository:** [https://github.com/DivyaDharshiniVS/ai-nids-platform](https://github.com/DivyaDharshiniVS/ai-nids-platform)

---

## 📌 Executive Summary & Project Vision

The **AI-Based Network Intrusion Detection System** is an enterprise-grade academic software application developed to detect, classify, and mitigate cyber threats across computer networks.

By combining deep packet flow inspection, machine learning feature engineering, and a genuine **Scikit-Learn Random Forest Classifier**, the platform enables security teams to:
1. **Analyze Ingress Network Traffic:** Ingest packet capture flows (CSV), extract and validate 12 core NetFlow features, and inspect interactive dark-mode distributions.
2. **Detect Incursions with Machine Learning:** Execute real-time inference using a trained Scikit-Learn `RandomForestClassifier` with dynamically computed Accuracy, Precision, Recall, F1 scores, confusion matrices, and feature importance rankings.
3. **Synthesize Text-Based Security Alerts & Mitigations:** Categorize attacks into `DoS Attack (SYN Flood / Smurf)`, `PortScan / Probe`, and `Unauthorized Access (Brute Force)` with actionable firewall mitigation playbooks and persistent SQLite audit storage.

In accordance with rigorous Software Engineering capstone requirements, this project bridges **machine learning cybersecurity engineering** with an **industry-standard development and delivery workflow** integrating:
**GitHub • Deployment • Jira • Confluence • Figma • Docker • Kubernetes • CI/CD Pipeline**.

---

## 🧭 Multi-Screen Application Architecture

The application implements a cohesive 4-screen layout with an executive Dark Emerald & Champagne Gold aesthetic:

### SCREEN 0 — Source Code Inspector (IDE Compiler View)
* Dual-pane source code and compiler explorer:
  * Left: Project file tree, architecture metadata, and component statistics.
  * Right: High-contrast syntax viewer with line numbers and file switching.

### SCREEN 7 — Main Network Intrusion Platform
* Hosts the **EXACTLY THREE Core NIDS Modules**:
  * `MODULE 01 — Network Traffic Analysis` (NetFlow ingestion, schema validation, 4 dark Plotly charts)
  * `MODULE 02 — AI-Based Intrusion Detection` (Scikit-Learn model training, held-out test evaluation, confusion matrix)
  * `MODULE 03 — Security Dashboard, Alerts & Reports` (Defense KPIs, text-based incident alerts with mitigations, SQLite history)

### SCREEN 8 — Network Traffic Scanner (Dual-Column Scanner)
* Preserves the executive dual-column layout:
  * Left: Emerald CSV upload card, 1-click benchmark loader, and Times New Roman Champagne Gold quote.
  * Right: Dark Emerald Scanner Matrix with animated pulsing radar, progress bar, real-time alert ticker, intrusion table, and downloadable CSV report.

### SCREEN 3 — Software Engineering Tools Dashboard
* Accessible in the top navigation under **"🛠️ Software Engineering Tools"**, providing dedicated inspection panels for:
  1. **GitHub** — Repository status, branch strategy, `.gitignore`, staged assets, and push runbook.
  2. **Deployment** — Streamlit Community Cloud and Render hosting descriptors, healthchecks, and URL verification.
  3. **Jira** — Interactive backlog viewer for 7 Epics, 14 User Stories with Acceptance Criteria, and 4 Sprints via `jira_backlog_import.csv`.
  4. **Confluence** — In-app documentation reader for all 4 technical volumes (`confluence_docs/`).
  5. **Figma** — Interactive design system viewer featuring palette tokens, typography scales, and wireframes (`figma_specs/`).
  6. **Docker** — Multi-stage `Dockerfile` syntax viewer, non-root security explanation, and CLI commands.
  7. **Kubernetes** — Manifest inspection for `Deployment`, `Service`, `ConfigMap`, and `HPA` with scaling runbook.
  8. **CI/CD Pipeline** — GitHub Actions `.github/workflows/ci.yml` runner and live Pytest verification evidence.

---

## 🗂️ Complete Project Directory Structure

```text
SE OUTPUT/
├── app.py                      # Main Streamlit application with 4-tab navigation lifecycle
├── nids_engine.py              # Scikit-Learn Random Forest Classifier, preprocessing & alerts
├── sample_network_traffic.csv  # 120-packet benchmark ingress capture for 1-click testing
├── data_manager.py             # SQLite persistence engine for scan_history & security_alerts
├── se_tools_dashboard.py       # 8 SE Capstone Tools Management Dashboard
├── requirements.txt            # Python dependencies (scikit-learn, streamlit, pandas, etc.)
├── Dockerfile                  # Production multi-stage secure containerization
├── render.yaml                 # Render PaaS deployment descriptor
├── Procfile                    # Web server startup declaration
├── .github/workflows/ci.yml    # GitHub Actions automated CI/CD pipeline
├── k8s/                        # Kubernetes manifests (Deployment, Service, HPA, ConfigMap)
├── confluence_docs/            # 4 volumes of comprehensive engineering documentation
├── figma_specs/                # UI/UX design tokens, typography scales, and wireframe specs
└── tests/                      # Automated Pytest suite (tests/test_nids.py)
```

---

## 🚀 Quickstart & Verification

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run automated test suite
pytest tests/test_nids.py -v

# 3. Launch the platform locally
streamlit run app.py
```
