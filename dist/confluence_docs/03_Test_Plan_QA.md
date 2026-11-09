# AI-Based Network Intrusion Detection System
## Software Engineering Capstone — Confluence Documentation Pack: Volume 3
### Quality Assurance & Automated Test Verification Plan

---

### 1. Test Strategy Overview
The testing architecture ensures that every layer of the NIDS platform is verified through automated unit tests with Pytest:
* **Feature Extraction & Schema Validation:** Checks one-hot categorical encoding and numeric vector dimensions.
* **Model Training & Evaluation:** Validates that Scikit-Learn `RandomForestClassifier` achieves >90% accuracy and F1 score on held-out test data.
* **Ingress Packet Classification:** Validates batch inference and threat categorization.
* **Alert Synthesis:** Verifies severity tags, vector attribution, and actionable mitigation text.
* **Database Persistence:** Confirms ACID transactions in SQLite for `scan_history` and `security_alerts`.

---

### 2. Automated Test Execution Evidence
```text
============================= test session starts =============================
platform win32 -- Python 3.13.14, pytest-9.1.1, pluggy-1.7.0
rootdir: C:\...\SE OUTPUT
plugins: anyio-4.15.1
collected 5 items

tests/test_nids.py::TestNIDSEngine::test_feature_preprocessing PASSED    [ 20%]
tests/test_nids.py::TestNIDSEngine::test_model_training_and_dynamic_metrics PASSED [ 40%]
tests/test_nids.py::TestNIDSEngine::test_traffic_analysis_and_anomaly_detection PASSED [ 60%]
tests/test_nids.py::TestNIDSEngine::test_security_alert_synthesis PASSED [ 80%]
tests/test_nids.py::TestNIDSEngine::test_sqlite_persistence_scans_and_alerts PASSED [100%]

============================== 5 passed in 6.09s ==============================
```

**Status:** 100% Pass Rate across all unit, algorithmic, and database integration tests.
