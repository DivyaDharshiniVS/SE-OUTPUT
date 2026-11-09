"""
test_engine.py - Automated Unit & Functional Tests
AI-Based Network Intrusion Detection System

Validates:
1. Feature extraction & NetFlow schema compatibility.
2. Scikit-Learn RandomForestClassifier model training & held-out test evaluation.
3. Batch flow inference & threat category assignment.
4. Actionable text-based security alert synthesis.
5. SQLite persistence for scan records and incident alerts.
"""

import os
import sys
import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import nids_engine
import data_manager

def run_all_tests():
    print("=" * 65)
    print("RUNNING AUTOMATED UNIT TESTS FOR AI-BASED NIDS PLATFORM")
    print("=" * 65)

    # 1. Test Feature Extraction & Preprocessing
    print("\n[Test 1] Network Flow Preprocessing & Schema Validation...")
    df_sample = nids_engine.generate_synthetic_nids_data(n_samples=50, random_seed=42)
    assert len(df_sample) == 50, "Sample dataset generation failed!"
    X, feat_names = nids_engine.preprocess_features(df_sample)
    assert X.shape[0] == 50, "Feature matrix row count mismatch!"
    assert X.shape[1] > 10, "Feature matrix column count insufficient!"
    print(f"✅ Preprocessing passed! Extracted {X.shape[1]} one-hot encoded numerical features.")

    # 2. Test Model Training & Evaluation Metrics
    print("\n[Test 2] Scikit-Learn Model Training & Held-Out Test Evaluation...")
    model, metrics, feats = nids_engine.train_nids_model()
    assert model is not None, "Model failed to train!"
    assert metrics["accuracy"] >= 0.90, f"Model accuracy too low: {metrics['accuracy']}"
    assert metrics["precision"] >= 0.85, f"Model precision too low: {metrics['precision']}"
    assert metrics["recall"] >= 0.85, f"Model recall too low: {metrics['recall']}"
    assert metrics["f1_score"] >= 0.85, f"Model F1 score too low: {metrics['f1_score']}"
    assert len(metrics["top_features"]) > 0, "No feature importances extracted!"
    print(f"✅ Model evaluation passed! Accuracy: {metrics['accuracy']*100:.2f}%, Precision: {metrics['precision']*100:.2f}%, Recall: {metrics['recall']*100:.2f}%, F1: {metrics['f1_score']*100:.2f}%")

    # 3. Test Ingress Traffic Inference & Threat Categorization
    print("\n[Test 3] Batch Ingress Flow Inference & Anomaly Detection...")
    nids_engine.create_benchmark_csv_if_missing()
    df_bench = pd.read_csv("sample_network_traffic.csv")
    results_df, summary = nids_engine.analyze_uploaded_traffic(df_bench)
    assert "predicted_label" in results_df.columns, "Predictions missing in results!"
    assert "anomaly_confidence" in results_df.columns, "Confidence scores missing!"
    assert "threat_category" in results_df.columns, "Threat categories missing!"
    assert summary["total_packets"] == len(df_bench), "Packet count mismatch in summary!"
    assert summary["malicious_count"] > 0, "No attacks detected in benchmark stream!"
    assert summary["normal_count"] > 0, "No normal traffic detected in benchmark stream!"
    print(f"✅ Inference passed! Total: {summary['total_packets']}, Normal: {summary['normal_count']}, Malicious: {summary['malicious_count']} ({summary['anomaly_rate']}%)")

    # 4. Test Text-Based Security Alert Synthesis
    print("\n[Test 4] Text-Based Security Alert Generation...")
    alerts = summary.get("alerts_list", [])
    assert len(alerts) > 0, "Expected security alerts for malicious flows!"
    first_alert = alerts[0]
    assert "alert_id" in first_alert, "Alert ID missing!"
    assert "source_ip" in first_alert, "Source IP missing in alert!"
    assert "severity" in first_alert, "Severity missing in alert!"
    assert "Mitigation:" in first_alert["alert_message"], "Actionable mitigation missing in alert text!"
    print(f"✅ Alert synthesis passed! Sample alert: {first_alert['alert_id']} [{first_alert['severity']}] - {first_alert['threat_type']}")

    # 5. Test SQLite Persistence
    print("\n[Test 5] SQLite Persistence Layer (Scans & Alerts)...")
    test_scan_ref = "TEST-SCN-001"
    ok_scan = data_manager.save_scan_record(
        scan_ref=test_scan_ref,
        total_packets=summary["total_packets"],
        normal_count=summary["normal_count"],
        malicious_count=summary["malicious_count"],
        anomaly_rate=summary["anomaly_rate"]
    )
    assert ok_scan, "Failed to save scan record into SQLite!"
    
    saved_alerts_count = data_manager.save_alerts_batch(alerts[:5], test_scan_ref)
    assert saved_alerts_count == min(5, len(alerts)), "Failed to save alerts batch into SQLite!"

    recent_scans = data_manager.get_all_scans(limit=5)
    assert len(recent_scans) > 0, "Failed to retrieve recent scans from SQLite!"
    recent_alerts = data_manager.get_recent_alerts(limit=5)
    assert len(recent_alerts) > 0, "Failed to retrieve recent alerts from SQLite!"

    stats = data_manager.get_db_stats()
    assert stats["total_scans"] > 0, "Scan count not reflected in DB stats!"
    assert stats["total_alerts"] > 0, "Alert count not reflected in DB stats!"
    print(f"✅ SQLite persistence passed! Stored scan {test_scan_ref} with {saved_alerts_count} alerts.")

    # 6. Test User Authentication & RBAC
    print("\n[Test 6] User Authentication, Role-Based Access Control & Password Hashing...")
    # Test hashing
    hash_val = data_manager.hash_password("admin123")
    assert isinstance(hash_val, str) and len(hash_val) == 64, "SHA-256 hash length incorrect!"

    # Test default admin account
    data_manager.seed_default_admin()
    admin_auth = data_manager.verify_user("admin", "admin123")
    assert admin_auth is not None, "Default demo admin verification failed!"
    assert admin_auth["role"] == "SOC Admin", "Admin role mismatch!"
    assert admin_auth["username"] == "admin", "Admin username mismatch!"

    # Test wrong password
    bad_auth = data_manager.verify_user("admin", "wrong_password_xyz")
    assert bad_auth is None, "Bad password verification should return None!"

    # Test user creation
    import time
    test_uname = f"analyst_test_{int(time.time())}"
    test_pass = "SecurePass!456"
    test_role = "SOC Analyst"
    ok_user = data_manager.create_user(test_uname, test_pass, test_role)
    assert ok_user is True, "Failed to create new user in SQLite!"

    # Test duplicate username rejection
    dup_user = data_manager.create_user(test_uname, "another_pass", test_role)
    assert dup_user is False, "Duplicate user creation should return False!"

    # Test created user verification
    analyst_auth = data_manager.verify_user(test_uname, test_pass)
    assert analyst_auth is not None, "Created user verification failed!"
    assert analyst_auth["role"] == test_role, "Created user role mismatch!"

    # Test user listing
    users_list = data_manager.get_all_users()
    assert len(users_list) >= 2, "User list count insufficient!"
    assert any(u["username"] == "admin" for u in users_list), "Admin not found in user list!"
    print(f"✅ User authentication & RBAC passed! Verified {len(users_list)} registered users with SHA-256 password security.")

    print("\n" + "=" * 65)
    print("ALL 6 NIDS ARCHITECTURAL MODULE TESTS PASSED (100% SUCCESS)!")
    print("=" * 65)

if __name__ == "__main__":
    run_all_tests()
