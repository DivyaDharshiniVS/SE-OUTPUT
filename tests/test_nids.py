"""
tests/test_nids.py - Pytest Test Suite for AI-Based Network Intrusion Detection System
Academic Project: AI-Based Network Intrusion Detection System
"""

import os
import pytest
import pandas as pd
import nids_engine
import data_manager

class TestNIDSEngine:
    """Comprehensive test suite for the Machine Learning NIDS engine."""

    def test_feature_preprocessing(self):
        """Verify feature matrix generation and one-hot encoding."""
        df_sample = nids_engine.generate_synthetic_nids_data(n_samples=60, random_seed=42)
        assert len(df_sample) == 60
        X, feat_names = nids_engine.preprocess_features(df_sample)
        assert X.shape[0] == 60
        assert X.shape[1] >= 15
        assert isinstance(feat_names, list)

    def test_model_training_and_dynamic_metrics(self):
        """Verify model trains on train set and dynamically evaluates on held-out test set."""
        model, metrics, feats = nids_engine.train_nids_model()
        assert model is not None
        assert 0.90 <= metrics["accuracy"] <= 1.00
        assert 0.85 <= metrics["precision"] <= 1.00
        assert 0.85 <= metrics["recall"] <= 1.00
        assert 0.85 <= metrics["f1_score"] <= 1.00
        assert len(metrics["confusion_matrix"]) == 2
        assert len(feats) > 0

    def test_traffic_analysis_and_anomaly_detection(self):
        """Verify batch packet classification and statistical summary."""
        nids_engine.create_benchmark_csv_if_missing()
        df_bench = pd.read_csv("sample_network_traffic.csv")
        results_df, summary = nids_engine.analyze_uploaded_traffic(df_bench)

        assert "predicted_label" in results_df.columns
        assert "anomaly_confidence" in results_df.columns
        assert "threat_category" in results_df.columns
        assert summary["total_packets"] == len(df_bench)
        assert summary["malicious_count"] > 0
        assert summary["normal_count"] > 0
        assert 0.0 <= summary["anomaly_rate"] <= 100.0

    def test_security_alert_synthesis(self):
        """Verify text-based security alert creation with severities and mitigations."""
        df_bench = pd.read_csv("sample_network_traffic.csv")
        results_df, summary = nids_engine.analyze_uploaded_traffic(df_bench)
        alerts = summary.get("alerts_list", [])

        assert len(alerts) > 0
        for alert in alerts:
            assert "alert_id" in alert
            assert "severity" in alert
            assert "threat_type" in alert
            assert "Mitigation:" in alert["alert_message"]
            assert alert["severity"] in ["Critical", "High", "Medium", "Info"]

    def test_sqlite_persistence_scans_and_alerts(self):
        """Verify storing and retrieving scan records and alerts in SQLite database."""
        data_manager.init_db()
        test_scan_ref = "PYTEST-SCN-001"
        ok_scan = data_manager.save_scan_record(
            scan_ref=test_scan_ref,
            total_packets=100,
            normal_count=70,
            malicious_count=30,
            anomaly_rate=30.0
        )
        assert ok_scan is True

        sample_alerts = [
            {
                "alert_id": "ALT-PT-001",
                "severity": "Critical",
                "threat_type": "DoS Attack (SYN Flood)",
                "source_ip": "192.168.1.105",
                "destination_ip": "10.0.0.5",
                "service": "http",
                "confidence": 0.98,
                "alert_message": "CRITICAL THREAT: High-volume SYN flood detected. Mitigation: Enable SYN cookie defense on edge firewall."
            }
        ]
        saved_count = data_manager.save_alerts_batch(sample_alerts, test_scan_ref)
        assert saved_count == 1

        scans = data_manager.get_all_scans(limit=10)
        assert any(s["scan_ref"] == test_scan_ref for s in scans)

        recent_alerts = data_manager.get_recent_alerts(limit=10)
        assert any(a["alert_ref"] == "ALT-PT-001" for a in recent_alerts)

    def test_user_authentication_and_rbac(self):
        """Verify user registration, SHA-256 password hashing, and authentication."""
        data_manager.init_db()
        data_manager.seed_default_admin()

        # 1. Verify default admin
        admin = data_manager.verify_user("admin", "admin123")
        assert admin is not None
        assert admin["role"] == "SOC Admin"
        assert admin["username"] == "admin"

        # 2. Verify invalid login
        assert data_manager.verify_user("admin", "incorrect_pwd") is None
        assert data_manager.verify_user("nonexistent_user", "12345") is None

        # 3. Create new user
        import time
        test_user = f"pytest_analyst_{int(time.time())}"
        test_pass = "P@ssword123!"
        ok = data_manager.create_user(test_user, test_pass, "Incident Responder")
        assert ok is True

        # 4. Reject duplicate user
        assert data_manager.create_user(test_user, "other_pass", "SOC Analyst") is False

        # 5. Verify credentials of new user
        user_info = data_manager.verify_user(test_user, test_pass)
        assert user_info is not None
        assert user_info["role"] == "Incident Responder"
        assert user_info["username"] == test_user

        # 6. Verify user list
        users = data_manager.get_all_users()
        assert any(u["username"] == test_user for u in users)

    def test_automated_user_manual_pdf_generation(self):
        """Verify automated generation of the publication-grade User Manual PDF."""
        import manual_generator
        pdf_bytes = manual_generator.generate_nids_user_manual_pdf()
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 5000, "PDF size is unexpectedly small!"
        assert pdf_bytes.startswith(b"%PDF-"), "Generated file does not match PDF magic header!"

    def test_static_user_manual_pdf_loader(self):
        """Verify the uploaded official 6-page static User Manual PDF is present and loaded."""
        import app
        pdf_bytes = app.get_user_manual_pdf_bytes()
        assert pdf_bytes is not None, "Static User Manual PDF not found!"
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 100000, f"PDF file size unexpectedly small ({len(pdf_bytes)} bytes)!"
        assert pdf_bytes.startswith(b"%PDF-"), "File does not match PDF magic header!"
