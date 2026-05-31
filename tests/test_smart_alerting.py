from __future__ import annotations

import unittest
from datetime import datetime, timezone, timedelta
from typing import Any

from src.alerts.models import CorrelatedIncident, AlertEvent
from src.alerts.correlation_engine import CorrelationEngine
from src.alerts.incident_manager import IncidentManager
from src.alerts.dynamic_baseline import DynamicBaseline
from src.alerts.fp_suppression import FPSuppressionEngine
from src.notifications.alerts import process_batch_alerts


class TestCorrelationEngine(unittest.TestCase):
    def test_correlation_by_ip_and_window(self):
        engine = CorrelationEngine(window_minutes=5)
        
        # 3 events within same window and IP
        alerts = [
            {"source_ip": "192.168.1.10", "timestamp": "2026-05-31T12:01:00Z", "uri": "/api/v1", "attack_type": "sqli", "risk_score": 85.0},
            {"source_ip": "192.168.1.10", "timestamp": "2026-05-31T12:02:00Z", "uri": "/api/v2", "attack_type": "xss", "risk_score": 75.0},
            # Different IP, same window
            {"source_ip": "10.0.0.5", "timestamp": "2026-05-31T12:03:00Z", "uri": "/login", "attack_type": "brute_force", "risk_score": 90.0},
            # Same IP, different window
            {"source_ip": "192.168.1.10", "timestamp": "2026-05-31T12:12:00Z", "uri": "/logout", "attack_type": "sqli", "risk_score": 40.0},
        ]
        
        correlated = engine.correlate_alerts(alerts)
        self.assertEqual(len(correlated), 3)
        
        # Verify grouping
        groups = {c.source_ips[0]: c for c in correlated}
        self.assertIn("10.0.0.5", groups)
        self.assertIn("192.168.1.10", groups)
        
        # For 192.168.1.10, we should have two correlated incidents due to different windows
        ip_192_incidents = [c for c in correlated if c.source_ips[0] == "192.168.1.10"]
        self.assertEqual(len(ip_192_incidents), 2)

    def test_behavior_classification(self):
        # Reconnaissance classification: 5 different endpoints
        engine = CorrelationEngine(window_minutes=5, recon_endpoint_threshold=3)
        alerts = [
            {"source_ip": "1.1.1.1", "timestamp": "2026-05-31T12:01:00Z", "uri": f"/path/{i}", "attack_type": "scanning", "risk_score": 50.0}
            for i in range(4)
        ]
        correlated = engine.correlate_alerts(alerts)
        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0].behavior_type, "reconnaissance")
        self.assertIn("Quét thăm dò", correlated[0].title)

        # Brute Force classification: high count against 1 endpoint
        engine = CorrelationEngine(window_minutes=5, brute_force_threshold=5, recon_endpoint_threshold=10)
        alerts = [
            {"source_ip": "2.2.2.2", "timestamp": "2026-05-31T12:01:00Z", "uri": "/login", "attack_type": "brute_force", "risk_score": 60.0}
            for _ in range(6)
        ]
        correlated = engine.correlate_alerts(alerts)
        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0].behavior_type, "brute_force")
        self.assertIn("Tấn công dồn dập", correlated[0].title)


class TestIncidentManager(unittest.TestCase):
    def test_in_memory_cooldown_and_merging(self):
        mgr = IncidentManager(db=None, cooldown_minutes=30)
        
        # Define basic CorrelatedIncident
        now = datetime.now(timezone.utc)
        incident = CorrelatedIncident(
            correlation_id="corr-1",
            title="Tấn công SQLi từ IP 1.1.1.1",
            behavior_type="single",
            source_ips=["1.1.1.1"],
            target_endpoints=["/api/users"],
            attack_types=["sqli"],
            evidence_count=1,
            evidence_ids=["evt-1"],
            max_risk_score=85.0,
            severity="high",
            window_start=now,
            window_end=now + timedelta(minutes=5),
            events=[{"event_id": "evt-1", "risk_score": 85.0}]
        )
        
        # First process: should create a new incident (NEW_ALERT)
        res1 = mgr.process_correlated_incident(incident)
        self.assertEqual(res1.action, "NEW_ALERT")
        self.assertIsNotNone(res1.incident_id)
        
        # Second process (same IP, within cooldown window): should merge (MERGED)
        new_incident = CorrelatedIncident(
            correlation_id="corr-2",
            title="Tấn công SQLi từ IP 1.1.1.1",
            behavior_type="single",
            source_ips=["1.1.1.1"],
            target_endpoints=["/api/admin"],
            attack_types=["xss"],
            evidence_count=1,
            evidence_ids=["evt-2"],
            max_risk_score=92.0,
            severity="high",
            window_start=now + timedelta(minutes=10),
            window_end=now + timedelta(minutes=15),
            events=[{"event_id": "evt-2", "risk_score": 92.0}]
        )
        
        res2 = mgr.process_correlated_incident(new_incident)
        self.assertEqual(res2.action, "MERGED")
        self.assertEqual(res2.incident_id, res1.incident_id)
        
        # Check that the in-memory document holds the merged details
        merged_doc = mgr._in_memory_store[res1.incident_id]
        self.assertEqual(merged_doc["evidence_count"], 2)
        self.assertEqual(merged_doc["max_risk_score"], 92.0)
        self.assertIn("sqli", merged_doc["attack_types"])
        self.assertIn("xss", merged_doc["attack_types"])
        self.assertIn("/api/admin", merged_doc["target_endpoints"])

    def test_severity_override_in_cooldown(self):
        mgr = IncidentManager(db=None, cooldown_minutes=30)
        now = datetime.now(timezone.utc)
        
        # Incident with low severity
        incident_low = CorrelatedIncident(
            correlation_id="corr-1",
            title="Suspicious recon from 1.1.1.1",
            behavior_type="single",
            source_ips=["1.1.1.1"],
            target_endpoints=["/somepath"],
            attack_types=["recon"],
            evidence_count=1,
            evidence_ids=["evt-1"],
            max_risk_score=40.0,
            severity="low",
            window_start=now,
            window_end=now + timedelta(minutes=5),
            events=[{"event_id": "evt-1", "risk_score": 40.0}]
        )
        
        res1 = mgr.process_correlated_incident(incident_low)
        self.assertEqual(res1.action, "NEW_ALERT")
        inc_id = res1.incident_id
        
        # New incident with high severity within cooldown
        incident_high = CorrelatedIncident(
            correlation_id="corr-2",
            title="SQLi dump attempt from 1.1.1.1",
            behavior_type="single",
            source_ips=["1.1.1.1"],
            target_endpoints=["/api/users"],
            attack_types=["sqli"],
            evidence_count=1,
            evidence_ids=["evt-2"],
            max_risk_score=95.0,
            severity="critical",  # critical > low
            window_start=now + timedelta(minutes=10),
            window_end=now + timedelta(minutes=15),
            events=[{"event_id": "evt-2", "risk_score": 95.0}]
        )
        
        res2 = mgr.process_correlated_incident(incident_high)
        # Should override cooldown and trigger NEW_ALERT
        self.assertEqual(res2.action, "NEW_ALERT")
        self.assertEqual(res2.incident_id, inc_id)
        
        # Verify the saved incident has the updated severity and risk score
        updated = mgr._in_memory_store[inc_id]
        self.assertEqual(updated["severity"], "critical")
        self.assertEqual(updated["max_risk_score"], 95.0)
        self.assertEqual(updated["evidence_count"], 2)


class TestDynamicBaseline(unittest.TestCase):
    def test_baseline_calculation_and_checks(self):
        # We test with None db (no MongoDB connection) so it falls back to defaults
        baseline = DynamicBaseline(db=None, sigma_multiplier=3.0, min_floor=0)
        
        # Get hour of week
        now = datetime.now(timezone.utc)
        hour = baseline.get_hour_of_week(now)
        self.assertTrue(0 <= hour <= 167)
        
        # Test baseline check with default mean=5, std=2 -> threshold = 5 + 3*2 = 11
        # 1. Under threshold
        res1 = baseline.should_alert_above_baseline(10, now)
        self.assertFalse(res1.should_alert)
        self.assertEqual(res1.threshold, 11.0)
        
        # 2. Over threshold
        res2 = baseline.should_alert_above_baseline(15, now)
        self.assertTrue(res2.should_alert)
        self.assertEqual(res2.deviation_ratio, 5.0)  # (15 - 5) / 2 = 5.0

    def test_hard_minimum_floor(self):
        # Even if current count (e.g. 5) is above dynamic threshold (e.g. 1.0),
        # it should not alert if below min_floor (e.g. 10).
        now = datetime.now(timezone.utc)
        
        # 1. Under floor, even if over dynamic baseline
        # (Default fallback mean=5.0, std=2.0 -> threshold = 11.0. If we use sigma_multiplier=-2.0 -> threshold = 1.0)
        baseline_low_sigma = DynamicBaseline(db=None, sigma_multiplier=-2.0, min_floor=10)
        res1 = baseline_low_sigma.should_alert_above_baseline(5, now) # count 5 > threshold 1.0 but < min_floor 10
        self.assertFalse(res1.should_alert)
        
        # 2. Over floor and over dynamic baseline
        res2 = baseline_low_sigma.should_alert_above_baseline(12, now) # count 12 > threshold 1.0 and >= min_floor 10
        self.assertTrue(res2.should_alert)

    def test_endpoint_grouping(self):
        from src.alerts.dynamic_baseline import get_endpoint_group
        self.assertEqual(get_endpoint_group("/api/v1/auth/login"), "api_v1")
        self.assertEqual(get_endpoint_group("/api/db-backup"), "sensitive")
        self.assertEqual(get_endpoint_group("/admin/settings"), "sensitive")
        self.assertEqual(get_endpoint_group("/index.html"), "index.html")
        self.assertEqual(get_endpoint_group(""), "root")

    def test_endpoint_specific_min_floor(self):
        # We check with None db so it uses IN_MEMORY_FLOORS
        # For sensitive: min_floor = 2
        # For api: min_floor = 20
        # For default/others: min_floor = 50
        baseline = DynamicBaseline(db=None, sigma_multiplier=-2.0, min_floor=50)
        now = datetime.now(timezone.utc)

        # 1. sensitive group: count = 3 (exceeds threshold 1.0 and min_floor 2)
        res_sens = baseline.should_alert_above_baseline(3, now, endpoint_group="sensitive")
        self.assertTrue(res_sens.should_alert)

        # 2. api group: count = 10 (exceeds threshold 1.0 but below min_floor 20)
        res_api = baseline.should_alert_above_baseline(10, now, endpoint_group="api")
        self.assertFalse(res_api.should_alert)


class TestFPSuppressionEngine(unittest.TestCase):
    def test_no_db_fallback(self):
        engine = FPSuppressionEngine(db=None, similarity_threshold=0.90)
        now = datetime.now(timezone.utc)
        incident = CorrelatedIncident(
            correlation_id="corr-1",
            title="Tấn công",
            behavior_type="single",
            source_ips=["1.1.1.1"],
            target_endpoints=["/"],
            attack_types=["sqli"],
            evidence_count=1,
            evidence_ids=["evt-1"],
            max_risk_score=80.0,
            severity="high",
            window_start=now,
            window_end=now + timedelta(minutes=5),
            events=[{"event_id": "evt-1", "embedding": [0.1, 0.2, 0.3]}]
        )
        # Should gracefully return is_false_positive=False because no collection is available
        res = engine.triage(incident)
        self.assertFalse(res.is_false_positive)
        self.assertIn("collection not available", res.reason)


class TestSmartAlertingIntegration(unittest.TestCase):
    def test_process_batch_alerts_flow_mock(self):
        # Full integration run with db=None (dry-run mode)
        alerts = [
            {"source_ip": "1.2.3.4", "timestamp": "2026-05-31T12:01:00Z", "uri": "/login", "attack_type": "brute_force", "risk_score": 85.0, "event_id": "evt-1"},
            {"source_ip": "1.2.3.4", "timestamp": "2026-05-31T12:02:00Z", "uri": "/login", "attack_type": "brute_force", "risk_score": 88.0, "event_id": "evt-2"},
        ]
        
        # With db=None and custom dispatcher to count sends
        class MockDispatcher:
            def __init__(self):
                self.sent = []
            def send(self, event):
                self.sent.append(event)
                return []
                
        dispatcher = MockDispatcher()
        
        # Run batch processing
        result = process_batch_alerts(
            alerts=alerts,
            db=None,
            dispatcher=dispatcher,
            cooldown_minutes=30,
            threshold=80,
            sigma_multiplier=-2.0,
            min_floor=1
        )
        
        # Verify batch result
        self.assertEqual(result.processed_count, 2)
        self.assertEqual(result.correlated_count, 1)
        self.assertEqual(result.alert_sent_count, 1)
        self.assertEqual(result.merged_count, 0)
        self.assertEqual(result.suppressed_count, 0)
        
        self.assertEqual(len(dispatcher.sent), 1)
        self.assertEqual(dispatcher.sent[0].source_ip, "1.2.3.4")
        self.assertEqual(dispatcher.sent[0].risk_score, 88.0)

    def test_process_batch_alerts_endpoint_group_suppression(self):
        # 1. sensitive endpoint alerts: count = 3. Since min_floor for sensitive is 2, it should alert.
        alerts_sensitive = [
            {"source_ip": "1.1.1.1", "timestamp": "2026-05-31T12:01:00Z", "uri": "/api/db-backup", "attack_type": "sqli", "risk_score": 85.0, "event_id": "evt-1"},
            {"source_ip": "1.1.1.1", "timestamp": "2026-05-31T12:02:00Z", "uri": "/api/db-backup", "attack_type": "sqli", "risk_score": 88.0, "event_id": "evt-2"},
            {"source_ip": "1.1.1.1", "timestamp": "2026-05-31T12:03:00Z", "uri": "/api/db-backup", "attack_type": "sqli", "risk_score": 90.0, "event_id": "evt-3"},
        ]
        
        # 2. root endpoint alerts: count = 3. Since min_floor for root is 100, it should be suppressed.
        alerts_root = [
            {"source_ip": "2.2.2.2", "timestamp": "2026-05-31T12:01:00Z", "uri": "/", "attack_type": "brute_force", "risk_score": 85.0, "event_id": "evt-4"},
            {"source_ip": "2.2.2.2", "timestamp": "2026-05-31T12:02:00Z", "uri": "/", "attack_type": "brute_force", "risk_score": 88.0, "event_id": "evt-5"},
            {"source_ip": "2.2.2.2", "timestamp": "2026-05-31T12:03:00Z", "uri": "/", "attack_type": "brute_force", "risk_score": 90.0, "event_id": "evt-6"},
        ]

        class MockDispatcher:
            def __init__(self):
                self.sent = []
            def send(self, event):
                self.sent.append(event)
                return []
                
        # Process sensitive
        disp_sens = MockDispatcher()
        res_sens = process_batch_alerts(
            alerts=alerts_sensitive,
            db=None,
            dispatcher=disp_sens,
            cooldown_minutes=30,
            threshold=80,
            sigma_multiplier=-2.0,
            min_floor=50  # Global is 50, but sensitive group overrides it to 2!
        )
        self.assertEqual(res_sens.alert_sent_count, 1) # Allowed because sensitive min_floor is 2

        # Process root
        disp_root = MockDispatcher()
        res_root = process_batch_alerts(
            alerts=alerts_root,
            db=None,
            dispatcher=disp_root,
            cooldown_minutes=30,
            threshold=80,
            sigma_multiplier=-2.0,
            min_floor=50  # Global is 50, but root group overrides it to 100!
        )
        self.assertEqual(res_root.alert_sent_count, 0) # Suppressed because 3 < 100 floor
        self.assertEqual(res_root.suppressed_count, 1)

    def test_smokescreen_attack_priority_scoring(self):
        engine = CorrelationEngine(window_minutes=5)
        # 1 sensitive alert (score 75), 10 root alerts (score 95)
        alerts = [
            {"source_ip": "1.1.1.1", "timestamp": "2026-05-31T12:01:00Z", "uri": "/api/db-backup", "attack_type": "sqli", "risk_score": 75.0, "event_id": "evt-sens"},
        ] + [
            {"source_ip": "1.1.1.1", "timestamp": "2026-05-31T12:01:10Z", "uri": "/static/image.png", "attack_type": "xss", "risk_score": 95.0, "event_id": f"evt-root-{i}"}
            for i in range(10)
        ]
        
        correlated = engine.correlate_alerts(alerts)
        self.assertEqual(len(correlated), 1)
        inc = correlated[0]
        # Risk score must be determined by the most sensitive group (sensitive), which has score 75.0
        self.assertEqual(inc.max_risk_score, 75.0)
        self.assertEqual(inc.severity, "high")

    def test_merged_incident_recalculates_priority_score(self):
        mgr = IncidentManager(db=None, cooldown_minutes=30)
        now = datetime.now(timezone.utc)
        
        # Base incident: root alerts (score 85.0 -> high)
        incident_root = CorrelatedIncident(
            correlation_id="corr-1",
            title="Tấn công root",
            behavior_type="single",
            source_ips=["1.1.1.1"],
            target_endpoints=["/index.html"],
            attack_types=["xss"],
            evidence_count=1,
            evidence_ids=["evt-root"],
            max_risk_score=85.0,
            severity="high",
            window_start=now,
            window_end=now + timedelta(minutes=5),
            events=[{"event_id": "evt-root", "risk_score": 85.0, "uri": "/index.html"}]
        )
        
        res1 = mgr.process_correlated_incident(incident_root)
        inc_id = res1.incident_id
        
        # New incident within cooldown: sensitive alert (score 65.0 -> medium)
        incident_sens = CorrelatedIncident(
            correlation_id="corr-2",
            title="Tấn công sensitive",
            behavior_type="single",
            source_ips=["1.1.1.1"],
            target_endpoints=["/api/db-backup"],
            attack_types=["sqli"],
            evidence_count=1,
            evidence_ids=["evt-sens"],
            max_risk_score=65.0,
            severity="medium",
            window_start=now + timedelta(minutes=5),
            window_end=now + timedelta(minutes=10),
            events=[{"event_id": "evt-sens", "risk_score": 65.0, "uri": "/api/db-backup"}]
        )
        
        # Process and merge
        res2 = mgr.process_correlated_incident(incident_sens)
        self.assertEqual(res2.action, "MERGED")
        self.assertEqual(res2.incident_id, inc_id)
        
        # Verify the merged incident's score is updated using the priority-based score of combined evidence
        merged_doc = mgr._in_memory_store[inc_id]
        # Sensitive has priority over root, so score becomes 65.0 and severity becomes medium
        self.assertEqual(merged_doc["max_risk_score"], 65.0)
        self.assertEqual(merged_doc["severity"], "medium")
