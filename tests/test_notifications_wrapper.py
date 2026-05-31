from __future__ import annotations

from src.alerts import AlertSendResult
from src.notifications.alerts import send_incident_alert, should_alert_incident


def test_should_alert_incident_true_for_risk_score_threshold():
    assert should_alert_incident({"risk_score": 80}) is True
    assert should_alert_incident({"score": "95"}) is True


def test_should_alert_incident_true_for_high_or_critical_severity():
    assert should_alert_incident({"severity": "high", "risk_score": 1}) is True
    assert should_alert_incident({"risk_level": "critical"}) is True


def test_should_alert_incident_false_for_low_risk():
    assert should_alert_incident({"risk_score": 20, "severity": "low"}) is False
    assert should_alert_incident({"attack_type": "benign"}) is False


def test_send_incident_alert_uses_injected_dispatcher():
    dispatcher = FakeDispatcher()
    incident = {
        "incident_id": "inc-1",
        "risk_score": 95,
        "severity": "high",
        "source_ip": "192.0.2.10",
    }

    results = send_incident_alert(incident, dispatcher=dispatcher)

    assert dispatcher.sent is True
    assert dispatcher.alert.incident_id == "inc-1"
    assert results == [AlertSendResult("fake", True, "sent")]


def test_send_incident_alert_skips_below_threshold():
    dispatcher = FakeDispatcher()

    results = send_incident_alert({"risk_score": 10, "severity": "low"}, dispatcher=dispatcher)

    assert results == []
    assert dispatcher.sent is False


def test_send_incident_alert_catches_dispatcher_exceptions():
    results = send_incident_alert({"risk_score": 95}, dispatcher=RaisingDispatcher())

    assert len(results) == 1
    assert results[0].success is False
    assert results[0].channel == "alerts"
    assert results[0].error == "RuntimeError"


class FakeDispatcher:
    def __init__(self) -> None:
        self.sent = False
        self.alert = None

    def send(self, alert):
        self.sent = True
        self.alert = alert
        return [AlertSendResult("fake", True, "sent")]


class RaisingDispatcher:
    def send(self, alert):
        raise RuntimeError("boom")
