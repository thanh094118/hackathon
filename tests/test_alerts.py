from __future__ import annotations

from src.alerts import (
    AlertConfig,
    AlertDispatcher,
    AlertEvent,
    AlertSendResult,
    BaseNotifier,
    build_default_dispatcher,
    load_alert_config,
)
from src.alerts.email_notifier import EmailNotifier
from src.alerts.formatter import format_alert_text
from src.alerts.slack_notifier import SlackNotifier
from src.alerts.telegram_notifier import TelegramNotifier


def _alert() -> AlertEvent:
    return AlertEvent(
        incident_id="inc-1",
        timestamp="2026-05-31T00:00:00Z",
        severity="high",
        attack_type="sqli",
        risk_score=91,
        source_ip="10.0.0.5",
        method="GET",
        uri="/login?id=1",
        message="SQL injection attempt detected",
        prediction_label="malicious",
        prediction_score=0.97,
        mitre=["T1190"],
        matched_pattern="sqli_union_select",
        similarity_score=0.84,
        dashboard_url="http://localhost:8501",
        raw_log='10.0.0.5 - - "GET /login?id=1 HTTP/1.1" 200',
        recommendations=["Block source IP", "Review affected endpoint"],
    )


def test_alert_event_from_incident_flexible_mapping():
    event = AlertEvent.from_incident(
        {
            "_id": 123,
            "event_time": "2026-05-31T00:00:00Z",
            "risk_level": "critical",
            "category": "xss",
            "score": 88,
            "ip": "192.0.2.10",
            "http_method": "POST",
            "original_url": "/search?q=<script>",
            "prediction": {"label": "malicious", "score": 0.99},
            "raw": "raw log line",
            "mitigation": "Escape output",
            "metadata": {"source": "test"},
        }
    )

    assert event.incident_id == "123"
    assert event.timestamp == "2026-05-31T00:00:00Z"
    assert event.severity == "critical"
    assert event.attack_type == "xss"
    assert event.risk_score == 88
    assert event.source_ip == "192.0.2.10"
    assert event.method == "POST"
    assert event.uri == "/search?q=<script>"
    assert event.prediction_label == "malicious"
    assert event.prediction_score == 0.99
    assert event.raw_log == "raw log line"
    assert event.recommendations == ["Escape output"]
    assert event.metadata == {"source": "test"}


def test_alert_event_from_incident_accepts_flat_prediction_keys():
    event = AlertEvent.from_incident(
        {
            "incident_id": "inc-2",
            "source_ip": "203.0.113.4",
            "method": "GET",
            "raw_uri": "/admin",
            "prediction.label": "suspicious",
            "prediction.score": 0.77,
            "raw_log": "raw",
        }
    )

    assert event.incident_id == "inc-2"
    assert event.source_ip == "203.0.113.4"
    assert event.uri == "/admin"
    assert event.prediction_label == "suspicious"
    assert event.prediction_score == 0.77
    assert event.raw_log == "raw"


def test_load_alert_config_from_environment_mapping():
    config = load_alert_config(
        {
            "ALERTS_ENABLED": "1",
            "ALERT_DRY_RUN": "0",
            "ALERT_CHANNELS": "email, slack",
            "ALERT_DASHBOARD_URL": "http://localhost:8501",
            "ALERT_EMAIL_ENABLED": "1",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "2525",
            "SMTP_FROM": "alerts@example.com",
            "SMTP_TO": "security@example.com",
            "ALERT_SLACK_ENABLED": "1",
            "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/placeholder",
        }
    )

    assert config.alerts_enabled is True
    assert config.dry_run is False
    assert config.channels == ["email", "slack"]
    assert config.dashboard_url == "http://localhost:8501"
    assert config.smtp_port == 2525
    assert config.channel_enabled("email") is True
    assert config.channel_enabled("telegram") is False
    assert config.channel_enabled("slack") is True


def test_alert_formatter_output_contains_key_context():
    text = format_alert_text(_alert())

    assert "[HIGH] Security Incident Alert" in text
    assert "Incident: inc-1" in text
    assert "Attack: sqli" in text
    assert "Source IP: 10.0.0.5" in text
    assert "Request: GET /login?id=1" in text
    assert "Prediction: malicious / 0.97" in text
    assert "Recommendations:" in text


def test_dispatcher_disabled_mode_returns_empty_results():
    dispatcher = AlertDispatcher(AlertConfig(alerts_enabled=False), notifiers=[SuccessNotifier()])

    assert dispatcher.send(_alert()) == []


def test_dispatcher_with_fake_notifier():
    notifier = SuccessNotifier()
    dispatcher = AlertDispatcher(AlertConfig(alerts_enabled=True), notifiers=[notifier])

    results = dispatcher.send(_alert())

    assert notifier.sent is True
    assert results == [AlertSendResult("fake", True, "sent")]


def test_dispatcher_continues_if_one_notifier_fails():
    dispatcher = AlertDispatcher(
        AlertConfig(alerts_enabled=True),
        notifiers=[RaisingNotifier(), SuccessNotifier()],
    )

    results = dispatcher.send(_alert())

    assert len(results) == 2
    assert results[0].channel == "raising"
    assert results[0].success is False
    assert results[0].error == "RuntimeError"
    assert results[1].success is True


def test_email_dry_run():
    config = AlertConfig(
        alerts_enabled=True,
        dry_run=True,
        channels=["email"],
        email_enabled=True,
    )

    result = EmailNotifier(config).send(_alert())

    assert result.channel == "email"
    assert result.success is True
    assert result.dry_run is True


def test_telegram_dry_run():
    config = AlertConfig(
        alerts_enabled=True,
        dry_run=True,
        channels=["telegram"],
        telegram_enabled=True,
    )

    result = TelegramNotifier(config).send(_alert())

    assert result.channel == "telegram"
    assert result.success is True
    assert result.dry_run is True


def test_slack_dry_run():
    config = AlertConfig(
        alerts_enabled=True,
        dry_run=True,
        channels=["slack"],
        slack_enabled=True,
    )

    result = SlackNotifier(config).send(_alert())

    assert result.channel == "slack"
    assert result.success is True
    assert result.dry_run is True


def test_missing_credentials_do_not_crash():
    config = AlertConfig(
        alerts_enabled=True,
        dry_run=False,
        channels=["email", "telegram", "slack"],
        email_enabled=True,
        telegram_enabled=True,
        slack_enabled=True,
    )
    dispatcher = build_default_dispatcher(config)

    results = dispatcher.send(_alert())

    assert [result.channel for result in results] == ["email", "telegram", "slack"]
    assert all(result.success is False for result in results)
    assert all(result.error and "missing:" in result.error for result in results)


class SuccessNotifier(BaseNotifier):
    channel = "fake"

    def __init__(self) -> None:
        super().__init__(enabled=True, dry_run=False)
        self.sent = False

    def send(self, alert: AlertEvent) -> AlertSendResult:
        self.sent = True
        return AlertSendResult(self.channel, True, "sent")


class RaisingNotifier(BaseNotifier):
    channel = "raising"

    def __init__(self) -> None:
        super().__init__(enabled=True, dry_run=False)

    def send(self, alert: AlertEvent) -> AlertSendResult:
        raise RuntimeError("boom")
