from __future__ import annotations

from email.utils import formatdate
from typing import Any

from .models import AlertEvent


def _present(value: Any) -> bool:
    return value is not None and value != "" and value != []


def _string(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    return str(value)


def _csv(values: list[Any]) -> str:
    return ", ".join(_string(value) for value in values if _present(value))


def _truncate(value: str, limit: int = 500) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def format_alert_text(alert: AlertEvent) -> str:
    severity = (alert.severity or "unknown").upper()
    title = f"[{severity}] Security Incident Alert"
    lines = [title]

    fields = [
        ("Incident", alert.incident_id),
        ("Time", alert.timestamp),
        ("Attack", alert.attack_type),
        ("Risk score", alert.risk_score),
        ("Source IP", alert.source_ip),
        ("Request", " ".join(item for item in [alert.method, alert.uri] if item)),
        ("Prediction", _prediction(alert)),
        ("MITRE", _csv(alert.mitre)),
        ("Matched pattern", alert.matched_pattern),
        ("Similarity", alert.similarity_score),
        ("Dashboard", alert.dashboard_url),
        ("Message", alert.message),
    ]
    for label, value in fields:
        if _present(value):
            lines.append(f"{label}: {_string(value)}")

    if alert.recommendations:
        lines.append("Recommendations:")
        for recommendation in alert.recommendations:
            if _present(recommendation):
                lines.append(f"- {_string(recommendation)}")

    if alert.raw_log:
        lines.append(f"Raw log: {_truncate(alert.raw_log)}")

    return "\n".join(lines)


def format_email_subject(alert: AlertEvent) -> str:
    severity = (alert.severity or "unknown").upper()
    incident = alert.incident_id or "unknown"
    attack_type = alert.attack_type or "security event"
    return f"[{severity}] {attack_type} incident {incident}"


def format_email_body(alert: AlertEvent) -> str:
    return format_alert_text(alert) + "\n\nGenerated: " + formatdate(localtime=False)


def format_slack_payload(alert: AlertEvent) -> dict[str, str]:
    return {"text": format_alert_text(alert)}


def _prediction(alert: AlertEvent) -> str | None:
    values = [value for value in [alert.prediction_label, alert.prediction_score] if _present(value)]
    if not values:
        return None
    return " / ".join(_string(value) for value in values)
