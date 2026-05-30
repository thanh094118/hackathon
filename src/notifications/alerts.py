from __future__ import annotations

from typing import Any, Mapping

from src.alerts import AlertEvent, AlertSendResult, build_default_dispatcher


HIGH_SEVERITIES = {"high", "critical"}


def should_alert_incident(incident: Mapping[str, Any], threshold: int = 80) -> bool:
    risk_score = _risk_score(incident)
    if risk_score is not None and risk_score >= float(threshold):
        return True

    severity = _first(incident, "severity", "risk_level", "rule_severity")
    if severity is not None and str(severity).strip().lower() in HIGH_SEVERITIES:
        return True

    return False


def send_incident_alert(
    incident: Mapping[str, Any],
    threshold: int = 80,
    dispatcher: Any | None = None,
) -> list[AlertSendResult]:
    if not should_alert_incident(incident, threshold=threshold):
        return []

    try:
        resolved_dispatcher = dispatcher or build_default_dispatcher()
        alert = AlertEvent.from_incident(incident)
        return list(resolved_dispatcher.send(alert))
    except Exception as exc:
        return [
            AlertSendResult(
                channel="alerts",
                success=False,
                message="incident alert failed",
                dry_run=False,
                error=exc.__class__.__name__,
            )
        ]


def _risk_score(incident: Mapping[str, Any]) -> float | None:
    value = _first(incident, "risk_score", "score", "final_score", "rule_score")
    if value is None:
        prediction = incident.get("prediction")
        if isinstance(prediction, Mapping):
            value = prediction.get("risk_score")

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _first(incident: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in incident and incident[key] not in (None, ""):
            return incident[key]
    return None
