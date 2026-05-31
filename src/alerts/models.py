from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if hasattr(value, "__dict__"):
        return vars(value)
    return {}


def _first(data: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return default


def _nested(data: Mapping[str, Any], path: str, default: Any = None) -> Any:
    current: Any = data
    for part in path.split("."):
        current = _as_mapping(current)
        if part not in current or current[part] is None:
            return default
        current = current[part]
    return current


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _list_or_empty(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    return [value]


@dataclass(frozen=True)
class AlertEvent:
    incident_id: str | None = None
    timestamp: str | None = None
    severity: str | None = None
    attack_type: str | None = None
    risk_score: float | int | str | None = None
    source_ip: str | None = None
    method: str | None = None
    uri: str | None = None
    message: str | None = None
    prediction_label: str | None = None
    prediction_score: float | int | str | None = None
    mitre: list[Any] = field(default_factory=list)
    matched_pattern: str | None = None
    similarity_score: float | int | str | None = None
    dashboard_url: str | None = None
    raw_log: str | None = None
    recommendations: list[Any] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_incident(cls, incident: Any) -> "AlertEvent":
        data = _as_mapping(incident)
        prediction = _as_mapping(data.get("prediction"))
        metadata = _as_mapping(data.get("metadata"))

        incident_id = _first(data, "incident_id", "_id", "event_id", "id")
        timestamp = _first(data, "timestamp", "event_time", "time", "created_at")
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()

        prediction_label = _first(data, "prediction_label", "prediction.label")
        if prediction_label is None:
            prediction_label = _first(prediction, "label")
        if prediction_label is None:
            prediction_label = _nested(data, "prediction.label")

        prediction_score = _first(data, "prediction_score", "prediction.score")
        if prediction_score is None:
            prediction_score = _first(prediction, "score")
        if prediction_score is None:
            prediction_score = _nested(data, "prediction.score")

        raw_log = _first(data, "raw_log", "raw", "raw_line")

        return cls(
            incident_id=_string_or_none(incident_id),
            timestamp=_string_or_none(timestamp),
            severity=_string_or_none(_first(data, "severity", "risk_level", "rule_severity")),
            attack_type=_string_or_none(_first(data, "attack_type", "attack", "category")),
            risk_score=_first(data, "risk_score", "score", "final_score", "rule_score"),
            source_ip=_string_or_none(_first(data, "source_ip", "ip", "client_ip", "remote_addr")),
            method=_string_or_none(_first(data, "method", "http_method", "request_method")),
            uri=_string_or_none(_first(data, "uri", "raw_uri", "original_url", "url", "path")),
            message=_string_or_none(_first(data, "message", "description", "summary")),
            prediction_label=_string_or_none(prediction_label),
            prediction_score=prediction_score,
            mitre=_list_or_empty(_first(data, "mitre", "mitre_techniques", "mitre_ids")),
            matched_pattern=_string_or_none(
                _first(data, "matched_pattern", "matched_rule", "matched_rule_id", "pattern_id")
            ),
            similarity_score=_first(data, "similarity_score", "similarity", "vector_score"),
            dashboard_url=_string_or_none(_first(data, "dashboard_url", "dashboard_link")),
            raw_log=_string_or_none(raw_log),
            recommendations=_list_or_empty(
                _first(data, "recommendations", "recommendation", "remediation", "mitigation")
            ),
            metadata=dict(metadata),
        )


@dataclass(frozen=True)
class AlertSendResult:
    channel: str
    success: bool
    message: str
    dry_run: bool = False
    error: str | None = None
