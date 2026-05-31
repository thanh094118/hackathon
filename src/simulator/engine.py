from __future__ import annotations

import os
import time
import uuid
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from src.notifications.alerts import send_incident_alert
from src.simulator.payloads import PAYLOADS, get_payload, normalize_attack_type

try:
    from pymongo import MongoClient

    HAS_PYMONGO = True
except Exception:  # pragma: no cover - optional dependency safety
    MongoClient = None  # type: ignore[assignment]
    HAS_PYMONGO = False


DEFAULT_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass
class SimulationResult:
    success: bool
    mode: str
    attack_type: str
    message: str
    event_id: str | None = None
    inserted_request_id: str | None = None
    inserted_incident_id: str | None = None
    http_status: int | None = None
    alert_results: list[Any] = field(default_factory=list)
    error: str | None = None


def build_simulated_event(attack_type: str, source_ip: str | None = None) -> dict[str, Any]:
    payload = get_payload(attack_type)
    now = datetime.now(timezone.utc).isoformat()
    event_id = f"sim-{uuid.uuid4().hex[:16]}"
    ip = source_ip or "192.0.2.10"

    return {
        "event_id": event_id,
        "timestamp": now,
        "ip": ip,
        "source_ip": ip,
        "method": payload.method,
        "http_method": payload.method,
        "uri": payload.uri,
        "raw_uri": payload.uri,
        "original_url": payload.uri,
        "raw": payload.raw_request,
        "raw_log": payload.raw_request,
        "attack_type": payload.attack_type,
        "risk_score": payload.risk_score,
        "severity": payload.severity,
        "prediction": {
            "label": "malicious",
            "score": payload.prediction_score,
        },
        "mitre": list(payload.mitre),
        "matched_pattern": payload.matched_pattern,
        "message": f"Simulated {payload.display_name} attack",
        "recommendations": list(payload.recommendations),
        "source": "attack_simulator",
        "is_simulated": True,
    }


def simulate_direct_mongo(
    *,
    attack_type: str,
    count: int = 1,
    source_ip: str | None = None,
    db: Any | None = None,
    uri: str | None = None,
    database_name: str | None = None,
    send_alerts: bool = True,
    dry_run: bool = False,
    alert_dispatcher: Any | None = None,
    max_count: int | None = None,
) -> list[SimulationResult]:
    checked_count = _bounded_count(count, max_count=max_count)
    if checked_count is None:
        return [_count_error("direct-mongo", attack_type, count, max_count=max_count)]

    client = None
    try:
        if dry_run:
            return [
                SimulationResult(
                    True,
                    "direct-mongo",
                    normalize_attack_type(attack_type),
                    "direct-mongo dry-run",
                    event_id=str(build_simulated_event(attack_type, source_ip=source_ip).get("event_id")),
                )
                for _ in range(checked_count)
            ]

        if db is None:
            if not HAS_PYMONGO:
                return [
                    SimulationResult(
                        False,
                        "direct-mongo",
                        attack_type,
                        "pymongo is not installed",
                        error="missing_pymongo",
                    )
                ]
            resolved_uri = uri or os.getenv("MONGODB_URI")
            resolved_db = (
                database_name
                or os.getenv("MONGODB_DB_NAME")
                or os.getenv("MONGODB_DATABASE")
                or "security_logs"
            )
            if not resolved_uri:
                return [
                    SimulationResult(
                        False,
                        "direct-mongo",
                        attack_type,
                        "MongoDB is not configured",
                        error="missing_mongodb_uri",
                    )
                ]
            client = MongoClient(resolved_uri)
            db = client[resolved_db]

        results: list[SimulationResult] = []
        for _ in range(checked_count):
            event = build_simulated_event(attack_type, source_ip=source_ip)
            incident = _incident_from_event(event)

            request_result = db["requests"].insert_one(event)
            incident_result = db["incidents"].insert_one(incident)

            alert_results = []
            if send_alerts:
                alert_results = send_incident_alert(incident, dispatcher=alert_dispatcher)

            results.append(
                SimulationResult(
                    True,
                    "direct-mongo",
                    normalize_attack_type(attack_type),
                    "simulated event inserted",
                    event_id=str(event.get("event_id")),
                    inserted_request_id=str(getattr(request_result, "inserted_id", "")) or None,
                    inserted_incident_id=str(getattr(incident_result, "inserted_id", "")) or None,
                    alert_results=alert_results,
                )
            )
        return results
    except Exception as exc:
        return [
            SimulationResult(
                False,
                "direct-mongo",
                normalize_attack_type(attack_type),
                "direct mongo simulation failed",
                error=exc.__class__.__name__,
            )
        ]
    finally:
        if client is not None:
            client.close()


def simulate_target_url(
    *,
    attack_type: str,
    target_url: str,
    count: int = 1,
    delay: float = 0.0,
    dry_run: bool | None = None,
    allowed_hosts: list[str] | set[str] | None = None,
    max_count: int | None = None,
) -> list[SimulationResult]:
    checked_count = _bounded_count(count, max_count=max_count)
    if checked_count is None:
        return [_count_error("target-url", attack_type, count, max_count=max_count)]

    payload = get_payload(attack_type)
    allowed = _allowed_hosts(allowed_hosts)
    parsed = urllib.parse.urlsplit(target_url)
    host = parsed.hostname or ""

    if parsed.scheme not in {"http", "https"} or not host:
        return [
            SimulationResult(
                False,
                "target-url",
                normalize_attack_type(attack_type),
                "target URL must be an HTTP or HTTPS URL",
                error="invalid_target_url",
            )
        ]

    if not _is_host_allowed(host, allowed):
        return [
            SimulationResult(
                False,
                "target-url",
                normalize_attack_type(attack_type),
                "target host is not allowed",
                error="host_not_allowed",
            )
        ]

    resolved_dry_run = _env_bool("SIMULATOR_DRY_RUN", default=True) if dry_run is None else bool(dry_run)
    url = _join_target_url(target_url, payload.uri)

    results: list[SimulationResult] = []
    for index in range(checked_count):
        event_id = f"sim-http-{uuid.uuid4().hex[:16]}"
        if resolved_dry_run:
            results.append(
                SimulationResult(
                    True,
                    "target-url",
                    normalize_attack_type(attack_type),
                    "target-url dry-run",
                    event_id=event_id,
                )
            )
        else:
            try:
                request = urllib.request.Request(url, method=payload.method)
                with urllib.request.urlopen(request, timeout=10) as response:
                    status = int(getattr(response, "status", 0) or response.getcode())
                    response.read()
                results.append(
                    SimulationResult(
                        True,
                        "target-url",
                        normalize_attack_type(attack_type),
                        "target-url request sent",
                        event_id=event_id,
                        http_status=status,
                    )
                )
            except Exception as exc:
                results.append(
                    SimulationResult(
                        False,
                        "target-url",
                        normalize_attack_type(attack_type),
                        "target-url request failed",
                        event_id=event_id,
                        error=exc.__class__.__name__,
                    )
                )
        if index < checked_count - 1 and delay > 0:
            time.sleep(float(delay))

    return results


def simulate_attack(
    *,
    mode: str,
    attack_type: str,
    count: int = 1,
    delay: float = 0.0,
    source_ip: str | None = None,
    target_url: str | None = None,
    dry_run: bool | None = None,
    send_alerts: bool = True,
    db: Any | None = None,
    alert_dispatcher: Any | None = None,
) -> list[SimulationResult]:
    normalized_mode = str(mode or "").strip().lower()
    checked_count = _bounded_count(count)
    if checked_count is None:
        return [_count_error(normalized_mode or "unknown", attack_type, count)]

    attack_types = _expand_attack_types(attack_type, count=checked_count)
    if normalized_mode == "direct-mongo":
        results: list[SimulationResult] = []
        for item in attack_types:
            results.extend(
                simulate_direct_mongo(
                    attack_type=item,
                    count=1,
                    source_ip=source_ip,
                    db=db,
                    send_alerts=send_alerts,
                    dry_run=bool(dry_run),
                    alert_dispatcher=alert_dispatcher,
                )
            )
        return results

    if normalized_mode == "target-url":
        resolved_target = target_url or os.getenv("SIMULATOR_DEFAULT_TARGET") or "http://localhost:8080"
        resolved_dry_run = _env_bool("SIMULATOR_DRY_RUN", default=True) if dry_run is None else bool(dry_run)
        results = []
        for index, item in enumerate(attack_types):
            results.extend(
                simulate_target_url(
                    attack_type=item,
                    target_url=resolved_target,
                    count=1,
                    delay=0.0,
                    dry_run=resolved_dry_run,
                )
            )
            if index < len(attack_types) - 1 and delay > 0:
                time.sleep(float(delay))
        return results

    return [
        SimulationResult(
            False,
            normalized_mode or "unknown",
            attack_type,
            "unsupported simulator mode",
            error="unsupported_mode",
        )
    ]


def _incident_from_event(event: Mapping[str, Any]) -> dict[str, Any]:
    incident_id = f"sim-inc-{uuid.uuid4().hex[:16]}"
    return {
        "incident_id": incident_id,
        "event_id": incident_id,
        "request_event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "ip": event.get("ip"),
        "source_ip": event.get("source_ip"),
        "method": event.get("method"),
        "uri": event.get("uri"),
        "raw": event.get("raw"),
        "raw_log": event.get("raw_log"),
        "attack_type": event.get("attack_type"),
        "risk_score": event.get("risk_score"),
        "severity": event.get("severity"),
        "prediction": dict(event.get("prediction") or {}),
        "mitre": list(event.get("mitre") or []),
        "matched_pattern": event.get("matched_pattern"),
        "message": event.get("message"),
        "recommendations": list(event.get("recommendations") or []),
        "status": "open",
        "source": "attack_simulator",
        "is_simulated": True,
    }


def _expand_attack_types(attack_type: str, *, count: int) -> list[str]:
    normalized = normalize_attack_type(attack_type)
    if normalized != "all":
        return [normalized] * max(1, int(count))

    keys = list(PAYLOADS)
    return [keys[index % len(keys)] for index in range(max(1, int(count)))]


def _bounded_count(count: int, *, max_count: int | None = None) -> int | None:
    try:
        value = int(count)
    except (TypeError, ValueError):
        return None
    configured_max = max_count if max_count is not None else _env_int("SIMULATOR_MAX_COUNT", 20)
    if value < 1 or value > int(configured_max):
        return None
    return value


def _count_error(mode: str, attack_type: str, count: int, *, max_count: int | None = None) -> SimulationResult:
    configured_max = max_count if max_count is not None else _env_int("SIMULATOR_MAX_COUNT", 20)
    return SimulationResult(
        False,
        mode,
        normalize_attack_type(attack_type),
        f"count must be between 1 and {configured_max}",
        error="invalid_count",
    )


def _allowed_hosts(allowed_hosts: list[str] | set[str] | None) -> set[str]:
    if allowed_hosts is not None:
        values = allowed_hosts
    else:
        raw = os.getenv("SIMULATOR_ALLOWED_HOSTS", "localhost,127.0.0.1")
        values = [item.strip() for item in raw.split(",")]

    allowed = {str(item).strip().lower() for item in values if str(item).strip()}
    return allowed | DEFAULT_ALLOWED_HOSTS


def _is_host_allowed(host: str, allowed_hosts: set[str]) -> bool:
    return host.strip().lower() in allowed_hosts


def _join_target_url(target_url: str, payload_uri: str) -> str:
    base = urllib.parse.urlsplit(target_url)
    payload = urllib.parse.urlsplit(payload_uri)
    path = urllib.parse.quote(payload.path or "/", safe="/")
    query = urllib.parse.quote(payload.query, safe="=&")
    return urllib.parse.urlunsplit(
        (
            base.scheme,
            base.netloc,
            path,
            query,
            "",
        )
    )


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default
