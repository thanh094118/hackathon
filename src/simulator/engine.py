from __future__ import annotations

import os
import time
import uuid
import urllib.parse
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .payloads import cycle_attack_types, get_payload, normalize_attack_type

DEFAULT_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


@dataclass
class SimulationResult:
    success: bool
    mode: str
    attack_type: str
    message: str
    event_id: str | None = None
    url: str | None = None
    http_status: int | None = None
    warning: str | None = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def build_attack_request(target_url: str, attack_type: str) -> tuple[str, dict[str, str]]:
    payload = get_payload(attack_type)
    base = urllib.parse.urlsplit(target_url)
    encoded_path = urllib.parse.quote(payload.path, safe="/")
    query_string = urllib.parse.urlencode(payload.query, doseq=True)
    full_url = urllib.parse.urlunsplit((base.scheme, base.netloc, encoded_path, query_string, ""))
    headers = {"User-Agent": payload.user_agent}
    return full_url, headers


def simulate_target_url(
    *,
    target_url: str,
    attack_type: str,
    count: int = 1,
    delay: float = 1.0,
    dry_run: bool = False,
    force: bool = True,
    timeout: float = 10.0,
) -> list[SimulationResult]:
    allowed_hosts = _allowed_hosts()
    parsed_target = urllib.parse.urlsplit(target_url)
    host = (parsed_target.hostname or "").strip().lower()
    if parsed_target.scheme not in {"http", "https"} or not host:
        return [
            SimulationResult(
                success=False,
                mode="target-url",
                attack_type=normalize_attack_type(attack_type),
                message="invalid target URL",
                error="invalid_target_url",
            )
        ]
    if host not in allowed_hosts:
        return [
            SimulationResult(
                success=False,
                mode="target-url",
                attack_type=normalize_attack_type(attack_type),
                message="target host is not allowed",
                error="host_not_allowed",
            )
        ]

    bounded_count = _bounded_count(count)
    delay_value = max(0.0, float(delay))
    run_dry = bool(dry_run)

    results: list[SimulationResult] = []
    for index, key in enumerate(cycle_attack_types(attack_type, bounded_count)):
        url, headers = build_attack_request(target_url, key)
        event_id = f"sim-http-{uuid.uuid4().hex[:16]}"

        if run_dry:
            results.append(
                SimulationResult(
                    success=True,
                    mode="target-url",
                    attack_type=key,
                    message="target-url dry-run",
                    event_id=event_id,
                    url=url,
                    metadata={"headers": headers},
                )
            )
        else:
            try:
                request = urllib.request.Request(url, method="GET", headers=headers)
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    status = int(getattr(response, "status", 0) or response.getcode())
                    response.read()
                results.append(
                    SimulationResult(
                        success=True,
                        mode="target-url",
                        attack_type=key,
                        message="attack request sent",
                        event_id=event_id,
                        url=url,
                        http_status=status,
                    )
                )
            except urllib.error.HTTPError as exc:
                # HTTP 4xx/5xx still means the request reached target server.
                results.append(
                    SimulationResult(
                        success=True,
                        mode="target-url",
                        attack_type=key,
                        message="attack request sent (http error response)",
                        event_id=event_id,
                        url=url,
                        http_status=int(exc.code),
                        error=exc.__class__.__name__,
                    )
                )
            except Exception as exc:
                results.append(
                    SimulationResult(
                        success=False,
                        mode="target-url",
                        attack_type=key,
                        message="attack request failed",
                        event_id=event_id,
                        url=url,
                        error=exc.__class__.__name__,
                    )
                )

        if index < bounded_count - 1 and delay_value > 0:
            time.sleep(delay_value)

    return results


def run_simulation(
    *,
    mode: str,
    attack_type: str,
    target_url: str | None = None,
    count: int = 1,
    delay: float = 0.0,
    dry_run: bool | None = None,
    force: bool = False,
) -> list[SimulationResult]:
    normalized_mode = str(mode or "").strip().lower()
    if normalized_mode == "target-url":
        resolved_target = target_url or os.getenv("SIMULATOR_DEFAULT_TARGET") or "http://localhost:8080"
        return simulate_target_url(
            target_url=resolved_target,
            attack_type=attack_type,
            count=count,
            delay=delay,
            dry_run=dry_run,
            force=force,
        )
    return [
        SimulationResult(
            success=False,
            mode=normalized_mode or "unknown",
            attack_type=normalize_attack_type(attack_type),
            message="unsupported simulator mode (only target-url is allowed)",
            error="unsupported_mode",
        )
    ]


def _allowed_hosts() -> set[str]:
    raw = os.getenv("SIMULATOR_ALLOWED_HOSTS", "localhost,127.0.0.1,::1")
    values = {item.strip().lower() for item in raw.split(",") if item.strip()}
    return values | DEFAULT_ALLOWED_HOSTS


def _bounded_count(requested_count: int) -> int:
    try:
        parsed = int(requested_count)
    except (TypeError, ValueError):
        parsed = 1
    max_count = _env_int("SIMULATOR_MAX_COUNT", 20)
    if parsed < 1:
        return 1
    return min(parsed, max_count)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default
