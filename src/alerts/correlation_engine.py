from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from .models import CorrelatedIncident


def calculate_priority_risk_score(events: list[dict[str, Any]]) -> float:
    """
    Calculates the risk score for a group of events based on context sensitivity.
    We isolate the context of sensitive, api, default, and root endpoints.
    The risk score will be the maximum score of the events in the most sensitive group present.
    """
    if not events:
        return 0.0

    from src.alerts.dynamic_baseline import get_endpoint_group

    # Group alerts/events by their endpoint group
    alerts_by_group = defaultdict(list)
    for a in events:
        request_obj = a.get("request")
        uri = ""
        if isinstance(request_obj, dict):
            uri = request_obj.get("uri") or ""
        if not uri:
            uri = a.get("uri") or a.get("original_url") or ""
        grp = get_endpoint_group(uri)
        alerts_by_group[grp].append(a)

    def get_group_priority_key(g: str) -> int:
        if g == "sensitive":
            return 0
        if g.startswith("api"):
            return 1
        if g == "root":
            return 3
        return 2  # default / others

    chosen_group = None
    min_priority = 999
    for grp in alerts_by_group.keys():
        pri = get_group_priority_key(grp)
        if pri < min_priority:
            min_priority = pri
            chosen_group = grp

    if chosen_group is None:
        # Fallback to absolute max of all events
        scores = []
        for a in events:
            val = a.get("risk_score") or a.get("score") or 0.0
            try:
                scores.append(float(val))
            except (ValueError, TypeError):
                pass
        return max(scores) if scores else 0.0

    # Get max risk of the chosen group
    scores = []
    for a in alerts_by_group[chosen_group]:
        val = a.get("risk_score") or a.get("score") or 0.0
        try:
            scores.append(float(val))
        except (ValueError, TypeError):
            pass
    return max(scores) if scores else 0.0


class CorrelationEngine:
    """Groups stateless alerts into correlated incidents based on Time, Entity, and Behavior."""

    def __init__(
        self,
        window_minutes: int = 5,
        recon_endpoint_threshold: int = 5,
        brute_force_threshold: int = 15,
        multi_vector_threshold: int = 2,
    ) -> None:
        self.window_minutes = window_minutes
        self.recon_endpoint_threshold = recon_endpoint_threshold
        self.brute_force_threshold = brute_force_threshold
        self.multi_vector_threshold = multi_vector_threshold

    def _parse_time(self, timestamp_str: str | None) -> datetime:
        if not timestamp_str:
            return datetime.now(timezone.utc)
        try:
            # Try to handle ISO formats with Z or offset
            if timestamp_str.endswith("Z"):
                timestamp_str = timestamp_str[:-1] + "+00:00"
            return datetime.fromisoformat(timestamp_str)
        except Exception:
            try:
                # Handle Apache format if it leaks through
                # e.g., 31/May/2026:12:00:00 +0000
                from email.utils import parsedate_to_datetime
                return parsedate_to_datetime(timestamp_str)
            except Exception:
                return datetime.now(timezone.utc)

    def _get_window_bucket(self, dt: datetime) -> datetime:
        # Convert to UTC to be safe
        dt_utc = dt.astimezone(timezone.utc)
        # Calculate start of window
        minute = (dt_utc.minute // self.window_minutes) * self.window_minutes
        return dt_utc.replace(minute=minute, second=0, microsecond=0)

    def correlate_alerts(self, alerts: list[dict[str, Any]]) -> list[CorrelatedIncident]:
        """
        Groups alerts by source_ip and time window.
        Analyzes behavioral characteristics within each group.
        """
        if not alerts:
            return []

        # Buckets: (source_ip, window_start_dt) -> list of alert dicts
        buckets: dict[tuple[str, datetime], list[dict[str, Any]]] = defaultdict(list)

        for alert in alerts:
            ip = str(alert.get("source_ip") or alert.get("ip") or "unknown_ip")
            ts_str = alert.get("timestamp") or alert.get("event_time")
            dt = self._parse_time(ts_str)
            window_start = self._get_window_bucket(dt)
            buckets[(ip, window_start)].append(alert)

        correlated_incidents: list[CorrelatedIncident] = []

        for (ip, window_start), group_alerts in buckets.items():
            window_end = window_start + timedelta(minutes=self.window_minutes)

            # Analyze properties of the group
            uris = [str(a.get("uri") or a.get("original_url") or "") for a in group_alerts]
            uris = [u for u in uris if u]
            unique_endpoints = set(uris)

            attack_types = [str(a.get("attack_type") or a.get("category") or "") for a in group_alerts]
            attack_types = [t for t in attack_types if t and t.lower() not in {"normal", "benign"}]
            unique_attack_types = set(attack_types)

            event_ids = [str(a.get("event_id") or a.get("_id") or "") for a in group_alerts]
            event_ids = [eid for eid in event_ids if eid]

            max_risk = calculate_priority_risk_score(group_alerts)

            evidence_count = len(group_alerts)

            # Determine behavior classification
            # 1. Reconnaissance: Scanning many different endpoints
            # 2. Brute Force: High volume against few endpoints
            # 3. Multi-vector: Different attack types
            if len(unique_endpoints) >= self.recon_endpoint_threshold:
                behavior_type = "reconnaissance"
                title = f"Quét thăm dò diện rộng từ IP {ip}"
            elif evidence_count >= self.brute_force_threshold:
                behavior_type = "brute_force"
                title = f"Tấn công dồn dập (Brute Force) từ IP {ip}"
            elif len(unique_attack_types) >= self.multi_vector_threshold:
                behavior_type = "multi_vector"
                title = f"Tấn công đa phương thức (Multi-vector) từ IP {ip}"
            else:
                behavior_type = "single"
                primary_attack = attack_types[0] if attack_types else "Bất thường bảo mật"
                title = f"Phát hiện hành vi {primary_attack} từ IP {ip}"

            # Resolve overall severity
            if max_risk >= 90:
                severity = "critical"
            elif max_risk >= 70:
                severity = "high"
            elif max_risk >= 40:
                severity = "medium"
            else:
                severity = "low"

            # Create a unique correlation ID
            # e.g., MD5 of (ip, window_start, behavior_type)
            hasher = hashlib.md5()
            hasher.update(f"{ip}:{window_start.isoformat()}:{behavior_type}".encode())
            correlation_id = f"corr-{hasher.hexdigest()[:12]}"

            correlated_incidents.append(
                CorrelatedIncident(
                    correlation_id=correlation_id,
                    title=title,
                    behavior_type=behavior_type,
                    source_ips=[ip],
                    target_endpoints=list(unique_endpoints),
                    attack_types=list(unique_attack_types),
                    evidence_count=evidence_count,
                    evidence_ids=event_ids,
                    max_risk_score=max_risk,
                    severity=severity,
                    window_start=window_start,
                    window_end=window_end,
                    events=group_alerts,
                )
            )

        return correlated_incidents
