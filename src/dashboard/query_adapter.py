from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency
    load_dotenv = None

try:
    from pymongo import MongoClient

    HAS_PYMONGO = True
except Exception:  # pragma: no cover - optional dependency
    MongoClient = None  # type: ignore[assignment]

    HAS_PYMONGO = False

try:
    from src.scoring import mongodb_queries
except Exception:  # pragma: no cover - keep dashboard import-safe
    mongodb_queries = None  # type: ignore[assignment]


_ENV_TRUE = {"1", "true", "yes", "y", "on"}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in _ENV_TRUE


def _ensure_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, datetime):
        return _ensure_aware_utc(value)

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None

    text = str(value).strip()
    if not text:
        return None

    try:
        # Supports values like 2026-01-01T12:00:00Z on modern Python.
        return _ensure_aware_utc(datetime.fromisoformat(text))
    except Exception:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            parsed = datetime.strptime(text, fmt)
            return _ensure_aware_utc(parsed)
        except ValueError:
            continue

    return None


def _timestamp_to_text(value: Any) -> str:
    parsed = _parse_timestamp(value)
    if parsed is not None:
        return parsed.isoformat()
    return "" if value is None else str(value)


def _safe_number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return int(default)


def _get_nested(record: Mapping[str, Any], dotted_path: str) -> Any:
    current: Any = record
    for segment in dotted_path.split("."):
        if not isinstance(current, Mapping):
            return None
        if segment not in current:
            return None
        current = current.get(segment)
    return current


def _first_non_empty(record: Mapping[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _get_nested(record, path)
        if value in (None, "", []):
            continue
        return value
    return None


def _normalize_attack_type(value: Any) -> str:
    if value is None:
        return "Unknown"
    if isinstance(value, list):
        if not value:
            return "Unknown"
        value = value[0]
    text = str(value).strip()
    return text if text else "Unknown"


def _normalize_label(record: Mapping[str, Any]) -> str:
    raw = _first_non_empty(record, "final_label", "prediction.label", "label", "ml_label")
    if raw is None:
        return "unknown"
    text = str(raw).strip().lower()
    if not text:
        return "unknown"
    return text


def _extract_prediction_score(record: Mapping[str, Any]) -> float:
    value = _first_non_empty(
        record,
        "prediction.score",
        "prediction.confidence",
        "ml_attack_probability",
        "ml_confidence",
        "score",
    )
    if value is None:
        # Fallback: derive from risk_score (0-100) when ML fields are absent
        risk = _first_non_empty(record, "risk_score", "rule_score")
        if risk is not None:
            return max(0.0, min(_safe_number(risk) / 100.0, 1.0))
        return 0.0
    score = _safe_number(value)
    if score > 1.0:
        score = score / 100.0
    return max(0.0, min(score, 1.0))


def _extract_risk_score(record: Mapping[str, Any]) -> int:
    value = _first_non_empty(record, "risk_score", "rule_score", "prediction.risk_score")
    if value is None:
        score = _extract_prediction_score(record)
        return _safe_int(score * 100)
    return _safe_int(value)


def _extract_severity(record: Mapping[str, Any], risk_score: int) -> str:
    raw = _first_non_empty(record, "severity", "rule_severity", "risk_level")
    if raw is not None:
        text = str(raw).strip().lower()
        if text:
            return text

    if risk_score >= 90:
        return "critical"
    if risk_score >= 75:
        return "high"
    if risk_score >= 50:
        return "medium"
    if risk_score > 0:
        return "low"
    return "unknown"


def _is_malicious_record(record: Mapping[str, Any]) -> bool:
    label = _normalize_label(record)
    if label in {"malicious", "suspicious", "attack", "attacker", "anomaly", "anomalous"}:
        return True

    attack_type = _normalize_attack_type(_first_non_empty(record, "attack_type", "prediction.attack_type"))
    if attack_type.lower() not in {"unknown", "", "none", "normal", "benign"}:
        return True

    return _extract_risk_score(record) >= 70


def _extract_detection_sources(record: Mapping[str, Any]) -> List[str]:
    raw_sources = _first_non_empty(record, "detection_sources")
    sources: List[str] = []

    if isinstance(raw_sources, str):
        raw_sources = [raw_sources]
    if isinstance(raw_sources, (list, tuple, set)):
        for value in raw_sources:
            text = str(value or "").strip().lower()
            if text and text not in sources:
                sources.append(text)

    if sources:
        return sources

    if record.get("matched_rule_ids") or _safe_int(record.get("rule_score"), 0) > 0:
        sources.append("rules")
    ml_label = str(record.get("ml_label") or "").strip().lower()
    if ml_label in {"attack", "malicious", "suspicious"} or record.get("ml_should_alert"):
        sources.append("ml")
    if _safe_int(record.get("risk_bonus"), 0) > 0:
        sources.append("features")

    return sources


def _normalize_request_record(record: Mapping[str, Any]) -> Dict[str, Any]:
    incident_id = _first_non_empty(record, "incident_id", "event_id", "_id")
    event_id = _first_non_empty(record, "event_id", "_id")

    risk_score = _extract_risk_score(record)
    prediction_score = _extract_prediction_score(record)

    normalized = {
        "incident_id": str(incident_id) if incident_id is not None else str(event_id) if event_id is not None else "",
        "event_id": str(event_id) if event_id is not None else "",
        "timestamp": _timestamp_to_text(_first_non_empty(record, "timestamp", "time", "@timestamp", "created_at")),
        "ip": str(_first_non_empty(record, "ip", "source_ip", "client_ip", "c_ip") or "Unknown"),
        "method": str(_first_non_empty(record, "method", "http_method", "verb", "cs_method") or "-"),
        "uri": str(_first_non_empty(record, "uri", "original_url", "raw_uri", "url", "request_uri") or "-"),
        "attack_type": _normalize_attack_type(_first_non_empty(record, "attack_type", "prediction.attack_type", "ml_attack_type")),
        "risk_score": risk_score,
        "prediction_score": round(prediction_score, 4),
        "severity": _extract_severity(record, risk_score),
        "verdict": _normalize_label(record),
        "user_agent": str(_first_non_empty(record, "user_agent", "ua", "request_user_agent", "cs_user_agent") or ""),
        "raw": str(_first_non_empty(record, "raw", "raw_log", "raw_line", "raw_request") or ""),
        "normalized_request": str(_first_non_empty(record, "normalized_request", "request", "normalized_uri") or ""),
        "matched_rule_ids": _first_non_empty(record, "matched_rule_ids") or [],
        "matched_rules": _first_non_empty(record, "matched_rules") or [],
        "embedding": _first_non_empty(record, "embedding", "features.embedding") or [],
        "ml_label": record.get("ml_label"),
        "ml_should_alert": record.get("ml_should_alert"),
        "should_alert": record.get("should_alert"),
        "ml_attack_type": record.get("ml_attack_type"),
        "rule_score": record.get("rule_score"),
        "detection_method": "hybrid",
        "detection_sources": _extract_detection_sources(record),
        "primary_signal": str(record.get("primary_signal") or "unknown"),
        "risk_input_scores": record.get("risk_input_scores") or {},
    }

    if not isinstance(normalized["matched_rule_ids"], list):
        normalized["matched_rule_ids"] = [str(normalized["matched_rule_ids"])]
    if not isinstance(normalized["matched_rules"], list):
        normalized["matched_rules"] = [normalized["matched_rules"]]
    if not isinstance(normalized["embedding"], list):
        normalized["embedding"] = []

    return normalized


def _build_default_response_by_attack_type(attack_type: str) -> List[str]:
    value = str(attack_type or "unknown").strip().lower()
    if "sql" in value:
        return [
            "Validate and sanitize query parameters.",
            "Use prepared statements for database access.",
            "Enable SQL injection WAF protections.",
            "Inspect database access logs for abuse.",
        ]
    if "xss" in value:
        return [
            "Encode output before rendering in browsers.",
            "Validate and sanitize user-controlled input fields.",
            "Enable XSS-focused WAF protections.",
            "Review affected endpoints for unsafe rendering.",
        ]
    if "traversal" in value or "path" in value:
        return [
            "Normalize and validate file paths server-side.",
            "Block ../ traversal sequences at the edge.",
            "Restrict filesystem access for application processes.",
            "Inspect exposed static and download routes.",
        ]
    return [
        "Review the raw request payload manually.",
        "Correlate source IP with nearby incidents.",
        "Increase logging on the affected endpoint.",
    ]


class DashboardQueryAdapter:
    """Stable query interface for Streamlit dashboard with mock fallback."""

    def __init__(self, *, use_mock: Optional[bool] = None, now: Optional[datetime] = None) -> None:
        if load_dotenv is not None:
            load_dotenv()

        self._explicit_now = now is not None
        self._now = _ensure_aware_utc(now or datetime.now(timezone.utc))
        self.uri = str(os.getenv("MONGODB_URI", "")).strip()
        self.database_name = (
            str(os.getenv("MONGODB_DB_NAME", "")).strip()
            or str(os.getenv("MONGODB_DATABASE", "")).strip()
            or "threatlens"
        )
        self.page_title = str(os.getenv("DASHBOARD_PAGE_TITLE", "")).strip() or "ThreatLens AI"
        self._env_force_mock = _env_bool("DASHBOARD_USE_MOCK", default=False)
        self._use_mock = self._env_force_mock if use_mock is None else bool(use_mock)

        self.client = None
        self.db = None
        self.available_collections: List[str] = []
        self.requests_collection_name: Optional[str] = None
        self.incidents_collection_name: Optional[str] = None
        self.patterns_collection_name: Optional[str] = None
        self.campaigns_collection_name: Optional[str] = None

        self._mock = self._build_mock_dataset()
        self._status = {
            "connection": "Not Connected",
            "mode": "mock",
            "database": self.database_name,
            "message": "",
            "last_refresh": self._now.isoformat(),
            "collections": [],
        }

        self._connect()

    def _parse_timeframe(self, timeframe: Optional[str]) -> Optional[datetime]:
        if not timeframe or timeframe.lower() in ("all", "all_time", ""):
            return None
        
        base_time = self._now if self._explicit_now else datetime.now(timezone.utc)
        
        tf = timeframe.lower().strip()
        try:
            if tf.endswith("m"):
                minutes = int(tf[:-1])
                return base_time - timedelta(minutes=minutes)
            elif tf.endswith("h"):
                hours = int(tf[:-1])
                return base_time - timedelta(hours=hours)
            elif tf.endswith("d"):
                days = int(tf[:-1])
                return base_time - timedelta(days=days)
        except Exception:
            pass
        return None

    def _build_timeframe_match(self, timeframe: Optional[str]) -> Dict[str, Any]:
        cutoff = self._parse_timeframe(timeframe)
        if not cutoff:
            return {}
        return {
            "$or": [
                {
                    "$and": [
                        {"timestamp": {"$type": "date"}},
                        {"timestamp": {"$gte": cutoff}}
                    ]
                },
                {
                    "$and": [
                        {"timestamp": {"$type": "string"}},
                        {
                            "$expr": {
                                "$gte": [
                                    {
                                        "$dateFromString": {
                                            "dateString": "$timestamp",
                                            "onError": None,
                                            "onNull": None
                                        }
                                    },
                                    cutoff
                                ]
                            }
                        }
                    ]
                }
            ]
        }

    def _filter_mock_by_timeframe(self, items: List[Dict[str, Any]], timeframe: Optional[str]) -> List[Dict[str, Any]]:
        cutoff = self._parse_timeframe(timeframe)
        if not cutoff:
            return items
        
        filtered = []
        for item in items:
            ts_str = item.get("timestamp")
            if not ts_str:
                continue
            try:
                ts_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if ts_dt >= cutoff:
                    filtered.append(item)
            except Exception:
                filtered.append(item)
        return filtered

    def _combine_queries(self, q1: Dict[str, Any], q2: Dict[str, Any]) -> Dict[str, Any]:
        if not q1:
            return q2
        if not q2:
            return q1
        return {"$and": [q1, q2]}

    def status(self) -> Dict[str, Any]:
        payload = dict(self._status)
        payload["using_mock"] = self.is_mock_mode()
        payload["available_collections"] = list(self.available_collections)
        payload["database_name"] = self.database_name
        return payload

    def is_mock_mode(self) -> bool:
        return self._status.get("mode") == "mock"

    # -------------------------
    # Overview tab query methods
    # -------------------------

    def get_soc_summary(self, timeframe: Optional[str] = None) -> Dict[str, Any]:
        if self.is_mock_mode():
            requests = self._filter_mock_by_timeframe(self._mock["requests"], timeframe)
            incidents = self._filter_mock_by_timeframe(self._mock["incidents"], timeframe)
            malicious = [row for row in requests if _is_malicious_record(row)]
            campaigns = self.get_active_campaigns(min_attacks=10, timeframe=timeframe)
            high_incidents = [
                row
                for row in incidents
                if str(row.get("severity", "")).lower() in {"high", "critical"}
                or _safe_int(row.get("risk_score"), 0) >= 80
            ]
            return {
                "total_requests": len(requests),
                "malicious_requests": len(malicious),
                "total_incidents": len(incidents),
                "active_campaigns": len(campaigns),
                "campaigns_last_updated": None,
                "high_severity_incidents": len(high_incidents),
            }

        tf_match = self._build_timeframe_match(timeframe)

        requests_count = self._count_documents(self.requests_collection_name, tf_match)
        malicious_count = self._count_documents(
            self.requests_collection_name,
            self._combine_queries(tf_match, self._malicious_match_query())
        )

        incident_count = self._count_documents(self.incidents_collection_name, tf_match)
        if incident_count == 0:
            incident_count = malicious_count

        high_severity = self._count_documents(
            self.incidents_collection_name,
            self._combine_queries(tf_match, {"severity": {"$in": ["high", "critical", "HIGH", "CRITICAL"]}}),
        )
        if high_severity == 0:
            high_severity = self._count_documents(
                self.requests_collection_name,
                self._combine_queries(
                    tf_match,
                    {
                        "$and": [
                            self._malicious_match_query(),
                            {
                                "$or": [
                                    {"severity": {"$in": ["high", "critical", "HIGH", "CRITICAL"]}},
                                    {"risk_score": {"$gte": 80}},
                                ]
                            },
                        ]
                    }
                ),
            )

        materialized = self._get_materialized_campaigns_count()

        return {
            "total_requests": requests_count,
            "malicious_requests": malicious_count,
            "total_incidents": incident_count,
            "active_campaigns": materialized.get("count", 0),
            "campaigns_last_updated": materialized.get("last_updated"),
            "high_severity_incidents": high_severity,
        }

    def get_attack_type_distribution(self, timeframe: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.is_mock_mode():
            requests = self._filter_mock_by_timeframe(self._mock["requests"], timeframe)
            counts: Dict[str, int] = {}
            for record in requests:
                if not _is_malicious_record(record):
                    continue
                attack_type = _normalize_attack_type(record.get("attack_type"))
                counts[attack_type] = counts.get(attack_type, 0) + 1
            return [
                {"attack_type": attack_type, "count": count}
                for attack_type, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)
            ]

        rows = self._query_attack_type_distribution(timeframe=timeframe)
        if not rows and self.requests_collection_name:
            # Keep a read-only local fallback when centralized query helpers are unavailable.
            tf_match = self._build_timeframe_match(timeframe)
            records = self._find_many(
                self.requests_collection_name,
                self._combine_queries(tf_match, self._malicious_match_query()),
                projection={"attack_type": 1, "ml_attack_type": 1, "prediction.attack_type": 1, "risk_score": 1, "prediction.label": 1, "ml_label": 1, "ml_should_alert": 1, "should_alert": 1},
                limit=20000,
                sort=None,
            )
            counts: Dict[str, int] = {}
            for record in records:
                attack_type = _normalize_attack_type(_first_non_empty(record, "attack_type", "prediction.attack_type", "ml_attack_type"))
                counts[attack_type] = counts.get(attack_type, 0) + 1
            rows = [{"attack_type": attack_type, "count": count} for attack_type, count in counts.items()]

        output: List[Dict[str, Any]] = []
        for row in rows:
            count = _safe_int(row.get("count"), 0)
            if count <= 0:
                continue
            output.append(
                {
                    "attack_type": _normalize_attack_type(_first_non_empty(row, "attack_type", "_id")),
                    "count": count,
                }
            )
        output.sort(key=lambda item: int(item.get("count", 0)), reverse=True)
        return output

    def get_top_attacking_ips(self, limit: int = 10, timeframe: Optional[str] = None) -> List[Dict[str, Any]]:
        limit = max(1, int(limit))

        if self.is_mock_mode():
            requests = self._filter_mock_by_timeframe(self._mock["requests"], timeframe)
            grouped: Dict[str, Dict[str, Any]] = {}
            for row in requests:
                if not _is_malicious_record(row):
                    continue
                normalized = _normalize_request_record(row)
                key = normalized["ip"]
                item = grouped.setdefault(
                    key,
                    {
                        "ip": key,
                        "total_attacks": 0,
                        "attack_types": set(),
                        "target_uris": set(),
                        "first_seen": None,
                        "last_seen": None,
                    },
                )
                item["total_attacks"] += 1
                item["attack_types"].add(normalized["attack_type"])
                item["target_uris"].add(normalized["uri"])
                timestamp = _parse_timestamp(normalized["timestamp"])
                if timestamp:
                    if item["first_seen"] is None or timestamp < item["first_seen"]:
                        item["first_seen"] = timestamp
                    if item["last_seen"] is None or timestamp > item["last_seen"]:
                        item["last_seen"] = timestamp

            return self._finalize_top_ips(list(grouped.values()), limit)

        rows = self._query_top_attacking_ips(limit=limit, timeframe=timeframe)
        if not rows and self.requests_collection_name:
            # Keep a read-only fallback to avoid dashboard failures when centralized helper is unavailable.
            tf_match = self._build_timeframe_match(timeframe)
            records = self._find_many(
                self.requests_collection_name,
                self._combine_queries(tf_match, self._malicious_match_query()),
                projection={"ip": 1, "source_ip": 1, "client_ip": 1, "attack_type": 1, "ml_attack_type": 1, "uri": 1, "timestamp": 1, "risk_score": 1, "prediction": 1, "ml_label": 1, "ml_should_alert": 1, "should_alert": 1},
                limit=20000,
                sort=[("timestamp", -1)],
            )
            grouped: Dict[str, Dict[str, Any]] = {}
            for record in records:
                normalized = _normalize_request_record(record)
                key = normalized["ip"]
                row = grouped.setdefault(
                    key,
                    {
                        "ip": key,
                        "total_attacks": 0,
                        "attack_types": set(),
                        "target_uris": set(),
                        "first_seen": None,
                        "last_seen": None,
                    },
                )
                row["total_attacks"] += 1
                row["attack_types"].add(normalized["attack_type"])
                row["target_uris"].add(normalized["uri"])
                timestamp = _parse_timestamp(normalized["timestamp"])
                if timestamp:
                    if row["first_seen"] is None or timestamp < row["first_seen"]:
                        row["first_seen"] = timestamp
                    if row["last_seen"] is None or timestamp > row["last_seen"]:
                        row["last_seen"] = timestamp
            return self._finalize_top_ips(list(grouped.values()), limit)

        mapped = []
        for row in rows:
            raw_attack_types = row.get("attack_types") or []
            if not isinstance(raw_attack_types, list):
                raw_attack_types = [raw_attack_types]
            raw_target_uris = row.get("target_uris") or []
            if not isinstance(raw_target_uris, list):
                raw_target_uris = [raw_target_uris]
            mapped.append(
                {
                    "ip": str(_first_non_empty(row, "ip", "_id") or "Unknown"),
                    "total_attacks": _safe_int(row.get("total_attacks"), 0),
                    "attack_types": set(filter(None, [_normalize_attack_type(value) for value in raw_attack_types])),
                    "target_uris": set(filter(None, [str(value) for value in raw_target_uris])),
                    "first_seen": _parse_timestamp(row.get("first_seen")),
                    "last_seen": _parse_timestamp(row.get("last_seen")),
                }
            )

        return self._finalize_top_ips(mapped, limit)

    def get_attack_timeline(self, bucket_size: int = 5, unit: str = "minute", timeframe: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.is_mock_mode():
            requests = self._filter_mock_by_timeframe(self._mock["requests"], timeframe)
            return self._build_timeline_from_records(requests)

        if not self.requests_collection_name:
            return []

        rows = self._query_attack_timeline(bucket_size=bucket_size, unit=unit, timeframe=timeframe)
        if rows:
            timeline: List[Dict[str, Any]] = []
            for row in rows:
                timestamp_value = _first_non_empty(row, "timestamp", "_id")
                timestamp_text = _timestamp_to_text(timestamp_value)
                attack_type = str(row.get("attack_type") or "Unknown")
                count = _safe_int(row.get("count"), 0)
                if not timestamp_text or count <= 0:
                    continue
                timeline.append({
                    "timestamp": timestamp_text,
                    "attack_type": attack_type,
                    "count": count
                })
            if timeline:
                timeline.sort(key=lambda item: (item.get("timestamp", ""), item.get("attack_type", "")))
                return timeline

        tf_match = self._build_timeframe_match(timeframe)
        recent_records = self._find_many(
            self.requests_collection_name,
            self._combine_queries(tf_match, self._malicious_match_query()),
            projection={"timestamp": 1, "attack_type": 1, "prediction": 1, "risk_score": 1, "ml_attack_type": 1},
            limit=10000,
            sort=[("timestamp", 1)],
        )
        return self._build_timeline_from_records(recent_records)

    def get_ip_blast_radius(self, ip: str) -> List[Dict[str, Any]]:
        ip = str(ip or "").strip()
        if not ip:
            return []

        if self.is_mock_mode():
            matched = [
                row for row in self._mock["requests"]
                if str(row.get("ip")) == ip or str(row.get("source_ip")) == ip
            ]
            if matched:
                counts: Dict[str, int] = {}
                for row in matched:
                    uri = str(row.get("uri") or "Unknown")
                    counts[uri] = counts.get(uri, 0) + 1
                total = sum(counts.values())
                return [
                    {
                        "uri": uri,
                        "count": count,
                        "percentage": round((count / total) * 100.0, 1)
                    }
                    for uri, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)
                ]
            return [
                {"uri": "/login", "count": 8, "percentage": 80.0},
                {"uri": "/api/users", "count": 2, "percentage": 20.0}
            ]

        rows = self._query_ip_blast_radius(ip)
        if not rows:
            return []

        return [
            {
                "uri": str(row.get("uri") or "Unknown"),
                "count": _safe_int(row.get("count"), 0),
                "percentage": round(_safe_number(row.get("percentage"), 0.0), 2)
            }
            for row in rows
        ]

    def get_active_campaigns(self, min_attacks: int = 50, min_attack_types: int = 3, timeframe: Optional[str] = None) -> List[Dict[str, Any]]:
        threshold = max(1, int(min_attacks))
        min_types = max(1, int(min_attack_types))

        if not self.is_mock_mode():
            rows = self._query_attack_campaigns(min_attacks=threshold, min_attack_types=min_types, limit=200, timeframe=timeframe)
            if rows:
                campaigns: List[Dict[str, Any]] = []
                for row in rows:
                    total_attacks = _safe_int(row.get("total_attacks"), 0)

                    raw_attack_types = row.get("attack_types") or []
                    if not isinstance(raw_attack_types, list):
                        raw_attack_types = [raw_attack_types]
                    attack_types = sorted(
                        list(
                            set(
                                filter(
                                    None,
                                    [_normalize_attack_type(value) for value in raw_attack_types],
                                )
                            )
                        )
                    )

                    raw_target_uris = row.get("target_uris") or []
                    if not isinstance(raw_target_uris, list):
                        raw_target_uris = [raw_target_uris]
                    target_uris = sorted(list(set(filter(None, [str(value) for value in raw_target_uris]))))

                    campaigns.append(
                        {
                            "ip": str(_first_non_empty(row, "ip", "_id") or "Unknown"),
                            "total_attacks": total_attacks,
                            "attack_types": attack_types,
                            "target_uris": target_uris,
                            "first_seen": _timestamp_to_text(row.get("first_seen")),
                            "last_seen": _timestamp_to_text(row.get("last_seen")),
                            "risk_level": self._campaign_risk_level(
                                total_attacks=total_attacks,
                                attack_type_count=len(attack_types),
                            ),
                        }
                    )

                campaigns.sort(key=lambda item: int(item.get("total_attacks", 0)), reverse=True)
                return campaigns

        top_ips = self.get_top_attacking_ips(limit=200, timeframe=timeframe)

        campaigns: List[Dict[str, Any]] = []
        for row in top_ips:
            total_attacks = _safe_int(row.get("total_attacks"), 0)
            attack_types = row.get("attack_types") or []
            target_uris = row.get("target_uris") or []

            if (
                total_attacks >= threshold
                or len(attack_types) >= min_types
                or len(target_uris) > 1
            ):
                campaigns.append(
                    {
                        "ip": row.get("ip", "Unknown"),
                        "total_attacks": total_attacks,
                        "attack_types": attack_types,
                        "target_uris": target_uris,
                        "first_seen": row.get("first_seen"),
                        "last_seen": row.get("last_seen"),
                        "risk_level": self._campaign_risk_level(total_attacks=total_attacks, attack_type_count=len(attack_types)),
                    }
                )

        campaigns.sort(key=lambda item: int(item.get("total_attacks", 0)), reverse=True)
        return campaigns

    def get_materialized_campaigns(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Read pre-computed campaigns from Atlas Materialized View."""
        if self.is_mock_mode():
            return self.get_active_campaigns(min_attacks=10)
        
        if self.db is None or mongodb_queries is None or not hasattr(mongodb_queries, "get_materialized_campaigns"):
            return self.get_active_campaigns(min_attacks=10)
        
        try:
            coll_name = self.campaigns_collection_name or "active_campaigns"
            rows = mongodb_queries.get_materialized_campaigns(self.db, campaigns_collection=coll_name, limit=limit)
            if rows:
                # Format dates and ensure proper shapes
                formatted = []
                for row in rows:
                    formatted.append({
                        "ip": row.get("ip", "Unknown"),
                        "total_attacks": row.get("total_attacks", 0),
                        "attack_types": row.get("attack_types") or [],
                        "target_uris": row.get("target_uris") or [],
                        "first_seen": _timestamp_to_text(row.get("first_seen")),
                        "last_seen": _timestamp_to_text(row.get("last_seen")),
                        "risk_level": row.get("risk_level", "low"),
                    })
                return formatted
        except Exception:
            pass
        
        # Fallback to dynamic aggregation if materialized view is empty or errors
        return self.get_active_campaigns(min_attacks=10)

    def _get_materialized_campaigns_count(self) -> Dict[str, Any]:
        """Read campaign count from materialized view (fast path)."""
        if self.is_mock_mode():
            campaigns = self.get_active_campaigns(min_attacks=10)
            return {"count": len(campaigns), "last_updated": None}

        if self.db is None or mongodb_queries is None or not hasattr(mongodb_queries, "get_campaigns_metadata"):
            campaigns = self.get_active_campaigns(min_attacks=10)
            return {"count": len(campaigns), "last_updated": None}
            
        try:
            coll_name = self.campaigns_collection_name or "active_campaigns"
            return mongodb_queries.get_campaigns_metadata(self.db, campaigns_collection=coll_name)
        except Exception:
            try:
                campaigns = self.get_active_campaigns(min_attacks=10)
                return {"count": len(campaigns), "last_updated": None}
            except Exception:
                return {"count": 0, "last_updated": None}

    # -----------------------------
    # Investigation tab query methods
    # -----------------------------

    def get_recent_incidents(self, limit: int = 100, method_filter: str = "All", timeframe: Optional[str] = None) -> List[Dict[str, Any]]:
        limit = max(1, int(limit))

        if self.is_mock_mode():
            incidents = self._filter_mock_by_timeframe(self._mock["incidents"], timeframe)
            rows = [
                _normalize_request_record(record)
                for record in incidents
            ]
            rows.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
            return rows[:limit]

        tf_match = self._build_timeframe_match(timeframe)
        query: Dict[str, Any] = self._combine_queries(tf_match, {})

        incident_records = self._find_many(
            self.incidents_collection_name,
            query,
            projection=None,
            limit=limit,
            sort=[("timestamp", -1)],
        )

        if incident_records:
            return [
                _normalize_request_record(record)
                for record in incident_records
            ]

        derived_query = self._malicious_match_query()
        if query:
            derived_query = self._combine_queries(derived_query, query)
        else:
            derived_query = self._combine_queries(tf_match, derived_query)

        derived = self._find_many(
            self.requests_collection_name,
            derived_query,
            projection=None,
            limit=limit,
            sort=[("timestamp", -1)],
        )
        return [
            _normalize_request_record(record)
            for record in derived
        ]

    def get_incident_detail(self, incident_id: str) -> Optional[Dict[str, Any]]:
        incident_id = str(incident_id or "").strip()
        if not incident_id:
            return None

        if self.is_mock_mode():
            for record in self._mock["incidents"]:
                normalized = _normalize_request_record(record)
                if incident_id in {normalized.get("incident_id"), normalized.get("event_id")}:
                    return normalized
            return None

        if self.incidents_collection_name:
            for key in ("incident_id", "event_id", "_id"):
                row = self._find_one(self.incidents_collection_name, {key: incident_id})
                if row is not None:
                    return _normalize_request_record(row)

        if self.requests_collection_name:
            for key in ("incident_id", "event_id", "_id"):
                row = self._find_one(self.requests_collection_name, {key: incident_id})
                if row is not None:
                    return _normalize_request_record(row)

        return None

    def find_similar_attack_patterns(self, request_embedding: List[float], limit: int = 3) -> List[Dict[str, Any]]:
        limit = max(1, int(limit))
        embedding = [] if request_embedding is None else [float(x) for x in request_embedding if isinstance(x, (int, float))]

        if not embedding:
            return []

        if self.is_mock_mode():
            return self._mock_vector_matches(embedding, limit=limit)

        rows = self._query_vector_search(embedding=embedding, limit=limit)
        if rows:
            return [self._normalize_pattern(row) for row in rows][:limit]

        # Fallback when vector search is unavailable or no index exists.
        fallback = self._find_many(
            self.patterns_collection_name,
            {},
            projection={
                "pattern_id": 1,
                "attack_type": 1,
                "category": 1,
                "name": 1,
                "description": 1,
                "examples": 1,
                "payload_example": 1,
                "remediation": 1,
                "mitigation": 1,
                "mitre": 1,
                "severity": 1,
            },
            limit=limit,
            sort=[("severity", -1)],
        )

        normalized = []
        for index, row in enumerate(fallback, start=1):
            item = self._normalize_pattern(row)
            # Synthetic score for non-vector fallback.
            item["score"] = round(max(0.0, 0.75 - (index * 0.1)), 4)
            normalized.append(item)
        return normalized

    def build_rule_based_explanation(self, incident: Mapping[str, Any]) -> str:
        attack_type = _normalize_attack_type(incident.get("attack_type"))
        risk_score = _safe_int(incident.get("risk_score"), 0)
        prediction_score = _safe_number(incident.get("prediction_score"), 0.0)
        detection_sources = incident.get("detection_sources") or []
        if not isinstance(detection_sources, list):
            detection_sources = [str(detection_sources)]

        matched_rule_ids = incident.get("matched_rule_ids") or []
        if not isinstance(matched_rule_ids, list):
            matched_rule_ids = [str(matched_rule_ids)]

        uri = str(incident.get("uri") or "")
        payload = str(incident.get("raw") or "")

        indicator_tokens = []
        token_map = {
            "union": "UNION",
            "select": "SELECT",
            "../": "../",
            "<script": "<script>",
            "onerror=": "onerror",
            "javascript:": "javascript:",
        }
        text = f"{uri} {payload}".lower()
        for key, label in token_map.items():
            if key in text:
                indicator_tokens.append(label)

        reason_parts = []
        if attack_type.lower() != "unknown":
            reason_parts.append(f"classified as {attack_type}")
        if matched_rule_ids:
            reason_parts.append(f"matched rules: {', '.join(str(x) for x in matched_rule_ids[:4])}")
        if detection_sources:
            reason_parts.append(f"hybrid sources: {', '.join(str(x) for x in detection_sources)}")
        if indicator_tokens:
            reason_parts.append(f"contains suspicious tokens ({', '.join(indicator_tokens[:5])})")
        reason_parts.append(f"risk score {risk_score}")
        reason_parts.append(f"prediction confidence {round(prediction_score * 100, 1)}%")

        return "This request was flagged by the hybrid risk engine because it was " + "; ".join(reason_parts) + "."

    def get_response_recommendations(self, incident: Mapping[str, Any], patterns: Optional[List[Mapping[str, Any]]] = None) -> List[str]:
        if patterns:
            for item in patterns:
                remediation = item.get("remediation")
                if isinstance(remediation, list) and remediation:
                    return [str(x) for x in remediation if str(x).strip()]

        return _build_default_response_by_attack_type(str(incident.get("attack_type", "unknown")))

    def find_similar_requests(self, request_embedding: List[float], limit: int = 5) -> List[Dict[str, Any]]:
        """Find historically similar log entries using MongoDB Vector Search ($vectorSearch).

        Delegates to ``find_similar_logs`` in ``mongodb_queries``, which issues a
        ``$vectorSearch`` aggregation against the requests/unified_logs collection.
        Returns ``[]`` when the DB is unavailable or the search returns no results.
        """
        limit = max(1, int(limit))
        embedding = [] if request_embedding is None else [float(x) for x in request_embedding if isinstance(x, (int, float))]

        if not embedding:
            return []

        if self.db is None or mongodb_queries is None:
            return []

        if not hasattr(mongodb_queries, "find_similar_logs"):
            return []

        # Prefer requests collection, fallback to unified_logs.
        for collection_name in (self.requests_collection_name, "unified_logs"):
            if not collection_name:
                continue
            try:
                col = self._collection(collection_name)
                if col is None:
                    continue
                rows = mongodb_queries.find_similar_logs(col, embedding, limit=limit)
                if rows:
                    return [self._normalize_similar_request(row) for row in rows]
            except Exception:
                continue

        return []


    @staticmethod
    def _normalize_similar_request(row: Mapping[str, Any]) -> Dict[str, Any]:
        """Normalize a raw similar-log result row returned by find_similar_logs."""
        score = _safe_number(row.get("score"), 0.0)
        # Scores from $vectorSearch are cosine similarities in [0, 1].
        similarity_score = max(0.0, min(1.0, score))
        return {
            "event_id": str(row.get("event_id") or ""),
            "timestamp": _timestamp_to_text(_first_non_empty(row, "timestamp", "time", "@timestamp")),
            "ip": str(_first_non_empty(row, "source_ip", "ip", "client_ip") or "Unknown"),
            "uri": str(_first_non_empty(row, "uri", "original_url", "url") or "-"),
            "risk_score": _safe_int(_first_non_empty(row, "risk_score", "rule_score"), 0),
            "risk_level": str(row.get("risk_level") or ""),
            "final_label": str(row.get("final_label") or ""),
            "similarity_score": round(similarity_score, 4),
        }

    # -------------
    # Internals
    # -------------

    def _query_vector_search(self, embedding: List[float], limit: int) -> List[Dict[str, Any]]:
        if self.db is None or mongodb_queries is None:
            return []
        if not hasattr(mongodb_queries, "explain_threat_via_vector_search"):
            return []
        try:
            if self.patterns_collection_name:
                return mongodb_queries.explain_threat_via_vector_search(
                    self.db,
                    embedding,
                    limit=limit,
                    patterns_collection=self.patterns_collection_name,
                )
            return mongodb_queries.explain_threat_via_vector_search(self.db, embedding, limit=limit)
        except TypeError:
            try:
                return mongodb_queries.explain_threat_via_vector_search(self.db, embedding, limit=limit)
            except Exception:
                return []
        except Exception:
            return []

    def _query_attack_type_distribution(self, timeframe: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.db is None or mongodb_queries is None:
            return []
        if not hasattr(mongodb_queries, "get_attack_type_distribution"):
            return []
        cutoff = self._parse_timeframe(timeframe)
        try:
            if self.requests_collection_name:
                return mongodb_queries.get_attack_type_distribution(
                    self.db,
                    requests_collection=self.requests_collection_name,
                    cutoff=cutoff,
                )
            return mongodb_queries.get_attack_type_distribution(self.db, cutoff=cutoff)
        except TypeError:
            try:
                return mongodb_queries.get_attack_type_distribution(self.db)
            except Exception:
                return []
        except Exception:
            return []

    def _query_top_attacking_ips(self, limit: int, timeframe: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.db is None or mongodb_queries is None:
            return []
        if not hasattr(mongodb_queries, "get_top_attacking_ips"):
            return []
        cutoff = self._parse_timeframe(timeframe)
        try:
            if self.requests_collection_name:
                return mongodb_queries.get_top_attacking_ips(
                    self.db,
                    limit=limit,
                    requests_collection=self.requests_collection_name,
                    cutoff=cutoff,
                )
            return mongodb_queries.get_top_attacking_ips(self.db, limit=limit, cutoff=cutoff)
        except TypeError:
            try:
                return mongodb_queries.get_top_attacking_ips(self.db, limit=limit)
            except Exception:
                return []
        except Exception:
            return []

    def _query_attack_timeline(self, bucket_size: int = 5, unit: str = "minute", timeframe: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.db is None or mongodb_queries is None:
            return []
        if not hasattr(mongodb_queries, "generate_attack_timeline"):
            return []
        cutoff = self._parse_timeframe(timeframe)
        try:
            if self.requests_collection_name:
                return mongodb_queries.generate_attack_timeline(
                    self.db,
                    ip=None,
                    bucket_size=bucket_size,
                    unit=unit,
                    limit=1000,
                    requests_collection=self.requests_collection_name,
                    cutoff=cutoff,
                )
            return mongodb_queries.generate_attack_timeline(self.db, ip=None, bucket_size=bucket_size, unit=unit, limit=1000, cutoff=cutoff)
        except TypeError:
            try:
                return mongodb_queries.generate_attack_timeline(self.db, ip=None, hours_bucket=1, limit=1000)
            except Exception:
                return []
        except Exception:
            return []

    def _query_ip_blast_radius(self, ip: str) -> List[Dict[str, Any]]:
        if self.db is None or mongodb_queries is None:
            return []
        if not hasattr(mongodb_queries, "get_ip_blast_radius"):
            return []
        try:
            if self.requests_collection_name:
                return mongodb_queries.get_ip_blast_radius(
                    self.db,
                    ip=ip,
                    requests_collection=self.requests_collection_name,
                )
            return mongodb_queries.get_ip_blast_radius(self.db, ip=ip)
        except Exception:
            return []

    def _query_attack_campaigns(self, *, min_attacks: int, min_attack_types: int = 3, limit: int, timeframe: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.db is None or mongodb_queries is None:
            return []
        if not hasattr(mongodb_queries, "detect_attack_campaigns"):
            return []
        cutoff = self._parse_timeframe(timeframe)
        try:
            if self.requests_collection_name:
                return mongodb_queries.detect_attack_campaigns(
                    self.db,
                    min_attacks=min_attacks,
                    min_attack_types=min_attack_types,
                    limit=limit,
                    requests_collection=self.requests_collection_name,
                    cutoff=cutoff,
                )
            return mongodb_queries.detect_attack_campaigns(self.db, min_attacks=min_attacks, min_attack_types=min_attack_types, limit=limit, cutoff=cutoff)
        except TypeError:
            try:
                return mongodb_queries.detect_attack_campaigns(self.db, min_attacks=min_attacks, limit=limit)
            except Exception:
                return []
        except Exception:
            return []

    def _connect(self) -> None:
        if self._use_mock:
            self._status.update(
                {
                    "connection": "Mock Mode",
                    "mode": "mock",
                    "message": "DASHBOARD_USE_MOCK=1",
                }
            )
            return

        if not self.uri:
            self._status.update(
                {
                    "connection": "Mock Mode",
                    "mode": "mock",
                    "message": "MONGODB_URI not set",
                }
            )
            return

        if not HAS_PYMONGO or MongoClient is None:
            self._status.update(
                {
                    "connection": "Mock Mode",
                    "mode": "mock",
                    "message": "pymongo is not installed",
                }
            )
            return

        try:
            self.client = MongoClient(
                self.uri,
                serverSelectionTimeoutMS=3000,
                connectTimeoutMS=3000,
                socketTimeoutMS=5000,
            )
            self.client.admin.command("ping")
            self.db = self.client[self.database_name]
            self.available_collections = sorted(self.db.list_collection_names())

            self.requests_collection_name = self._pick_collection_name("requests", "logs")
            self.incidents_collection_name = self._pick_collection_name("incidents")
            self.patterns_collection_name = self._pick_collection_name("attack_patterns")
            self.campaigns_collection_name = self._pick_collection_name("active_campaigns") or "active_campaigns"

            self._status.update(
                {
                    "connection": "Connected",
                    "mode": "mongodb",
                    "message": "MongoDB connection ready",
                    "collections": list(self.available_collections),
                }
            )
        except Exception as exc:
            self.client = None
            self.db = None
            self.available_collections = []
            self._status.update(
                {
                    "connection": "Error",
                    "mode": "mock",
                    "message": f"MongoDB connection failed: {exc}",
                }
            )

    def _pick_collection_name(self, *candidates: str) -> Optional[str]:
        available = set(self.available_collections)
        for candidate in candidates:
            if candidate in available:
                return candidate
        return None

    def _collection(self, name: Optional[str]):
        if not name or self.db is None:
            return None
        try:
            return self.db[name]
        except Exception:
            return None

    def _count_documents(self, collection_name: Optional[str], query: Mapping[str, Any]) -> int:
        collection = self._collection(collection_name)
        if collection is None:
            return 0
        try:
            return int(collection.count_documents(dict(query)))
        except Exception:
            return 0

    def _find_one(self, collection_name: Optional[str], query: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        collection = self._collection(collection_name)
        if collection is None:
            return None
        try:
            row = collection.find_one(dict(query))
            if row is None:
                return None
            return dict(row)
        except Exception:
            return None

    def _find_many(
        self,
        collection_name: Optional[str],
        query: Mapping[str, Any],
        *,
        projection: Optional[Mapping[str, Any]],
        limit: int,
        sort: Optional[List[tuple[str, int]]],
    ) -> List[Dict[str, Any]]:
        collection = self._collection(collection_name)
        if collection is None:
            return []

        try:
            cursor = collection.find(dict(query), projection)
            if sort:
                cursor = cursor.sort(sort)
            cursor = cursor.limit(max(1, int(limit)))
            return [dict(row) for row in cursor]
        except Exception:
            return []

    def _aggregate(
        self,
        collection_name: Optional[str],
        pipeline: List[Dict[str, Any]],
        *,
        swallow_errors: bool = True,
    ) -> List[Dict[str, Any]]:
        collection = self._collection(collection_name)
        if collection is None:
            return []

        try:
            rows = collection.aggregate(pipeline, allowDiskUse=True)
            return [dict(row) for row in rows]
        except Exception:
            if swallow_errors:
                return []
            raise

    @staticmethod
    def _malicious_match_query() -> Dict[str, Any]:
        return {
            "$or": [
                {"prediction.label": {"$in": ["malicious", "suspicious", "attack"]}},
                {"ml_label": {"$in": ["malicious", "suspicious", "attack"]}},
                {"ml_should_alert": True},
                {"should_alert": True},
                {"attack_type": {"$exists": True, "$nin": [None, "", "Unknown", "unknown", "normal", "benign"]}},
                {"ml_attack_type": {"$exists": True, "$nin": [None, "", "Unknown", "unknown", "normal", "benign"]}},
                {"risk_score": {"$gte": 70}},
            ]
        }

    @staticmethod
    def _campaign_risk_level(*, total_attacks: int, attack_type_count: int) -> str:
        if total_attacks >= 30 or attack_type_count >= 4:
            return "critical"
        if total_attacks >= 15 or attack_type_count >= 3:
            return "high"
        if total_attacks >= 8 or attack_type_count >= 2:
            return "medium"
        return "low"

    def _build_timeline_from_records(self, records: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        buckets: Dict[tuple[str, str], int] = {}
        for record in records:
            if not _is_malicious_record(record):
                continue

            value = _first_non_empty(record, "timestamp", "time", "@timestamp", "created_at")
            parsed = _parse_timestamp(value)
            if parsed is None:
                continue

            # 5-minute bucketing for nicer charts:
            minute_rounded = (parsed.minute // 5) * 5
            bucket = parsed.replace(minute=minute_rounded, second=0, microsecond=0)
            key = bucket.isoformat()

            attack_type = _normalize_attack_type(_first_non_empty(record, "attack_type", "prediction.attack_type", "ml_attack_type"))
            buckets[(key, attack_type)] = buckets.get((key, attack_type), 0) + 1

        out = [
            {"timestamp": ts, "attack_type": at, "count": count}
            for (ts, at), count in sorted(buckets.items(), key=lambda x: x[0])
        ]
        return out

    def _finalize_top_ips(self, grouped_rows: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
        final_rows: List[Dict[str, Any]] = []
        for row in grouped_rows:
            attack_types = sorted(list(row.get("attack_types", [])))
            target_uris = sorted(list(row.get("target_uris", [])))
            first_seen = row.get("first_seen")
            last_seen = row.get("last_seen")

            final_rows.append(
                {
                    "ip": row.get("ip", "Unknown"),
                    "total_attacks": _safe_int(row.get("total_attacks"), 0),
                    "attack_types": attack_types,
                    "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else _timestamp_to_text(first_seen),
                    "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else _timestamp_to_text(last_seen),
                    "target_count": len(target_uris),
                    "target_uris": target_uris,
                }
            )

        final_rows.sort(key=lambda item: int(item.get("total_attacks", 0)), reverse=True)
        return final_rows[:limit]

    def _normalize_pattern(self, row: Mapping[str, Any]) -> Dict[str, Any]:
        score = _safe_number(row.get("score"), 0.0)
        raw_examples = row.get("examples") or row.get("payload_example") or []
        examples = [raw_examples] if isinstance(raw_examples, str) else list(raw_examples) if isinstance(raw_examples, (list, set, tuple)) else []
        raw_remediation = row.get("remediation") or row.get("mitigation") or []
        remediation = [raw_remediation] if isinstance(raw_remediation, str) else list(raw_remediation) if isinstance(raw_remediation, (list, set, tuple)) else []
        return {
            "pattern_id": str(row.get("pattern_id") or row.get("_id") or ""),
            "attack_type": _normalize_attack_type(_first_non_empty(row, "attack_type", "category")),
            "name": str(row.get("name") or row.get("pattern_id") or "Unknown Pattern"),
            "description": str(row.get("description") or "No pattern description available."),
            "examples": examples,
            "remediation": remediation,
            "mitre": str(row.get("mitre") or "N/A"),
            "severity": str(row.get("severity") or "unknown"),
            "score": max(0.0, min(score, 1.0 if score <= 1.0 else score)),
        }

    def _mock_vector_matches(self, embedding: List[float], limit: int = 3) -> List[Dict[str, Any]]:
        patterns = [self._normalize_pattern(row) for row in self._mock["attack_patterns"]]
        if not patterns:
            return []

        for index, row in enumerate(patterns):
            # Deterministic pseudo-score for demo mode.
            seed = (index + 1) * 0.13 + (sum(embedding[:8]) % 0.17)
            row["score"] = round(max(0.55, min(0.97, 0.95 - seed)), 4)

        patterns.sort(key=lambda item: float(item.get("score", 0.0)), reverse=True)
        return patterns[:limit]

    def _build_mock_dataset(self) -> Dict[str, List[Dict[str, Any]]]:
        base = self._now.replace(minute=0, second=0, microsecond=0)

        def ts(hours_ago: int, minutes: int = 0) -> str:
            value = base - timedelta(hours=hours_ago, minutes=minutes)
            return value.isoformat()

        requests = [
            {
                "_id": "evt-001",
                "event_id": "evt-001",
                "timestamp": ts(10, 20),
                "ip": "10.0.0.12",
                "method": "GET",
                "uri": "/health",
                "attack_type": "Unknown",
                "prediction": {"label": "normal", "score": 0.02},
                "risk_score": 4,
                "severity": "low",
                "embedding": [0.01, 0.02, 0.01],
            },
            {
                "_id": "evt-002",
                "event_id": "evt-002",
                "timestamp": ts(9, 30),
                "ip": "10.0.0.18",
                "method": "GET",
                "uri": "/assets/logo.png",
                "attack_type": "Unknown",
                "prediction": {"label": "normal", "score": 0.04},
                "risk_score": 6,
                "severity": "low",
                "embedding": [0.03, 0.01, 0.02],
            },
            {
                "_id": "evt-100",
                "event_id": "evt-100",
                "timestamp": ts(8, 50),
                "ip": "185.24.9.10",
                "method": "GET",
                "uri": "/product?id=1%20UNION%20SELECT%20password%20FROM%20users",
                "attack_type": "SQLI",
                "prediction": {"label": "malicious", "score": 0.97},
                "risk_score": 96,
                "severity": "critical",
                "matched_rule_ids": ["sqli_union_select", "sqli_information_schema"],
                "raw": 'GET /product?id=1 UNION SELECT password FROM users HTTP/1.1',
                "embedding": [0.92, 0.88, 0.85, 0.93],
            },
            {
                "_id": "evt-101",
                "event_id": "evt-101",
                "timestamp": ts(8, 42),
                "ip": "185.24.9.10",
                "method": "GET",
                "uri": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                "attack_type": "XSS",
                "prediction": {"label": "suspicious", "score": 0.91},
                "risk_score": 88,
                "severity": "high",
                "matched_rule_ids": ["xss_script_tag"],
                "raw": 'GET /search?q=<script>alert(1)</script> HTTP/1.1',
                "embedding": [0.81, 0.79, 0.84, 0.76],
            },
            {
                "_id": "evt-102",
                "event_id": "evt-102",
                "timestamp": ts(8, 35),
                "ip": "185.24.9.10",
                "method": "GET",
                "uri": "/download?file=../../etc/passwd",
                "attack_type": "PATH_TRAVERSAL",
                "prediction": {"label": "malicious", "score": 0.94},
                "risk_score": 92,
                "severity": "critical",
                "matched_rule_ids": ["traversal_dotdot", "traversal_linux_passwd"],
                "raw": 'GET /download?file=../../etc/passwd HTTP/1.1',
                "embedding": [0.83, 0.88, 0.78, 0.82],
            },
            {
                "_id": "evt-103",
                "event_id": "evt-103",
                "timestamp": ts(7, 55),
                "ip": "185.24.9.10",
                "method": "POST",
                "uri": "/login",
                "attack_type": "SQLI",
                "prediction": {"label": "malicious", "score": 0.89},
                "risk_score": 85,
                "severity": "high",
                "matched_rule_ids": ["sqli_or_true"],
                "raw": "POST /login username=admin' OR 1=1--",
                "embedding": [0.86, 0.8, 0.83, 0.89],
            },
            {
                "_id": "evt-104",
                "event_id": "evt-104",
                "timestamp": ts(7, 22),
                "ip": "185.24.9.10",
                "method": "GET",
                "uri": "/admin",
                "attack_type": "SCANNING",
                "prediction": {"label": "suspicious", "score": 0.74},
                "risk_score": 72,
                "severity": "medium",
                "matched_rule_ids": ["sensitive_admin_path"],
                "raw": "GET /admin HTTP/1.1",
                "embedding": [0.66, 0.65, 0.62, 0.61],
            },
            {
                "_id": "evt-105",
                "event_id": "evt-105",
                "timestamp": ts(6, 10),
                "ip": "203.0.113.44",
                "method": "GET",
                "uri": "/product?item=1",
                "attack_type": "Unknown",
                "prediction": {"label": "normal", "score": 0.07},
                "risk_score": 10,
                "severity": "low",
                "embedding": [0.08, 0.05, 0.03],
            },
        ]

        # Add more campaign-like traffic from the same IP for demo campaign detection.
        for index in range(6):
            requests.append(
                {
                    "_id": f"evt-cmp-{index}",
                    "event_id": f"evt-cmp-{index}",
                    "timestamp": ts(5 - (index // 2), (index * 7) % 58),
                    "ip": "185.24.9.10",
                    "method": "GET",
                    "uri": f"/api/export?path=../../var/log/app-{index}.log",
                    "attack_type": "PATH_TRAVERSAL" if index % 2 else "SQLI",
                    "prediction": {"label": "malicious", "score": 0.83},
                    "risk_score": 81,
                    "severity": "high",
                    "matched_rule_ids": ["traversal_dotdot"] if index % 2 else ["sqli_union_select"],
                    "embedding": [0.75, 0.79, 0.82, 0.8],
                }
            )

        incidents = [row for row in requests if _is_malicious_record(row)]

        attack_patterns = [
            {
                "pattern_id": "sqli_union_select",
                "attack_type": "SQLI",
                "name": "UNION SELECT SQL Injection",
                "description": "Injection attempt that appends UNION SELECT to extract data from backend tables.",
                "examples": ["union select", "information_schema"],
                "mitre": "T1190",
                "severity": "high",
                "remediation": [
                    "Block source IP and review burst traffic from the subnet.",
                    "Use prepared statements and parameterized database queries.",
                    "Enable SQLi-focused WAF rules and monitor DB auth logs.",
                ],
                "embedding": [0.95, 0.92, 0.91, 0.9],
            },
            {
                "pattern_id": "xss_script_injection",
                "attack_type": "XSS",
                "name": "Reflected XSS Script Injection",
                "description": "Client-side script payload reflected by the application and executed in browser context.",
                "examples": ["<script>alert(1)</script>", "javascript:alert(1)"],
                "mitre": "T1059",
                "severity": "high",
                "remediation": [
                    "Encode output before rendering HTML responses.",
                    "Apply strict input validation on query/body parameters.",
                    "Enable CSP and XSS response headers.",
                ],
                "embedding": [0.86, 0.88, 0.91, 0.83],
            },
            {
                "pattern_id": "path_traversal_dotdot",
                "attack_type": "PATH_TRAVERSAL",
                "name": "Path Traversal dot-dot-slash",
                "description": "Attempt to access restricted files using ../ traversal sequences.",
                "examples": ["../../etc/passwd", "..\\..\\windows\\win.ini"],
                "mitre": "T1006",
                "severity": "critical",
                "remediation": [
                    "Normalize and canonicalize user-supplied file paths.",
                    "Restrict filesystem reads to allowlisted directories.",
                    "Block traversal signatures at reverse proxy or WAF.",
                ],
                "embedding": [0.82, 0.89, 0.84, 0.86],
            },
        ]

        return {
            "requests": requests,
            "incidents": incidents,
            "attack_patterns": attack_patterns,
            "analyst_feedback": [],
            "logs": requests,
        }
