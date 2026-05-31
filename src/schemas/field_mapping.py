from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping

# Exact matches for flat keys -> nested paths
MAPPED_FIELDS: Dict[str, str] = {
    # Request Info
    "source_ip": "request.source_ip",
    "ip": "request.source_ip",
    "client_ip": "request.source_ip",
    "method": "request.method",
    "http_method": "request.method",
    "request_http_method": "request.method",
    "uri": "request.uri",
    "original_url": "request.uri",
    "url": "request.uri",
    "request_http_request": "request.uri",
    "query_string": "request.query_string",
    "query": "request.query_string",
    "status_code": "request.status_code",
    "response_http_status_code": "request.status_code",
    "response_size": "request.response_size",
    "response_content_length": "request.response_size",
    "user_agent": "request.user_agent",
    "request_user_agent": "request.user_agent",
    "raw_log": "request.raw_log",
    "raw": "request.raw_log",
    "line": "request.raw_log",

    # Preprocessor Info
    "normalized_uri": "preprocessed.normalized_uri",
    "normalized_query_string": "preprocessed.normalized_query_string",
    "normalized_user_agent": "preprocessed.normalized_user_agent",
    "normalized_request": "preprocessed.normalized_request",
    "decode_depth": "preprocessed.decode.depth",
    "decode_changed": "preprocessed.decode.changed",
    "decode_depth_uri": "preprocessed.decode.depth_uri",
    "decode_changed_uri": "preprocessed.decode.changed_uri",
    "decode_depth_query_string": "preprocessed.decode.depth_query",
    "decode_depth_query": "preprocessed.decode.depth_query",
    "decode_changed_query_string": "preprocessed.decode.changed_query",
    "decode_changed_query": "preprocessed.decode.changed_query",
    "decode_limit_reached": "preprocessed.decode.limit_reached",
    "removed_control_chars": "preprocessed.decode.removed_control_chars",

    # Feature version
    "feature_version": "features.version",

    # Detection Info - Rules
    "rule_score": "detection.rules.score",
    "rule_severity": "detection.rules.severity",
    "matched_rule_ids": "detection.rules.matched_ids",
    "matched_rules": "detection.rules.matched_rules",
    "attack_type": "detection.rules.attack_type",

    # Detection Info - ML
    "ml_label": "detection.ml.label",
    "ml_attack_type": "detection.ml.attack_type",
    "ml_attack_probability": "detection.ml.probability",
    "ml_should_alert": "detection.ml.should_alert",

    # Final Scoring Info
    "risk_score": "scoring.risk_score",
    "risk_bonus": "scoring.risk_bonus",
    "risk_level": "scoring.risk_level",
    "final_label": "scoring.final_label",
    "should_alert": "scoring.should_alert",
    "detection_method": "scoring.detection_method",
    "detection_sources": "scoring.detection_sources",
    "primary_signal": "scoring.primary_signal",
    "risk_input_scores": "scoring.risk_input_scores",
}


def map_field_path(path: str) -> str:
    """Translate a flat field name or dotted path to the corresponding nested schema path."""
    if not path:
        return path

    # If it already refers to a nested field, leave it
    if any(path.startswith(prefix + ".") for prefix in ["request", "preprocessed", "features", "detection", "scoring"]):
        return path

    # Check for exact matches first
    if path in MAPPED_FIELDS:
        return MAPPED_FIELDS[path]

    # Handcrafted features: feature_name -> features.vector.name
    if path.startswith("feature_"):
        name = path[len("feature_"):]
        return f"features.vector.{name}"

    # Check prefix mapping for dotted paths (e.g. prediction.label)
    # prediction.* -> detection.ml.*
    if path.startswith("prediction."):
        suffix = path[len("prediction."):]
        if suffix == "label":
            return "detection.ml.label"
        if suffix == "attack_type":
            return "detection.ml.attack_type"
        if suffix == "score" or suffix == "probability":
            return "detection.ml.probability"
        return f"detection.ml.{suffix}"

    return path


def map_query(query: Any) -> Any:
    """Recursively map flat keys in a query dictionary, list, or value to their nested equivalents."""
    if isinstance(query, dict):
        new_query: Dict[str, Any] = {}
        for k, v in query.items():
            # If the key starts with $, it is an operator (e.g. $or, $and, $gte)
            if k.startswith("$"):
                new_query[k] = map_query(v)
            else:
                new_key = map_field_path(k)
                new_query[new_key] = map_query(v)
        return new_query
    elif isinstance(query, list):
        return [map_query(item) for item in query]
    else:
        return query
