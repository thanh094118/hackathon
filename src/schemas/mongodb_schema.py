from __future__ import annotations

import copy
from typing import Any, Dict, Mapping

SCHEMA_VERSION = 2

FEATURE_PREFIX = "feature_"


def is_nested_schema(doc: Mapping[str, Any]) -> bool:
    """Return True if the document is structured under the nested schema version."""
    return doc.get("_schema_version", 0) >= SCHEMA_VERSION


def flat_to_nested(doc: Mapping[str, Any]) -> Dict[str, Any]:
    """Convert a flat log document to the nested schema structure (Schema Version 2)."""
    if is_nested_schema(doc):
        return dict(doc)

    nested: Dict[str, Any] = {
        "_schema_version": SCHEMA_VERSION,
    }

    # Copy identity / metadata fields directly to top-level
    top_level_keys = {
        "_id",
        "event_id",
        "timestamp",
        "server_type",
        "line_number",
        "parse_status",
        "flags",
        "physical_line_range",
    }
    for key in top_level_keys:
        if key in doc:
            nested[key] = doc[key]

    # --- Parsed Request Info ---
    request_keys = {
        "source_ip": ("source_ip", "ip", "client_ip"),
        "method": ("http_method", "method", "request_http_method"),
        "uri": ("uri", "original_url", "url", "request_http_request"),
        "query_string": ("query_string", "query"),
        "status_code": ("status_code", "response_http_status_code"),
        "response_size": ("response_size", "response_content_length"),
        "user_agent": ("user_agent", "request_user_agent"),
        "raw_log": ("raw_log", "raw", "line"),
    }
    req_data: Dict[str, Any] = {}
    for dest, sources in request_keys.items():
        val = _first_val(doc, sources)
        if val is not None:
            req_data[dest] = val
    if req_data:
        nested["request"] = req_data

    # --- Preprocessor Decode Info ---
    preprocessed_keys = {
        "normalized_uri": ("normalized_uri",),
        "normalized_query_string": ("normalized_query_string",),
        "normalized_user_agent": ("normalized_user_agent",),
        "normalized_request": ("normalized_request",),
    }
    prep_data: Dict[str, Any] = {}
    for dest, sources in preprocessed_keys.items():
        val = _first_val(doc, sources)
        if val is not None:
            prep_data[dest] = val

    # Nested decode sub-document
    decode_keys = {
        "depth": ("decode_depth",),
        "changed": ("decode_changed",),
        "depth_uri": ("decode_depth_uri",),
        "changed_uri": ("decode_changed_uri",),
        "depth_query": ("decode_depth_query_string", "decode_depth_query"),
        "changed_query": ("decode_changed_query_string", "decode_changed_query"),
        "limit_reached": ("decode_limit_reached",),
        "removed_control_chars": ("removed_control_chars",),
    }
    decode_data: Dict[str, Any] = {}
    for dest, sources in decode_keys.items():
        val = _first_val(doc, sources)
        if val is not None:
            decode_data[dest] = val
    if decode_data:
        prep_data["decode"] = decode_data

    if prep_data:
        nested["preprocessed"] = prep_data

    # --- Handcrafted Numeric Features ---
    feat_vector: Dict[str, Any] = {}
    for k, v in doc.items():
        if k.startswith(FEATURE_PREFIX):
            name = k[len(FEATURE_PREFIX):]
            feat_vector[name] = v
    
    features_doc: Dict[str, Any] = {}
    feat_version = doc.get("feature_version")
    if feat_version:
        features_doc["version"] = feat_version
    if feat_vector:
        features_doc["vector"] = feat_vector

    if features_doc:
        nested["features"] = features_doc

    # --- Detection Signals (Rules and ML) ---
    detection_doc: Dict[str, Any] = {}

    rules_data: Dict[str, Any] = {}
    rules_keys = {
        "score": ("rule_score",),
        "severity": ("rule_severity",),
        "matched_ids": ("matched_rule_ids",),
        "matched_rules": ("matched_rules",),
        "attack_type": ("attack_type",),
    }
    for dest, sources in rules_keys.items():
        val = _first_val(doc, sources)
        if val is not None:
            rules_data[dest] = val
    if rules_data:
        detection_doc["rules"] = rules_data

    ml_data: Dict[str, Any] = {}
    ml_keys = {
        "label": ("ml_label",),
        "attack_type": ("ml_attack_type",),
        "probability": ("ml_attack_probability",),
        "should_alert": ("ml_should_alert",),
    }
    for dest, sources in ml_keys.items():
        val = _first_val(doc, sources)
        if val is not None:
            ml_data[dest] = val
    if ml_data:
        detection_doc["ml"] = ml_data

    if detection_doc:
        nested["detection"] = detection_doc

    # --- Final Scoring ---
    scoring_data: Dict[str, Any] = {}
    scoring_keys = {
        "risk_score": ("risk_score",),
        "risk_bonus": ("risk_bonus",),
        "risk_level": ("risk_level",),
        "final_label": ("final_label",),
        "should_alert": ("should_alert",),
        "detection_method": ("detection_method",),
        "detection_sources": ("detection_sources",),
        "primary_signal": ("primary_signal",),
        "risk_input_scores": ("risk_input_scores",),
    }
    for dest, sources in scoring_keys.items():
        val = _first_val(doc, sources)
        if val is not None:
            scoring_data[dest] = val
    if scoring_data:
        nested["scoring"] = scoring_data

    # --- Embeddings (kept top-level for Atlas Vector Search) ---
    if "embedding" in doc:
        nested["embedding"] = doc["embedding"]

    return nested


def nested_to_flat(doc: Mapping[str, Any]) -> Dict[str, Any]:
    """Convert a nested document back to the flat format for backward compatibility."""
    if not is_nested_schema(doc):
        return dict(doc)

    flat: Dict[str, Any] = {}

    # Copy top-level identity fields directly
    for k, v in doc.items():
        if k not in {"request", "preprocessed", "features", "detection", "scoring", "_schema_version"}:
            flat[k] = v

    # Request fields
    req = doc.get("request")
    if isinstance(req, Mapping):
        # We restore the canonical flat names used by the rest of the application
        flat["raw_log"] = req.get("raw_log")
        flat["source_ip"] = req.get("source_ip")
        flat["http_method"] = req.get("method")
        flat["uri"] = req.get("uri")
        flat["query_string"] = req.get("query_string")
        flat["status_code"] = req.get("status_code")
        flat["response_size"] = req.get("response_size")
        flat["user_agent"] = req.get("user_agent")
        
        # Legacy mappings
        flat["ip"] = req.get("source_ip")
        flat["method"] = req.get("method")
        flat["raw"] = req.get("raw_log")

    # Preprocessed fields
    prep = doc.get("preprocessed")
    if isinstance(prep, Mapping):
        flat["normalized_uri"] = prep.get("normalized_uri")
        flat["normalized_query_string"] = prep.get("normalized_query_string")
        flat["normalized_user_agent"] = prep.get("normalized_user_agent")
        flat["normalized_request"] = prep.get("normalized_request")

        decode = prep.get("decode")
        if isinstance(decode, Mapping):
            flat["decode_depth"] = decode.get("depth")
            flat["decode_changed"] = decode.get("changed")
            flat["decode_depth_uri"] = decode.get("depth_uri")
            flat["decode_changed_uri"] = decode.get("changed_uri")
            flat["decode_depth_query_string"] = decode.get("depth_query")
            flat["decode_changed_query_string"] = decode.get("changed_query")
            flat["decode_limit_reached"] = decode.get("limit_reached")
            flat["removed_control_chars"] = decode.get("removed_control_chars")

    # Features fields
    features = doc.get("features")
    if isinstance(features, Mapping):
        flat["feature_version"] = features.get("version")
        vector = features.get("vector")
        if isinstance(vector, Mapping):
            for k, v in vector.items():
                flat[f"{FEATURE_PREFIX}{k}"] = v

    # Detection fields
    detection = doc.get("detection")
    if isinstance(detection, Mapping):
        rules = detection.get("rules")
        if isinstance(rules, Mapping):
            flat["rule_score"] = rules.get("score")
            flat["rule_severity"] = rules.get("severity")
            flat["matched_rule_ids"] = rules.get("matched_ids")
            flat["matched_rules"] = rules.get("matched_rules")
            flat["attack_type"] = rules.get("attack_type")

        ml = detection.get("ml")
        if isinstance(ml, Mapping):
            flat["ml_label"] = ml.get("label")
            flat["ml_attack_type"] = ml.get("attack_type")
            flat["ml_attack_probability"] = ml.get("probability")
            flat["ml_should_alert"] = ml.get("should_alert")

    # Scoring fields
    scoring = doc.get("scoring")
    if isinstance(scoring, Mapping):
        for k, v in scoring.items():
            flat[k] = v

    return flat


def _first_val(doc: Mapping[str, Any], sources: Iterable[str]) -> Any:
    for source in sources:
        if source in doc:
            return doc[source]
    return None
