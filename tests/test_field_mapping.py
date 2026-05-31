from __future__ import annotations

from src.schemas.field_mapping import map_field_path, map_query


def test_map_field_path():
    assert map_field_path("ip") == "request.source_ip"
    assert map_field_path("uri") == "request.uri"
    assert map_field_path("rule_score") == "detection.rules.score"
    assert map_field_path("ml_label") == "detection.ml.label"
    assert map_field_path("feature_has_xss") == "features.vector.has_xss"
    assert map_field_path("prediction.label") == "detection.ml.label"
    assert map_field_path("prediction.attack_type") == "detection.ml.attack_type"
    assert map_field_path("risk_score") == "scoring.risk_score"
    assert map_field_path("timestamp") == "timestamp"  # Unchanged top level


def test_map_query():
    query = {
        "$and": [
            {"ip": "1.2.3.4"},
            {
                "$or": [
                    {"risk_score": {"$gte": 80}},
                    {"prediction.label": "malicious"},
                ]
            },
            {"feature_sql_keywords": {"$gt": 2}},
        ]
    }

    mapped = map_query(query)

    expected = {
        "$and": [
            {"request.source_ip": "1.2.3.4"},
            {
                "$or": [
                    {"scoring.risk_score": {"$gte": 80}},
                    {"detection.ml.label": "malicious"},
                ]
            },
            {"features.vector.sql_keywords": {"$gt": 2}},
        ]
    }
    assert mapped == expected
