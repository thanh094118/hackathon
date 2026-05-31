from __future__ import annotations

from src.schemas.mongodb_schema import flat_to_nested, nested_to_flat, is_nested_schema


def test_flat_to_nested_conversion():
    flat_doc = {
        "event_id": "test-123",
        "timestamp": "2026-05-31T00:00:00Z",
        "source_ip": "1.2.3.4",
        "http_method": "GET",
        "uri": "/admin",
        "query_string": "x=1",
        "status_code": 200,
        "response_content_length": 500,
        "user_agent": "Mozilla",
        "raw_log": "GET /admin",
        "decode_depth": 3,
        "decode_changed": True,
        "feature_length": 5,
        "feature_has_sql_keywords": 1.0,
        "feature_version": "v1.2",
        "rule_score": 80,
        "rule_severity": "high",
        "matched_rule_ids": ["r1", "r2"],
        "attack_type": "SQLI",
        "ml_label": "malicious",
        "ml_attack_type": "SQLI",
        "ml_attack_probability": 0.95,
        "ml_should_alert": True,
        "risk_score": 90,
        "risk_level": "critical",
        "final_label": "malicious",
        "should_alert": True,
        "embedding": [0.1, 0.2, 0.3],
    }

    nested = flat_to_nested(flat_doc)

    assert is_nested_schema(nested) is True
    assert nested["event_id"] == "test-123"
    assert nested["timestamp"] == "2026-05-31T00:00:00Z"
    
    assert nested["request"]["source_ip"] == "1.2.3.4"
    assert nested["request"]["method"] == "GET"
    assert nested["request"]["uri"] == "/admin"
    assert nested["request"]["query_string"] == "x=1"
    assert nested["request"]["status_code"] == 200
    assert nested["request"]["response_size"] == 500
    assert nested["request"]["user_agent"] == "Mozilla"
    assert nested["request"]["raw_log"] == "GET /admin"

    assert nested["preprocessed"]["decode"]["depth"] == 3
    assert nested["preprocessed"]["decode"]["changed"] is True

    assert nested["features"]["version"] == "v1.2"
    assert nested["features"]["vector"]["length"] == 5
    assert nested["features"]["vector"]["has_sql_keywords"] == 1.0

    assert nested["detection"]["rules"]["score"] == 80
    assert nested["detection"]["rules"]["severity"] == "high"
    assert nested["detection"]["rules"]["matched_ids"] == ["r1", "r2"]
    assert nested["detection"]["rules"]["attack_type"] == "SQLI"

    assert nested["detection"]["ml"]["label"] == "malicious"
    assert nested["detection"]["ml"]["attack_type"] == "SQLI"
    assert nested["detection"]["ml"]["probability"] == 0.95
    assert nested["detection"]["ml"]["should_alert"] is True

    assert nested["scoring"]["risk_score"] == 90
    assert nested["scoring"]["risk_level"] == "critical"
    assert nested["scoring"]["final_label"] == "malicious"
    assert nested["scoring"]["should_alert"] is True

    assert nested["embedding"] == [0.1, 0.2, 0.3]


def test_nested_to_flat_conversion():
    nested_doc = {
        "_schema_version": 2,
        "event_id": "test-123",
        "timestamp": "2026-05-31T00:00:00Z",
        "request": {
            "source_ip": "1.2.3.4",
            "method": "GET",
            "uri": "/admin",
            "query_string": "x=1",
            "status_code": 200,
            "response_size": 500,
            "user_agent": "Mozilla",
            "raw_log": "GET /admin",
        },
        "preprocessed": {
            "decode": {
                "depth": 3,
                "changed": True,
            }
        },
        "features": {
            "version": "v1.2",
            "vector": {
                "length": 5,
                "has_sql_keywords": 1.0,
            }
        },
        "detection": {
            "rules": {
                "score": 80,
                "severity": "high",
                "matched_ids": ["r1", "r2"],
                "attack_type": "SQLI",
            },
            "ml": {
                "label": "malicious",
                "attack_type": "SQLI",
                "probability": 0.95,
                "should_alert": True,
            }
        },
        "scoring": {
            "risk_score": 90,
            "risk_level": "critical",
            "final_label": "malicious",
            "should_alert": True,
        },
        "embedding": [0.1, 0.2, 0.3],
    }

    flat = nested_to_flat(nested_doc)

    assert flat["event_id"] == "test-123"
    assert flat["timestamp"] == "2026-05-31T00:00:00Z"
    
    assert flat["source_ip"] == "1.2.3.4"
    assert flat["http_method"] == "GET"
    assert flat["uri"] == "/admin"
    assert flat["query_string"] == "x=1"
    assert flat["status_code"] == 200
    assert flat["response_size"] == 500
    assert flat["user_agent"] == "Mozilla"
    assert flat["raw_log"] == "GET /admin"

    assert flat["decode_depth"] == 3
    assert flat["decode_changed"] is True

    assert flat["feature_version"] == "v1.2"
    assert flat["feature_length"] == 5
    assert flat["feature_has_sql_keywords"] == 1.0

    assert flat["rule_score"] == 80
    assert flat["rule_severity"] == "high"
    assert flat["matched_rule_ids"] == ["r1", "r2"]
    assert flat["attack_type"] == "SQLI"

    assert flat["ml_label"] == "malicious"
    assert flat["ml_attack_type"] == "SQLI"
    assert flat["ml_attack_probability"] == 0.95
    assert flat["ml_should_alert"] is True

    assert flat["risk_score"] == 90
    assert flat["risk_level"] == "critical"
    assert flat["final_label"] == "malicious"
    assert flat["should_alert"] is True

    assert flat["embedding"] == [0.1, 0.2, 0.3]
