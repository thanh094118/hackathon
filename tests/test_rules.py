from src.detection.rule_detector import RuleDetector
import pytest


def test_rule_detector_flags_sqli_and_scanner():
    detector = RuleDetector("data/labels/attack_patterns.yaml")
    record = {
        "normalized_request": "get /index.php?id=1' or 1=1 -- sqlmap",
        "normalized_query_string": "id=1' or 1=1 --",
        "normalized_uri": "/index.php",
        "normalized_user_agent": "sqlmap/1.7",
        "normalized_url": "/index.php?id=1' or 1=1 --",
    }
    out = detector.detect(record)
    assert out["rule_label"] in {"suspicious", "malicious"}
    assert out["rule_score"] > 0
    assert "sqli" in out["attack_types"] or "scanner" in out["attack_types"]
    assert out["matched_rule_ids"]


def test_rule_detector_benign_request():
    detector = RuleDetector("data/labels/attack_patterns.yaml")
    record = {
        "normalized_request": "get /home",
        "normalized_query_string": "",
        "normalized_uri": "/home",
        "normalized_user_agent": "mozilla/5.0",
        "normalized_url": "/home",
    }
    out = detector.detect(record)
    assert out["rule_label"] == "benign"
    assert out["rule_score"] == 0
    assert out["matched_rule_ids"] == []


def test_rule_detector_rejects_invalid_rule_yaml(tmp_path):
    rules_path = tmp_path / "invalid_rules.yaml"
    rules_path.write_text(
        "sqli:\n"
        "  - id: bad_rule\n"
        "    field: request\n"
        "    type: regex\n"
        "    pattern: '([unclosed'\n"
        "    score: 10\n"
        "    severity: high\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        RuleDetector(str(rules_path))
