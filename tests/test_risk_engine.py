from src.scoring.risk_engine import RiskEngine


def test_risk_engine_merges_rule_ml_and_feature_signals():
    scored = RiskEngine().score(
        {
            "rule_label": "suspicious",
            "rule_score": 60,
            "attack_type": "sqli",
            "attack_types": ["sqli"],
            "matched_rule_ids": ["sqli_union_select"],
            "ml_label": "attack",
            "ml_attack_probability": 0.82,
            "ml_attack_type": "xss",
            "ml_should_alert": True,
            "feature_has_sql_keyword": 1,
        }
    )

    assert scored["detection_method"] == "hybrid"
    assert scored["detection_sources"] == ["rules", "ml", "features"]
    assert scored["primary_signal"] == "ml"
    assert scored["attack_type"] == "xss"
    assert scored["attack_types"] == ["sqli", "xss"]
    assert scored["risk_input_scores"] == {
        "rules": 60,
        "ml": 82,
        "features": 8,
        "base": 82,
    }
    assert scored["risk_score"] == 90
    assert scored["final_label"] == "malicious"
    assert scored["should_alert"] is True


def test_risk_engine_can_alert_from_rules_plus_feature_bonus():
    scored = RiskEngine().score(
        {
            "rule_label": "benign",
            "rule_score": 20,
            "attack_type": "scanner",
            "attack_types": ["scanner"],
            "matched_rule_ids": ["scanner_user_agent"],
            "feature_is_scanner_user_agent": 1,
        }
    )

    assert scored["detection_method"] == "hybrid"
    assert scored["detection_sources"] == ["rules", "features"]
    assert scored["primary_signal"] == "rules"
    assert scored["risk_score"] == 26
    assert scored["final_label"] == "suspicious"
    assert scored["should_alert"] is True


def test_risk_engine_keeps_benign_records_in_hybrid_contract():
    scored = RiskEngine().score({"rule_score": 0, "rule_label": "benign"})

    assert scored["detection_method"] == "hybrid"
    assert scored["detection_sources"] == []
    assert scored["primary_signal"] == "none"
    assert scored["risk_input_scores"] == {
        "rules": 0,
        "ml": 0,
        "features": 0,
        "base": 0,
    }
    assert scored["final_label"] == "benign"
    assert scored["should_alert"] is False
