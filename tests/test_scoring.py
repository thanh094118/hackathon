from src.scoring.risk_engine import RiskEngine


def test_risk_engine_elevates_score_from_features():
    engine = RiskEngine()
    record = {
        "rule_score": 40,
        "feature_has_sql_keyword": 1,
        "feature_has_xss_keyword": 0,
        "feature_has_path_traversal": 1,
        "feature_is_scanner_user_agent": 1,
        "feature_special_char_count": 30,
        "feature_param_count": 12,
        "status_code": 200,
    }
    out = engine.score(record)
    assert out["risk_score"] > 40
    assert out["final_label"] in {"suspicious", "malicious"}
    assert out["should_alert"] is True


def test_risk_engine_benign_when_low_score():
    engine = RiskEngine()
    out = engine.score({"rule_score": 0})
    assert out["risk_score"] == 0
    assert out["final_label"] == "benign"
    assert out["should_alert"] is False
