from src.features.feature_extractor import FeatureExtractor


def test_feature_extractor_detects_keywords_and_counts():
    extractor = FeatureExtractor()
    record = {
        "normalized_uri": "/index.php",
        "normalized_query_string": "id=1' or 1=1",
        "normalized_user_agent": "sqlmap/1.7",
        "normalized_request": "get /index.php?id=1' or 1=1 -- sqlmap/1.7",
        "status_code": 200,
        "response_size": 123,
    }
    features = extractor.extract(record)
    assert features["request_length"] > 0
    assert features["param_count"] == 1
    assert features["has_sql_keyword"] == 1
    assert features["is_scanner_user_agent"] == 1


def test_feature_enrich_prefixes_feature_keys():
    extractor = FeatureExtractor()
    enriched = extractor.enrich({"normalized_request": ""})
    assert any(key.startswith("feature_") for key in enriched.keys())
