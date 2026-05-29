from src.features.feature_extractor import FeatureExtractor


# ============================================================
# FEATURE EXTRACTOR TESTS
# Mục tiêu:
# - Kiểm tra feature vector numeric-only và schema cố định.
# - Tách feature theo field: URI / query / User-Agent.
# - Không chỉ đếm trên normalized_request gộp chung.
# - Entropy riêng cho URI/query/UA để tránh pha loãng payload.
# - Dùng metadata từ RequestPreprocessor: decode_depth, decode_changed,
#   decode_limit_reached, removed_control_chars.
# - Dùng flag invalid/missing từ Normalizer.
# - enrich() dùng prefix feature_ và không ghi đè field gốc.
# ============================================================


def base_record(**overrides):
    record = {
        "normalized_uri": "/index.php",
        "normalized_query_string": "id=1",
        "normalized_user_agent": "mozilla/5.0",
        "normalized_url": "/index.php?id=1",
        "normalized_method": "get",
        "normalized_request": "method=get | url=/index.php?id=1 | user_agent=mozilla/5.0",
        "status_code": 200,
        "response_size": 123,
        "status_code_missing": False,
        "status_code_invalid": False,
        "response_size_missing": False,
        "response_size_invalid": False,
        "decode_depth": 0,
        "decode_changed": False,
        "decode_depth_uri": 0,
        "decode_changed_uri": False,
        "decode_depth_query_string": 0,
        "decode_changed_query_string": False,
        "decode_depth_user_agent": 0,
        "decode_changed_user_agent": False,
        "decode_limit_reached": False,
        "removed_control_chars": False,
    }
    record.update(overrides)
    return record


def test_feature_extractor_detects_keywords_and_counts():
    """
    Test:
    - SQLi keyword/evasion cơ bản.
    - Scanner user-agent.
    - Query param count.

    Ý nghĩa:
    - Giữ lại behavior cũ nhưng trên feature schema mới.
    """
    extractor = FeatureExtractor()
    record = base_record(
        normalized_query_string="id=1' or 1=1",
        normalized_user_agent="sqlmap/1.7",
        normalized_url="/index.php?id=1' or 1=1",
        normalized_request="method=get | url=/index.php?id=1' or 1=1 -- | user_agent=sqlmap/1.7",
    )

    features = extractor.extract(record)

    assert features["request_length"] > 0
    assert features["param_count"] == 1
    assert features["has_sql_keyword"] == 1
    assert features["has_sqli_evasion_pattern"] == 1
    assert features["is_scanner_user_agent"] == 1


def test_feature_extractor_counts_are_split_by_uri_query_and_user_agent():
    """
    Test:
    - Slash/dot trong URI không bị trộn với User-Agent.
    - Quote/equals trong query được tính riêng.

    Ý nghĩa:
    - Fix vấn đề mọi count tính trên normalized_request gộp chung.
    """
    extractor = FeatureExtractor()
    record = base_record(
        normalized_uri="/a/b/../admin.php",
        normalized_query_string="id=1'&x=<script>",
        normalized_user_agent="mozilla/5.0 firefox/120.0",
        normalized_url="/a/b/../admin.php?id=1'&x=<script>",
        normalized_request=(
            "method=get | url=/a/b/../admin.php?id=1'&x=<script> "
            "| user_agent=mozilla/5.0 firefox/120.0"
        ),
    )

    features = extractor.extract(record)

    assert features["uri_slash_count"] == 4
    assert features["uri_dot_count"] == 3
    assert features["query_quote_count"] == 1
    assert features["query_equals_count"] == 2
    assert features["query_ampersand_count"] == 1
    assert features["query_angle_bracket_count"] == 2

    # UA dots/slashes counted separately, not confused with URI traversal.
    assert features["ua_slash_count"] == 2
    assert features["ua_dot_count"] == 2

    # Backward-compatible aggregate still exists.
    assert features["slash_count"] >= features["uri_slash_count"]


def test_feature_extractor_entropy_is_available_per_field():
    """
    Test:
    - Có entropy riêng cho URI/query/User-Agent.
    - Query obfuscated có entropy riêng, không chỉ entropy request gộp.

    Ý nghĩa:
    - Tránh payload ngắn trong query bị pha loãng bởi UA dài.
    """
    extractor = FeatureExtractor()
    record = base_record(
        normalized_uri="/search",
        normalized_query_string="q=%61%6c%65%72%74%28%31%29",
        normalized_user_agent="mozilla/5.0 " + "a" * 100,
        normalized_request=(
            "method=get | url=/search?q=%61%6c%65%72%74%28%31%29 "
            "| user_agent=mozilla/5.0 " + "a" * 100
        ),
    )

    features = extractor.extract(record)

    assert features["query_entropy"] > 0
    assert features["uri_entropy"] > 0
    assert features["ua_entropy"] > 0
    assert features["entropy"] > 0


def test_feature_extractor_uses_preprocessor_decode_metadata():
    """
    Test:
    - FeatureExtractor đọc decode_depth/decode_changed từ Preprocessor.

    Ý nghĩa:
    - Double/triple encoding là signal evasion rất quan trọng.
    """
    extractor = FeatureExtractor()
    record = base_record(
        decode_depth=3,
        decode_changed=True,
        decode_depth_uri=1,
        decode_changed_uri=True,
        decode_depth_query_string=3,
        decode_changed_query_string=True,
        decode_depth_user_agent=0,
        decode_changed_user_agent=False,
        decode_limit_reached=True,
        removed_control_chars=True,
    )

    features = extractor.extract(record)

    assert features["decode_depth"] == 3
    assert features["decode_changed"] == 1
    assert features["decode_depth_uri"] == 1
    assert features["decode_changed_uri"] == 1
    assert features["decode_depth_query"] == 3
    assert features["decode_changed_query"] == 1
    assert features["decode_depth_user_agent"] == 0
    assert features["decode_changed_user_agent"] == 0
    assert features["decode_limit_reached"] == 1
    assert features["removed_control_chars"] == 1


def test_feature_extractor_uses_normalizer_quality_flags():
    """
    Test:
    - FeatureExtractor giữ status/size invalid/missing flags.

    Ý nghĩa:
    - Không mất signal chất lượng dữ liệu từ Normalizer.
    """
    extractor = FeatureExtractor()
    record = base_record(
        status_code=0,
        status_code_invalid=True,
        status_code_missing=False,
        response_size=0,
        response_size_missing=True,
        response_size_invalid=False,
    )

    features = extractor.extract(record)

    assert features["status_code"] == 0
    assert features["status_code_invalid"] == 1
    assert features["status_code_missing"] == 0
    assert features["response_size"] == 0
    assert features["response_size_missing"] == 1
    assert features["response_size_invalid"] == 0


def test_feature_extractor_detects_sqli_comment_evasion_pattern():
    """
    Test:
    - OR/**/1=1 được detect bằng has_sqli_evasion_pattern.

    Ý nghĩa:
    - Fix giới hạn keyword exact 'or 1=1' quá ngây thơ.
    """
    extractor = FeatureExtractor()
    record = base_record(
        normalized_query_string="id=1'/**/or/**/1=1",
        normalized_url="/index.php?id=1'/**/or/**/1=1",
        normalized_request="method=get | url=/index.php?id=1'/**/or/**/1=1 | user_agent=ua",
    )

    features = extractor.extract(record)

    assert features["has_sql_keyword"] == 0
    assert features["has_sqli_evasion_pattern"] == 1


def test_feature_extractor_detects_xss_and_traversal_keywords():
    """
    Test:
    - XSS keyword.
    - Path traversal keyword.

    Ý nghĩa:
    - Baseline keyword feature vẫn hoạt động.
    """
    extractor = FeatureExtractor()
    xss = extractor.extract(base_record(
        normalized_query_string="q=<svg onload=alert(1)>",
        normalized_url="/search?q=<svg onload=alert(1)>",
        normalized_request="method=get | url=/search?q=<svg onload=alert(1)> | user_agent=ua",
    ))
    traversal = extractor.extract(base_record(
        normalized_uri="/../../etc/passwd",
        normalized_url="/../../etc/passwd",
        normalized_request="method=get | url=/../../etc/passwd | user_agent=ua",
    ))

    assert xss["has_xss_keyword"] == 1
    assert traversal["has_path_traversal"] == 1


def test_feature_schema_is_fixed_and_numeric_only():
    """
    Test:
    - extract() trả đúng FEATURE_NAMES.
    - Tất cả value là int/float.

    Ý nghĩa:
    - Train/inference sklearn không bị lệch cột.
    """
    extractor = FeatureExtractor()
    features = extractor.extract(base_record())

    assert list(features.keys()) == FeatureExtractor.FEATURE_NAMES
    assert extractor.feature_names() == FeatureExtractor.FEATURE_NAMES
    assert all(isinstance(value, (int, float)) for value in features.values())


def test_feature_enrich_prefixes_feature_keys_and_preserves_original_record():
    """
    Test:
    - enrich() thêm feature_ prefix.
    - Không ghi đè field gốc.
    - Có feature_version và feature_names để audit.

    Ý nghĩa:
    - Đúng convention pipeline enriched record.
    """
    extractor = FeatureExtractor()
    record = base_record(normalized_request="")
    enriched = extractor.enrich(record)

    assert enriched is not record
    assert enriched["normalized_uri"] == record["normalized_uri"]
    assert any(key.startswith("feature_") for key in enriched.keys())
    assert enriched["feature_uri_length"] == len(record["normalized_uri"])
    assert enriched["feature_version"] == FeatureExtractor.FEATURE_VERSION
    assert enriched["feature_names"] == FeatureExtractor.FEATURE_NAMES


def test_feature_extractor_fallback_builds_request_when_missing():
    """
    Test:
    - Nếu normalized_request thiếu, extractor build fallback từ method/url/ua.

    Ý nghĩa:
    - Không crash với record preprocess thiếu một vài field.
    """
    extractor = FeatureExtractor()
    record = {
        "normalized_method": "get",
        "normalized_uri": "/home",
        "normalized_query_string": "",
        "normalized_user_agent": "ua",
        "status_code": 200,
        "response_size": 10,
    }

    features = extractor.extract(record)

    assert features["request_length"] > 0
    assert features["uri_length"] == len("/home")
    assert features["user_agent_length"] == 2


def test_feature_extractor_parse_query_fallback_handles_malformed_query():
    """
    Test:
    - Query malformed không làm crash.
    - fallback split bằng & vẫn tạo param_count.

    Ý nghĩa:
    - Bảo toàn robustness của _safe_parse_query().
    """
    extractor = FeatureExtractor()
    record = base_record(normalized_query_string="a=1&broken&c=3")

    features = extractor.extract(record)

    assert features["param_count"] == 3
    assert features["param_name_count"] == 3
