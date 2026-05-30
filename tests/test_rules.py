from pathlib import Path

import pytest
import yaml

from src.detection.rule_detector import RuleDetector


# ============================================================
# RULE DETECTOR TESTS
# Mục tiêu:
# - Kiểm tra detector match SQLi / scanner / XSS / traversal.
# - Kiểm tra benign không bị flag.
# - Kiểm tra field thiếu không silent fail.
# - Kiểm tra score aggregation không cộng thô nhiều rule cùng category.
# - Kiểm tra regex được compile/cache khi load rules.
# - Kiểm tra strict=True raise, strict=False skip invalid rule.
# - Kiểm tra YAML size guard và ReDoS heuristic.
# - Kiểm tra reload_rules() và enrich output.
# ============================================================


def make_record(**overrides):
    record = {
        "normalized_request": "method=get | url=/home | user_agent=mozilla/5.0",
        "normalized_query_string": "",
        "normalized_uri": "/home",
        "normalized_user_agent": "mozilla/5.0",
        "normalized_url": "/home",
        "raw_uri": "/home",
        "status_code": 200,
        "decode_depth": 0,
        "removed_control_chars": False,
    }
    record.update(overrides)
    return record


def write_rules(tmp_path: Path, rules: dict) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(rules, sort_keys=False), encoding="utf-8")
    return path


def test_rule_detector_flags_sqli_and_scanner():
    """
    Test:
    - SQLi trong query.
    - Scanner trong User-Agent.
    - Output có score_by_category và matched_rule_ids.

    Ý nghĩa:
    - Happy path chính của detector.
    """
    detector = RuleDetector("src/rules/attack_patterns.yaml")
    record = make_record(
        normalized_request="method=get | url=/index.php?id=1' or 1=1 -- | user_agent=sqlmap/1.7",
        normalized_query_string="id=1' or 1=1 --",
        normalized_uri="/index.php",
        normalized_user_agent="sqlmap/1.7",
        normalized_url="/index.php?id=1' or 1=1 --",
        raw_uri="/index.php?id=1%27%20or%201%3D1%20--",
    )

    out = detector.detect(record)

    assert out["rule_label"] in {"suspicious", "malicious"}
    assert out["rule_score"] > 0
    assert {"sqli", "scanner"}.issubset(set(out["attack_types"]))
    assert out["score_by_category"]["sqli"] >= 20
    assert out["score_by_category"]["scanner"] >= 25
    assert out["matched_rule_ids"]
    assert out["detector_status"] == "success"


def test_rule_detector_benign_request():
    """
    Test:
    - Request lành tính không match rule nào.

    Ý nghĩa:
    - Kiểm tra false positive cơ bản.
    """
    detector = RuleDetector("src/rules/attack_patterns.yaml")
    record = make_record()

    out = detector.detect(record)

    assert out["rule_label"] == "benign"
    assert out["rule_score"] == 0
    assert out["rule_severity"] == "none"
    assert out["attack_type"] is None
    assert out["attack_types"] == []
    assert out["matched_rule_ids"] == []
    assert out["score_by_category"] == {}
    assert out["severity_by_category"] == {}
    assert out["detector_status"] == "success"


def test_rule_detector_detects_non_script_xss_vectors():
    """
    Test:
    - XSS không dùng <script>: <svg onload=...>.

    Ý nghĩa:
    - Bắt vấn đề YAML chỉ có xss_script_tag quá hẹp.
    """
    detector = RuleDetector("src/rules/attack_patterns.yaml")
    record = make_record(
        normalized_request="method=get | url=/search?q=<svg onload=alert(1)> | user_agent=ua",
        normalized_query_string="q=<svg onload=alert(1)>",
        normalized_url="/search?q=<svg onload=alert(1)>",
    )

    out = detector.detect(record)

    assert "xss" in out["attack_types"]
    assert "xss_html_event_handler" in out["matched_rule_ids"]


def test_rule_detector_encoded_traversal_rule_uses_raw_uri():
    """
    Test:
    - Encoded traversal phải match trên raw_uri, không phụ thuộc normalized_url đã decode.

    Ý nghĩa:
    - Bắt lỗi rule encoded chạy nhầm trên normalized field.
    """
    detector = RuleDetector("src/rules/attack_patterns.yaml")
    record = make_record(
        raw_uri="/download?file=%252e%252e%252fetc/passwd",
        normalized_url="/download?file=../etc/passwd",
        normalized_uri="/download",
        normalized_query_string="file=../etc/passwd",
        normalized_request="method=get | url=/download?file=../etc/passwd | user_agent=ua",
    )

    out = detector.detect(record)

    assert "traversal" in out["attack_types"]
    assert (
        "traversal_encoded_dotdot_raw" in out["matched_rule_ids"]
        or "traversal_dotdot" in out["matched_rule_ids"]
    )


def test_sqli_comment_alone_does_not_match_without_sql_context():
    """
    Test:
    - Query chỉ có anchor/comment marker không nên bị đánh SQLi nếu thiếu SQL context.

    Ý nghĩa:
    - Giảm false positive của pattern (--|#|/*).
    """
    detector = RuleDetector("src/rules/attack_patterns.yaml")
    record = make_record(
        normalized_query_string="section=#intro",
        normalized_url="/docs?section=#intro",
        normalized_request="method=get | url=/docs?section=#intro | user_agent=mozilla/5.0",
    )

    out = detector.detect(record)

    assert "sqli_comment_with_context" not in out["matched_rule_ids"]
    assert "sqli" not in out["attack_types"]


def test_missing_rule_field_is_reported_not_silent(tmp_path):
    """
    Test:
    - Rule trỏ đến field không tồn tại trong record.
    - Detector phải ghi detector_errors.

    Ý nghĩa:
    - Tránh YAML sai field nhưng silent fail.
    """
    rules = {
        "custom": [
            {
                "id": "missing_field_rule",
                "field": "missing_field",
                "type": "contains",
                "pattern": "abc",
                "score": 10,
                "severity": "low",
            }
        ]
    }
    path = write_rules(tmp_path, rules)
    detector = RuleDetector(path)

    out = detector.detect(make_record())

    assert out["rule_label"] == "benign"
    assert out["detector_status"] == "error"
    assert out["detector_errors"] == ["field_missing:missing_field_rule:missing_field"]


def test_score_aggregation_uses_max_per_category_not_raw_sum(tmp_path):
    """
    Test:
    - 7 rule nhỏ cùng category cùng match.
    - Score không được cộng thô 7*15=105 rồi thành malicious.

    Ý nghĩa:
    - Giảm false malicious do nhiều tín hiệu yếu cùng loại.
    """
    rules = {
        "scanner": [
            {
                "id": f"weak_scanner_{i}",
                "field": "request",
                "type": "contains",
                "pattern": "scanner",
                "score": 15,
                "severity": "low",
            }
            for i in range(7)
        ]
    }
    path = write_rules(tmp_path, rules)
    detector = RuleDetector(path)

    out = detector.detect(make_record(normalized_request="scanner scanner scanner"))

    assert len(out["matched_rule_ids"]) == 7
    assert out["score_by_category"] == {"scanner": 15}
    assert out["rule_score"] == 15
    assert out["rule_label"] == "benign"


def test_multi_category_bonus_is_small_and_explainable(tmp_path):
    """
    Test:
    - Score = sum(max score/category) + 10*(category_count-1).

    Ý nghĩa:
    - Có bonus khi nhiều loại attack cùng xuất hiện nhưng không cộng thô mọi rule.
    """
    rules = {
        "sqli": [
            {
                "id": "sqli_a",
                "field": "request",
                "type": "contains",
                "pattern": "select",
                "score": 30,
                "severity": "medium",
            }
        ],
        "scanner": [
            {
                "id": "scanner_a",
                "field": "request",
                "type": "contains",
                "pattern": "sqlmap",
                "score": 20,
                "severity": "medium",
            }
        ],
    }
    path = write_rules(tmp_path, rules)
    detector = RuleDetector(path)

    out = detector.detect(make_record(normalized_request="select from users sqlmap"))

    assert out["score_by_category"] == {"scanner": 20, "sqli": 30}
    assert out["rule_score"] == 60


def test_regex_rules_are_compiled_and_cached_on_load(tmp_path):
    """
    Test:
    - Regex rule có _compiled sau khi load.

    Ý nghĩa:
    - Tránh compile regex lại mỗi lần match.
    """
    rules = {
        "xss": [
            {
                "id": "regex_rule",
                "field": "request",
                "type": "regex",
                "pattern": "<script",
                "score": 50,
                "severity": "high",
            }
        ]
    }
    path = write_rules(tmp_path, rules)
    detector = RuleDetector(path)

    compiled = detector.rules["xss"][0].get("_compiled")

    assert compiled is not None
    assert compiled.search("<SCRIPT>alert(1)</SCRIPT>")


def test_rule_detector_rejects_invalid_rule_yaml(tmp_path):
    """
    Test:
    - strict=True: regex invalid làm detector raise ValueError.

    Ý nghĩa:
    - CI/test fail-fast khi rule sai.
    """
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


def test_rule_detector_lenient_mode_skips_invalid_rule(tmp_path):
    """
    Test:
    - strict=False: rule lỗi bị skip, detector vẫn chạy.

    Ý nghĩa:
    - Production có thể warn-and-skip thay vì crash toàn bộ.
    """
    rules_path = tmp_path / "invalid_rules.yaml"
    rules_path.write_text(
        "sqli:\n"
        "  - id: bad_rule\n"
        "    field: request\n"
        "    type: regex\n"
        "    pattern: '([unclosed'\n"
        "    score: 10\n"
        "    severity: high\n"
        "  - id: good_rule\n"
        "    field: request\n"
        "    type: contains\n"
        "    pattern: select\n"
        "    score: 30\n"
        "    severity: medium\n",
        encoding="utf-8",
    )

    detector = RuleDetector(str(rules_path), strict=False)
    out = detector.detect(make_record(normalized_request="select from users"))

    assert detector.load_errors
    assert [r["id"] for r in detector.rules["sqli"]] == ["good_rule"]
    assert out["matched_rule_ids"] == ["good_rule"]


def test_rule_detector_rejects_oversized_yaml(tmp_path):
    """
    Test:
    - YAML vượt max_yaml_size_bytes bị reject trước safe_load.

    Ý nghĩa:
    - Giảm rủi ro resource exhaustion.
    """
    rules_path = tmp_path / "huge_rules.yaml"
    rules_path.write_text("x" * 100, encoding="utf-8")

    with pytest.raises(ValueError, match="too large"):
        RuleDetector(rules_path, max_yaml_size_bytes=10)


def test_rule_detector_rejects_redos_risky_regex_in_strict_mode(tmp_path):
    """
    Test:
    - Pattern có nested quantifier dạng (a+)+b bị reject ở strict mode.

    Ý nghĩa:
    - Compile regex thành công không đảm bảo an toàn ReDoS.
    """
    rules = {
        "redos": [
            {
                "id": "redos_rule",
                "field": "request",
                "type": "regex",
                "pattern": "(a+)+b",
                "score": 10,
                "severity": "low",
            }
        ]
    }
    path = write_rules(tmp_path, rules)

    with pytest.raises(ValueError, match="ReDoS"):
        RuleDetector(path, strict=True)


def test_rule_detector_allows_redos_risky_regex_in_lenient_mode_but_warns(tmp_path):
    """
    Test:
    - strict=False không crash với risky regex, nhưng vẫn load.

    Ý nghĩa:
    - Production có thể tiếp tục nếu chấp nhận rủi ro, nhưng cần log warning.
    """
    rules = {
        "redos": [
            {
                "id": "redos_rule",
                "field": "request",
                "type": "regex",
                "pattern": "(a+)+b",
                "score": 10,
                "severity": "low",
            }
        ]
    }
    path = write_rules(tmp_path, rules)

    detector = RuleDetector(path, strict=False)

    assert detector.rules["redos"][0]["_compiled"] is not None
    assert "_redos_warning" in detector.rules["redos"][0]


def test_rule_detector_truncates_very_long_target_and_reports_error(tmp_path):
    """
    Test:
    - Target quá dài bị truncate trước khi regex search.
    - detector_errors ghi nhận target_truncated.

    Ý nghĩa:
    - Giảm rủi ro regex trên request cực lớn.
    """
    rules = {
        "test": [
            {
                "id": "long_rule",
                "field": "request",
                "type": "contains",
                "pattern": "needle",
                "score": 10,
                "severity": "low",
            }
        ]
    }
    path = write_rules(tmp_path, rules)
    detector = RuleDetector(path, max_target_length=10)

    out = detector.detect(make_record(normalized_request="x" * 100 + "needle"))

    assert out["matched_rule_ids"] == []
    assert out["detector_status"] == "error"
    assert "target_truncated:long_rule:normalized_request" in out["detector_errors"]


def test_rule_detector_reload_rules(tmp_path):
    """
    Test:
    - reload_rules() cập nhật ruleset không cần tạo detector mới.

    Ý nghĩa:
    - Hỗ trợ pipeline long-running.
    """
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "a:\n"
        "  - id: rule_a\n"
        "    field: request\n"
        "    type: contains\n"
        "    pattern: alpha\n"
        "    score: 10\n"
        "    severity: low\n",
        encoding="utf-8",
    )
    detector = RuleDetector(rules_path)
    assert detector.detect(make_record(normalized_request="alpha"))["matched_rule_ids"] == ["rule_a"]

    rules_path.write_text(
        "b:\n"
        "  - id: rule_b\n"
        "    field: request\n"
        "    type: contains\n"
        "    pattern: beta\n"
        "    score: 20\n"
        "    severity: medium\n",
        encoding="utf-8",
    )

    detector.reload_rules()

    assert detector.detect(make_record(normalized_request="alpha"))["matched_rule_ids"] == []
    assert detector.detect(make_record(normalized_request="beta"))["matched_rule_ids"] == ["rule_b"]


def test_rule_detector_can_return_enriched_record():
    """
    Test:
    - detect(enrich=True) trả record gốc + detection fields.

    Ý nghĩa:
    - Nhất quán với pipeline enriched record của các module trước.
    """
    detector = RuleDetector("src/rules/attack_patterns.yaml")
    record = make_record(
        event_id="evt1",
        normalized_request="method=get | url=/search?q=<script>alert(1)</script> | user_agent=ua",
        normalized_query_string="q=<script>alert(1)</script>",
        normalized_url="/search?q=<script>alert(1)</script>",
    )

    out = detector.detect(record, enrich=True)

    assert out["event_id"] == "evt1"
    assert out["normalized_request"] == record["normalized_request"]
    assert "xss" in out["attack_types"]
    assert out["rule_score"] > 0


def test_rule_detector_result_contains_rule_version():
    """
    Test:
    - Output có rule_version hash.

    Ý nghĩa:
    - Audit được kết quả detect sinh ra từ ruleset nào.
    """
    detector = RuleDetector("src/rules/attack_patterns.yaml")
    out = detector.detect(make_record())

    assert isinstance(out["rule_version"], str)
    assert len(out["rule_version"]) == 12
