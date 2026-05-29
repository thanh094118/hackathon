import inspect
from collections.abc import Iterator
import pytest

from src.parser.apache_parser import ApacheParser
from src.parser.base_parser import BaseParser
from src.parser.iis_parser import IISParser
from src.parser.nginx_parser import NginxParser


# ============================================================
# PARSER TESTS
# Mục tiêu:
# - Kiểm tra parser Apache / Nginx / IIS parse đúng log thực tế.
# - Bắt các lỗi schema không nhất quán giữa success/error record.
# - Bắt lỗi Nginx profile ambiguous: combined / combined_with_tail.
# - Bắt lỗi IISParser override parse_lines làm lệch BaseParser.
# - Bắt lỗi IISParser stateful khi reuse parser cho nhiều file.
# - Bắt rủi ro event_id trùng khi merge nhiều file.
# - Bắt rủi ro parse_lines load toàn bộ vào RAM thay vì streaming.
# - Bắt các trường hợp log injection / malformed request.
# ============================================================


# ============================================================
# HELPERS
# ============================================================

REQUIRED_KEYS = {
    "parse_error",
    "parse_status",
    "error_message",
    "raw_log",
    "timestamp",
    "source_ip",
    "http_method",
    "raw_uri",
    "http_version",
    "status_code",
    "response_size",
    "referrer",
    "user_agent",
    "server_type",
    "line_number",
    "event_id",
}


def collect(result):
    """
    Helper:
    - Hỗ trợ cả implementation cũ trả list.
    - Hỗ trợ implementation mới trả generator/iterator.
    """
    return list(result)


def assert_common_schema(record):
    """
    Test contract chung:
    - Mọi record, kể cả record lỗi, phải có schema tối thiểu giống nhau.
    """
    assert REQUIRED_KEYS.issubset(record.keys())


def assert_error_record(record, message_contains=None):
    """
    Test contract record lỗi:
    - parse_error=True.
    - parse_status='error'.
    - Có error_message.
    - Các field semantic đã parse không được giả vờ là dữ liệu hợp lệ.
    """
    assert_common_schema(record)
    assert record["parse_error"] is True
    assert record["parse_status"] == "error"
    assert record["error_message"]

    if message_contains:
        assert message_contains in record["error_message"]

    assert record["http_method"] is None
    assert record["raw_uri"] is None
    assert record["http_version"] is None
    assert record["status_code"] is None
    assert record["response_size"] is None


# ============================================================
# BASE PARSER CONTRACT TESTS
# ============================================================


def test_base_parser_is_abstract_contract():
    assert inspect.isabstract(BaseParser)
    assert "parse_line" in BaseParser.__abstractmethods__
    assert BaseParser.server_type == "unknown"


def test_parse_lines_should_be_streaming_iterator_not_eager_list():
    parser = ApacheParser()
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /a HTTP/1.1" 200 10 "-" "ua"'

    result = parser.parse_lines([line])

    assert not isinstance(result, list)
    assert isinstance(result, Iterator)

    records = list(result)
    assert len(records) == 1
    assert records[0]["parse_error"] is False


def test_parser_event_id_supports_source_namespace_to_avoid_multi_file_collision():
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /same HTTP/1.1" 200 10 "-" "ua"'

    parser_a = ApacheParser()
    parser_b = ApacheParser()

    parser_a.set_event_namespace("fileA1234")
    parser_b.set_event_namespace("fileB5678")

    record_a = collect(parser_a.parse_lines([line]))[0]
    record_b = collect(parser_b.parse_lines([line]))[0]

    assert record_a["event_id"] != record_b["event_id"]
    assert record_a["event_id"].startswith("apache:1:fileA1234:")
    assert record_b["event_id"].startswith("apache:1:fileB5678:")


def test_error_records_use_consistent_minimum_schema_across_all_parsers():
    apache = collect(ApacheParser().parse_lines(["not apache format"]))[0]
    nginx = collect(NginxParser().parse_lines(["not nginx format"]))[0]
    iis = collect(IISParser().parse_lines([
        "2026-05-18 10:10:10 192.168.1.1 GET /index.php id=1 200 100 Mozilla/5.0 -"
    ]))[0]

    for record in (apache, nginx, iis):
        assert_error_record(record)


# ============================================================
# APACHE PARSER TESTS
# ============================================================


def test_apache_parser_success_combined_log():
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /a.php?id=1 HTTP/1.1" 200 123 "-" "ua"'

    record = collect(ApacheParser().parse_lines([line]))[0]

    assert_common_schema(record)
    assert record["parse_error"] is False
    assert record["parse_status"] == "success"
    assert record["server_type"] == "apache"
    assert record["http_method"] == "GET"
    assert record["raw_uri"] == "/a.php?id=1"
    assert record["original_url"] == "/a.php?id=1"
    assert record["status_code"] == 200
    assert record["response_size"] == 123
    assert record["event_id"].startswith("apache:1:")


def test_apache_parser_malformed_line_becomes_error_record():
    line = "this is not apache combined format"

    record = collect(ApacheParser().parse_lines([line]))[0]

    assert_error_record(record, "No Apache log pattern matched")
    assert record["line_number"] == 1
    assert record["raw_log"] == line


def test_apache_parser_request_field_mismatch_does_not_expose_partial_success_fields():
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET" 200 123 "-" "ua"'

    record = collect(ApacheParser().parse_lines([line]))[0]

    assert_error_record(record, "Request field")
    assert record["raw_log"] == line


@pytest.mark.parametrize(
    "bad_request",
    [
        'GET /a.php\\nInjected:1 HTTP/1.1',
        'GET /a.php\\rInjected:1 HTTP/1.1',
        'GET /a.php\\tInjected:1 HTTP/1.1',
        "GET /a.php\nInjected:1 HTTP/1.1",
        "GET /a.php\rInjected:1 HTTP/1.1",
        "GET /a.php\tInjected:1 HTTP/1.1",
    ],
)
def test_apache_parser_rejects_request_with_control_or_escaped_control_markers(bad_request):
    line = f'127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "{bad_request}" 200 123 "-" "ua"'

    record = collect(ApacheParser().parse_lines([line]))[0]

    assert_error_record(record, "control")


def test_apache_parser_accepts_request_without_http_version():
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /shell.php" 200 12 "-" "ua"'

    record = collect(ApacheParser().parse_lines([line]))[0]

    assert record["parse_error"] is False
    assert record["http_method"] == "GET"
    assert record["raw_uri"] == "/shell.php"
    assert record["http_version"] is None


def test_apache_parser_preserves_unencoded_space_in_attack_uri():
    line = (
        '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
        '"GET /a.php?id=1 UNION SELECT 1,2,3 HTTP/1.1" 200 123 "-" "ua"'
    )

    record = collect(ApacheParser().parse_lines([line]))[0]

    assert record["parse_error"] is False
    assert record["raw_uri"] == "/a.php?id=1 UNION SELECT 1,2,3"
    assert record["http_version"] == "HTTP/1.1"


def test_apache_parser_preserves_embedded_quote_payload_inside_request_uri():
    line = (
        '10.0.0.12 - - [23/Jan/2019:14:11:05 +0330] '
        '"GET /search?q=\"><svg/onload=alert(1)> HTTP/1.1" 200 15600 '
        '"https://www.zanbil.ir/" "Mozilla/5.0" "-"'
    )

    record = collect(ApacheParser().parse_lines([line]))[0]

    assert record["parse_error"] is False
    assert record["http_method"] == "GET"
    assert record["raw_uri"] == '/search?q="><svg/onload=alert(1)>'


# ============================================================
# NGINX PARSER TESTS
# ============================================================


def test_nginx_parser_should_not_inherit_from_apache_parser():
    assert not issubclass(NginxParser, ApacheParser)


def test_nginx_parser_success_combined_log():
    line = '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] "POST /login HTTP/1.1" 401 44 "-" "ua"'

    record = collect(NginxParser().parse_lines([line]))[0]

    assert_common_schema(record)
    assert record["parse_error"] is False
    assert record["server_type"] == "nginx"
    assert record["http_method"] == "POST"
    assert record["raw_uri"] == "/login"
    assert record["status_code"] == 401
    assert record.get("format_profile") == "combined"
    assert record.get("extra_tail") in (None, "")


def test_nginx_parser_combined_line_with_trailing_spaces_stays_combined_not_tail_profile():
    line = '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] "POST /login HTTP/1.1" 401 44 "-" "ua"   '

    record = collect(NginxParser().parse_lines([line]))[0]

    assert record["parse_error"] is False
    assert record["http_method"] == "POST"
    assert record["raw_uri"] == "/login"
    assert record.get("format_profile") == "combined"
    assert record.get("extra_tail") in (None, "")


def test_nginx_parser_combined_with_real_extra_tail_captures_tail_explicitly():
    line = (
        '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] '
        '"GET /search?q=1 HTTP/1.1" 200 512 "-" "ua" "example.com" 0.123'
    )

    record = collect(NginxParser().parse_lines([line]))[0]

    assert record["parse_error"] is False
    assert record["http_method"] == "GET"
    assert record["raw_uri"] == "/search?q=1"
    assert record["referrer"] == "-"
    assert record["user_agent"] == "ua"
    assert record.get("format_profile") == "combined_with_tail"
    assert record.get("extra_tail") == '"example.com" 0.123'


def test_nginx_parser_common_log_profile():
    line = '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] "GET /health HTTP/1.1" 200 12'

    record = collect(NginxParser().parse_lines([line]))[0]

    assert record["parse_error"] is False
    assert record["user_agent"] == "-"
    assert record["referrer"] == "-"
    assert record.get("format_profile") == "common"


@pytest.mark.parametrize(
    "bad_request",
    [
        'POST /login\\nInjected:1 HTTP/1.1',
        'POST /login\\rInjected:1 HTTP/1.1',
        'POST /login\\tInjected:1 HTTP/1.1',
        "POST /login\nInjected:1 HTTP/1.1",
        "POST /login\rInjected:1 HTTP/1.1",
        "POST /login\tInjected:1 HTTP/1.1",
    ],
)
def test_nginx_parser_rejects_request_with_control_or_escaped_control_markers(bad_request):
    line = f'10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] "{bad_request}" 401 44 "-" "ua"'

    record = collect(NginxParser().parse_lines([line]))[0]

    assert_error_record(record, "control")


def test_nginx_parser_accepts_request_without_http_version():
    line = '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] "GET /shell.php" 200 12 "-" "ua"'

    record = collect(NginxParser().parse_lines([line]))[0]

    assert record["parse_error"] is False
    assert record["http_method"] == "GET"
    assert record["raw_uri"] == "/shell.php"
    assert record["http_version"] is None


def test_nginx_parser_preserves_unencoded_space_in_attack_uri():
    line = (
        '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] '
        '"GET /product/32793?id=1 UNION SELECT 1,2,3-- HTTP/1.1" 500 245 "-" "ua" "-"'
    )

    record = collect(NginxParser().parse_lines([line]))[0]

    assert record["parse_error"] is False
    assert record["http_method"] == "GET"
    assert record["raw_uri"] == "/product/32793?id=1 UNION SELECT 1,2,3--"


def test_nginx_parser_preserves_embedded_quote_payload_inside_request_uri():
    line = (
        '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] '
        '"GET /search?q=<iframe src="javascript:alert(1)"></iframe> HTTP/1.1" '
        '200 100 "-" "ua" "-"'
    )

    record = collect(NginxParser().parse_lines([line]))[0]

    assert record["parse_error"] is False
    assert record["http_method"] == "GET"
    assert record["raw_uri"] == '/search?q=<iframe src="javascript:alert(1)"></iframe>'


def test_nginx_parser_missing_required_field_is_error():
    line = '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] "POST /login HTTP/1.1" 401'

    record = collect(NginxParser().parse_lines([line]))[0]

    assert_error_record(record)


def test_nginx_parser_field_order_change_is_error():
    line = '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] 401 "POST /login HTTP/1.1" 44 "-" "ua"'

    record = collect(NginxParser().parse_lines([line]))[0]

    assert_error_record(record)


# ============================================================
# IIS PARSER TESTS
# ============================================================


def test_iis_parser_should_delegate_common_parse_lines_contract_to_base_parser():
    source = inspect.getsource(IISParser.parse_lines)
    assert "super().parse_lines" in source


def test_iis_parser_success_with_fields_header():
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent) cs(Referer)",
        "2026-05-18 10:10:10 192.168.1.1 GET /index.php id=1 200 100 Mozilla/5.0 -",
    ]

    record = collect(IISParser().parse_lines(lines))[0]

    assert_common_schema(record)
    assert record["parse_error"] is False
    assert record["parse_status"] == "success"
    assert record["server_type"] == "iis"
    assert record["timestamp"] == "2026-05-18 10:10:10"
    assert record["source_ip"] == "192.168.1.1"
    assert record["http_method"] == "GET"
    assert record["raw_uri"] == "/index.php?id=1"
    assert record["original_url"] == "/index.php?id=1"
    assert record["status_code"] == 200
    assert record["response_size"] == 100


def test_iis_parser_handles_quoted_user_agent_and_referrer_with_spaces():
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent) cs(Referer)",
        '2026-05-18 10:10:10 192.168.1.1 GET /index.php id=1 200 100 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "https://example.com/start page"',
    ]

    record = collect(IISParser().parse_lines(lines))[0]

    assert record["parse_error"] is False
    assert record["user_agent"] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    assert record["referrer"] == "https://example.com/start page"


def test_iis_parser_without_header_is_parse_error():
    line = "2026-05-18 10:10:10 192.168.1.1 GET /index.php id=1 200 100 Mozilla/5.0 -"

    record = collect(IISParser().parse_lines([line]))[0]

    assert_error_record(record, "Missing #Fields")


def test_iis_parser_data_line_number_counts_success_only():
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent) cs(Referer)",
        "2026-05-18 10:10:10 192.168.1.1 GET /index.php id=1 200 100 Mozilla/5.0 -",
        "2026-05-18 10:10:11 192.168.1.2 GET /broken.php id=2 500",
        "2026-05-18 10:10:12 192.168.1.3 POST /submit.php - 201 40 curl/8.0 -",
    ]

    records = collect(IISParser().parse_lines(lines))

    assert [row["line_number"] for row in records] == [2, 3, 4]
    assert [row["parse_status"] for row in records] == ["success", "error", "success"]
    assert [row["data_line_number"] for row in records] == [1, None, 2]
    assert records[0]["event_id"].startswith("iis:2:")
    assert records[1]["event_id"].startswith("iis:3:")
    assert records[2]["event_id"].startswith("iis:4:")


def test_iis_parser_parse_lines_resets_fields_state_between_calls():
    parser = IISParser()

    lines1 = [
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent) cs(Referer)",
        "2026-05-18 10:10:10 192.168.1.1 GET /index.php id=1 200 100 Mozilla/5.0 -",
    ]
    lines2 = [
        "2026-05-18 10:10:10 192.168.1.2 GET /index.php id=2 200 100 Mozilla/5.0 -",
    ]

    first = collect(parser.parse_lines(lines1))
    second = collect(parser.parse_lines(lines2))

    assert first[0]["parse_error"] is False
    assert_error_record(second[0], "Missing #Fields")


def test_iis_parser_handles_changed_fields_header_in_same_file():
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-bytes",
        "2026-05-18 10:10:10 192.168.1.1 GET /a.php 200 100",
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent)",
        "2026-05-18 10:10:11 192.168.1.2 POST /b.php id=2 201 40 curl/8.0",
    ]

    records = collect(IISParser().parse_lines(lines))

    assert len(records) == 2
    assert records[0]["parse_error"] is False
    assert records[0]["raw_uri"] == "/a.php"
    assert records[0]["user_agent"] == "-"
    assert records[1]["parse_error"] is False
    assert records[1]["raw_uri"] == "/b.php?id=2"
    assert records[1]["user_agent"] == "curl/8.0"


def test_iis_parser_keeps_encoded_query_raw_in_parser_stage():
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent) cs(Referer)",
        "2026-05-18 10:10:10 192.168.1.1 GET /search.php q=%252fadmin%2bpanel 200 100 Mozilla/5.0 -",
    ]

    record = collect(IISParser().parse_lines(lines))[0]

    assert record["parse_error"] is False
    assert record["raw_uri"] == "/search.php?q=%252fadmin%2bpanel"
    assert record["original_url"] == "/search.php?q=%252fadmin%2bpanel"


def test_iis_parser_empty_query_dash_does_not_add_question_mark():
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes",
        "2026-05-18 10:10:10 192.168.1.1 GET /index.php - 200 100",
    ]

    record = collect(IISParser().parse_lines(lines))[0]

    assert record["parse_error"] is False
    assert record["raw_uri"] == "/index.php"
    assert record["original_url"] == "/index.php"


def test_iis_parser_missing_cs_uri_query_field_still_builds_raw_uri_from_stem_only():
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-bytes",
        "2026-05-18 10:10:10 192.168.1.1 GET /index.php 200 100",
    ]

    record = collect(IISParser().parse_lines(lines))[0]

    assert record["parse_error"] is False
    assert record["raw_uri"] == "/index.php"
    assert record["original_url"] == "/index.php"


def test_iis_parser_malformed_quoted_fields_becomes_error_record():
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent)",
        '2026-05-18 10:10:10 192.168.1.1 GET /index.php id=1 200 100 "Mozilla/5.0',
    ]

    record = collect(IISParser().parse_lines(lines))[0]

    assert_error_record(record, "quoted")


# ============================================================
# CROSS-PARSER DATA QUALITY / VALIDATION TESTS
# ============================================================


@pytest.mark.parametrize(
    "parser,line",
    [
        (
            ApacheParser(),
            'not-an-ip - - [10/Oct/2000:13:55:36 +0000] "GET /a HTTP/1.1" 200 10 "-" "ua"',
        ),
        (
            NginxParser(),
            'not-an-ip - - [10/Oct/2000:13:55:36 +0000] "GET /a HTTP/1.1" 200 10 "-" "ua"',
        ),
    ],
)
def test_parser_flags_invalid_source_ip(parser, line):
    record = collect(parser.parse_lines([line]))[0]

    assert_error_record(record, "source_ip")


@pytest.mark.parametrize(
    "parser,line",
    [
        (
            ApacheParser(),
            '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "G E T /a HTTP/1.1" 200 10 "-" "ua"',
        ),
        (
            NginxParser(),
            '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] "GETS\\x00 /a HTTP/1.1" 200 10 "-" "ua"',
        ),
    ],
)
def test_parser_flags_invalid_http_method(parser, line):
    record = collect(parser.parse_lines([line]))[0]

    assert_error_record(record, "http_method")


@pytest.mark.parametrize(
    "status_code",
    ["0", "99", "600", "700", "-1"],
)
def test_parser_flags_invalid_status_code_range(status_code):
    line = f'127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /a HTTP/1.1" {status_code} 10 "-" "ua"'

    record = collect(ApacheParser().parse_lines([line]))[0]

    assert_error_record(record, "status_code")


@pytest.mark.parametrize(
    "size",
    ["-2", "abc"],
)
def test_parser_flags_invalid_response_size(size):
    line = f'127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /a HTTP/1.1" 200 {size} "-" "ua"'

    record = collect(ApacheParser().parse_lines([line]))[0]

    assert_error_record(record, "response_size")


def test_parser_keeps_raw_log_for_success_and_error_records():
    success_line = '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /a HTTP/1.1" 200 10 "-" "ua"'
    error_line = "not apache format"

    records = collect(ApacheParser().parse_lines([success_line, error_line]))

    assert records[0]["raw_log"] == success_line
    assert records[1]["raw_log"] == error_line
