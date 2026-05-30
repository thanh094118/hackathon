from datetime import timezone

import pytest

from src.normalizer.normalizer import Normalizer


# ============================================================
# NORMALIZER TESTS
# Mục tiêu:
# - Kiểm tra normalize parsed record từ Apache/Nginx/IIS về schema chung.
# - Bắt lỗi split URI/query với fragment malformed.
# - Bắt lỗi normalize_status phụ thuộc nhầm parse_error.
# - Bắt lỗi timestamp parse fail nhưng vẫn trả raw string.
# - Bắt lỗi dateutil quá permissive với IIS timestamp.
# - Bắt lỗi COMMON_FIELDS không enforce schema.
# - Bắt lỗi empty/missing value bị trộn lẫn.
# - Bắt lỗi không validate source_ip, http_method, status_code, response_size.
# - Bắt lỗi output type không nhất quán.
# - Bắt thiếu normalize_errors để debug chất lượng normalize.
# ============================================================


# ============================================================
# HELPERS
# ============================================================

COMMON_FIELDS = [
    "event_id",
    "timestamp",
    "source_ip",
    "http_method",
    "original_url",
    "raw_uri",
    "uri",
    "query_string",
    "fragment",
    "status_code",
    "status_code_invalid",
    "response_size",
    "response_size_missing",
    "response_size_invalid",
    "user_agent",
    "referrer",
    "server_type",
    "raw_log",
    "line_number",
    "parse_status",
    "parse_error",
    "parse_error_message",
    "normalize_status",
    "normalize_errors",
    "error_message",
]


def base_parsed(**overrides):
    """
    Helper:
    - Tạo parsed record hợp lệ tối thiểu từ parser.

    Ý nghĩa:
    - Mỗi test chỉ override field cần kiểm tra.
    - Giảm duplicate dữ liệu test và làm rõ mục tiêu từng test.
    """
    parsed = {
        "event_id": "apache:1:abc123",
        "timestamp": "10/Oct/2000:13:55:36 +0000",
        "source_ip": "127.0.0.1",
        "http_method": "GET",
        "raw_uri": "/index.html",
        "original_url": "/index.html",
        "status_code": "200",
        "response_size": "123",
        "user_agent": "ua",
        "referrer": "-",
        "server_type": "apache",
        "raw_log": '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 123 "-" "ua"',
        "line_number": 1,
        "parse_error": False,
        "parse_status": "success",
        "error_message": None,
    }
    parsed.update(overrides)
    return parsed


def normalize(**overrides):
    """
    Helper:
    - Normalize record hợp lệ sau khi override các field cần test.

    Ý nghĩa:
    - Test ngắn hơn, tập trung vào expected behavior.
    """
    return Normalizer().normalize(base_parsed(**overrides))


def assert_common_schema(out):
    """
    Test contract:
    - Output normalizer phải có schema chung và thứ tự field ổn định.

    Ý nghĩa:
    - Downstream JSONL/Parquet/SQL/model feature extractor không bị lệch field.
    """
    assert list(out.keys()) == COMMON_FIELDS


def assert_normalize_success(out):
    """
    Test contract:
    - Record normalize thành công không có normalize_errors.

    Ý nghĩa:
    - Tránh normalize_status success nhưng vẫn có lỗi ẩn.
    """
    assert out["normalize_status"] == "success"
    assert out["normalize_errors"] == []


def assert_normalize_error(out, *expected_errors):
    """
    Test contract:
    - Record normalize lỗi phải có normalize_status='error'.
    - normalize_errors phải nêu rõ lỗi.

    Ý nghĩa:
    - Dễ debug lỗi dữ liệu và đánh giá chất lượng normalize.
    """
    assert out["normalize_status"] == "error"
    assert isinstance(out["normalize_errors"], list)
    assert out["normalize_errors"]

    for error in expected_errors:
        assert error in out["normalize_errors"]


# ============================================================
# HAPPY PATH / SCHEMA TESTS
# ============================================================


def test_normalizer_outputs_common_flat_schema_for_success_record():
    """
    Test:
    - Record Apache hợp lệ được normalize ra flat schema chung.

    Ý nghĩa:
    - Đây là contract chính giữa Parser -> Normalizer -> Detector.
    - Schema phải ổn định, có event_id và normalize_errors.
    """
    out = normalize(raw_uri="/a.php?id=1&x=2", original_url="/a.php?id=1&x=2")

    assert_common_schema(out)
    assert out["event_id"] == "apache:1:abc123"
    assert out["timestamp"] == "2000-10-10T13:55:36+00:00"
    assert out["source_ip"] == "127.0.0.1"
    assert out["http_method"] == "GET"
    assert out["raw_uri"] == "/a.php?id=1&x=2"
    assert out["uri"] == "/a.php"
    assert out["query_string"] == "id=1&x=2"
    assert out["fragment"] is None
    assert out["status_code"] == 200
    assert out["status_code_invalid"] is False
    assert out["response_size"] == 123
    assert out["response_size_missing"] is False
    assert out["response_size_invalid"] is False
    assert out["user_agent"] == "ua"
    assert out["referrer"] is None
    assert out["server_type"] == "apache"
    assert out["parse_error"] is False
    assert out["parse_status"] == "success"
    assert out["parse_error_message"] is None
    assert out["error_message"] is None
    assert_normalize_success(out)


def test_normalizer_outputs_common_flat_schema_for_parse_error_record():
    """
    Test:
    - Record lỗi từ parser vẫn được normalize ra cùng schema chung.

    Ý nghĩa:
    - Downstream có thể lưu/audit record lỗi mà không cần special-case thiếu key.
    """
    parsed = base_parsed(
        timestamp=None,
        source_ip=None,
        http_method=None,
        raw_uri=None,
        original_url=None,
        status_code=None,
        response_size=None,
        user_agent=None,
        referrer=None,
        parse_error=True,
        parse_status="error",
        error_message="bad apache line",
        raw_log="bad apache line",
    )

    out = Normalizer().normalize(parsed)

    assert_common_schema(out)
    assert out["parse_error"] is True
    assert out["parse_status"] == "error"
    assert out["parse_error_message"] == "bad apache line"
    assert out["error_message"] == "bad apache line"
    assert_normalize_error(out, "parse_error")


def test_normalizer_uses_common_fields_as_schema_source_of_truth():
    """
    Test:
    - Normalizer.COMMON_FIELDS phải khớp schema output thực tế.

    Ý nghĩa:
    - Bắt lỗi khai báo COMMON_FIELDS nhưng không dùng.
    - Bắt lỗi event_id có trong output nhưng không có trong COMMON_FIELDS.
    """
    out = normalize()

    assert hasattr(Normalizer, "COMMON_FIELDS")
    assert Normalizer.COMMON_FIELDS == COMMON_FIELDS
    assert list(out.keys()) == Normalizer.COMMON_FIELDS


# ============================================================
# URI / QUERY / FRAGMENT TESTS
# ============================================================


def test_normalizer_splits_uri_and_query_and_keeps_original_url():
    """
    Test:
    - raw_uri có query chuẩn phải tách uri/query đúng.
    - original_url giữ lại giá trị gốc từ parser.

    Ý nghĩa:
    - Detector có thể dùng uri riêng và query riêng.
    - Vẫn giữ được request target gốc để audit.
    """
    out = normalize(
        raw_uri="/a.php?id=1&x=2",
        original_url="/a.php?id=1&x=2",
        http_method="get",
        response_size="-",
        user_agent="-",
        referrer="-",
    )

    assert out["uri"] == "/a.php"
    assert out["query_string"] == "id=1&x=2"
    assert out["fragment"] is None
    assert out["http_method"] == "GET"
    assert out["response_size"] == 0
    assert out["response_size_missing"] is True
    assert out["response_size_invalid"] is False
    assert out["original_url"] == "/a.php?id=1&x=2"
    assert out["user_agent"] is None
    assert out["referrer"] is None
    assert_normalize_success(out)


def test_normalizer_does_not_extract_query_from_fragment():
    """
    Test:
    - URI malformed có '?' nằm sau '#'.
    - query_string không được lấy nhầm từ fragment.

    Ý nghĩa:
    - Tránh bug _split_uri() fallback raw_uri.split('?') lấy sai query.
    """
    out = normalize(raw_uri="/index.html#frag?fake=1", original_url="/index.html#frag?fake=1")

    assert out["uri"] == "/index.html"
    assert out["query_string"] == ""
    assert out["fragment"] == "frag?fake=1"
    assert_normalize_success(out)


def test_normalizer_handles_normal_uri_with_query_and_fragment():
    """
    Test:
    - URI chuẩn có query trước fragment.

    Ý nghĩa:
    - Đảm bảo fix case malformed không làm hỏng case URL chuẩn.
    """
    out = normalize(raw_uri="/path?q=1#section", original_url="/path?q=1#section")

    assert out["uri"] == "/path"
    assert out["query_string"] == "q=1"
    assert out["fragment"] == "section"
    assert_normalize_success(out)


def test_normalizer_preserves_and_decodes_percent_encoded_uri_fields():
    """
    Test:
    - raw_uri giữ nguyên encoded value.
    - decode chi tiết được xử lý ở preprocessor stage.

    Ý nghĩa:
    - Giữ forensic raw value.
    - Đồng thời hỗ trợ detector bắt attack dạng percent-encoding.
    """
    out = normalize(
        raw_uri="/%2e%2e/%2e%2e/etc/passwd?q=%3Cscript%3E",
        original_url="/%2e%2e/%2e%2e/etc/passwd?q=%3Cscript%3E",
    )

    assert out["uri"] == "/%2e%2e/%2e%2e/etc/passwd"
    assert out["query_string"] == "q=%3Cscript%3E"
    assert_normalize_success(out)


def test_normalizer_uses_raw_uri_as_original_url_when_missing_but_marks_name_as_request_target():
    """
    Test:
    - Nếu original_url từ parser thiếu, normalizer dùng raw_uri.

    Ý nghĩa:
    - Không mất request target gốc.
    - original_url trong pipeline nên được hiểu là request target gốc, không nhất thiết là absolute URL.
    """
    out = normalize(raw_uri="/only/path?x=1", original_url=None)

    assert out["original_url"] == "/only/path?x=1"
    assert out["raw_uri"] == "/only/path?x=1"
    assert out["uri"] == "/only/path"
    assert out["query_string"] == "x=1"


# ============================================================
# TIMESTAMP TESTS
# ============================================================


@pytest.mark.parametrize("server_type", ["apache", "nginx"])
def test_normalizer_apache_nginx_timestamp_strict_parsing(server_type):
    """
    Test:
    - Apache/Nginx timestamp dùng format cố định CLF.
    - Parse thành ISO 8601 có timezone.

    Ý nghĩa:
    - Không dùng parser permissive cho format đã biết rõ.
    """
    out = normalize(server_type=server_type, timestamp="10/Oct/2000:13:55:36 +0700")

    assert out["timestamp"] == "2000-10-10T13:55:36+07:00"
    assert_normalize_success(out)


def test_normalizer_invalid_timestamp_becomes_error_and_none():
    """
    Test:
    - Timestamp hỏng không được trả raw string.

    Ý nghĩa:
    - Bắt lỗi _normalize_timestamp() nuốt exception rồi return value.
    - Downstream không nhận timestamp type không nhất quán.
    """
    out = normalize(timestamp="not-a-time")

    assert out["timestamp"] is None
    assert_normalize_error(out, "timestamp_invalid")


def test_normalizer_iis_timestamp_strict_parsing_and_utc_timezone():
    """
    Test:
    - IIS W3C timestamp hợp lệ parse bằng format cố định.
    - Vì IIS W3C convention là UTC, output có +00:00.

    Ý nghĩa:
    - Đúng convention IIS và tránh dateutil suy diễn quá rộng.
    """
    out = normalize(
        server_type="iis",
        timestamp="2026-05-29 13:45:01",
        raw_log="2026-05-29 13:45:01 10.0.0.1 GET /ok - 200 12",
    )

    assert out["timestamp"] == "2026-05-29T13:45:01+00:00"
    assert_normalize_success(out)


@pytest.mark.parametrize(
    "bad_timestamp",
    [
        "18",
        "2026/05/29 13:45:01",
        "2026-13-99 61:61:61",
        "2026-05-29",
        "13:45:01",
    ],
)
def test_normalizer_iis_rejects_permissive_or_corrupt_timestamp(bad_timestamp):
    """
    Test:
    - IIS timestamp sai format phải lỗi rõ ràng.

    Ý nghĩa:
    - Bắt lỗi dateutil.parser.parse() quá permissive.
    - Tránh timestamp corrupt bị suy diễn thành thời gian hợp lệ giả.
    """
    out = normalize(server_type="iis", timestamp=bad_timestamp)

    assert out["timestamp"] is None
    assert_normalize_error(out, "timestamp_invalid")


def test_normalizer_unknown_server_timestamp_does_not_use_overly_permissive_parse():
    """
    Test:
    - server_type không xác định không được parse timestamp tùy tiện.

    Ý nghĩa:
    - Tránh dữ liệu corrupt tạo timestamp giả khi chưa biết format log.
    """
    out = normalize(server_type="custom", timestamp="18")

    assert out["timestamp"] is None
    assert out["server_type"] is None
    assert_normalize_error(out, "server_type_invalid", "timestamp_invalid")


# ============================================================
# STATUS / ERROR STATE TESTS
# ============================================================


def test_normalize_status_tracks_normalizer_errors_not_only_parse_error():
    """
    Test:
    - parse_error=False nhưng normalize fail thì normalize_status phải là error.

    Ý nghĩa:
    - Bắt bug normalize_status chỉ phụ thuộc parse_error.
    """
    out = normalize(timestamp="bad-time", parse_error=False, parse_status="success")

    assert out["parse_error"] is False
    assert out["parse_status"] == "success"
    assert out["normalize_status"] == "error"
    assert "timestamp_invalid" in out["normalize_errors"]


def test_normalizer_missing_parse_status_no_longer_defaults_success():
    """
    Test:
    - parsed_record thiếu parse_status không được mặc định success.

    Ý nghĩa:
    - Tránh che lỗi upstream parser.
    """
    parsed = base_parsed()
    parsed.pop("parse_status")

    out = Normalizer().normalize(parsed)

    assert out["parse_status"] == "error"
    assert out["parse_error"] is True
    assert_normalize_error(out, "parse_status_missing")


def test_normalizer_parse_error_message_and_normalize_errors_are_separate():
    """
    Test:
    - Lỗi parser và lỗi normalizer được tách riêng.

    Ý nghĩa:
    - Debug rõ record lỗi do parser hay do normalizer.
    """
    out = normalize(
        parse_error=True,
        parse_status="error",
        error_message="parser failed",
        timestamp="bad-time",
    )

    assert out["parse_error"] is True
    assert out["parse_error_message"] == "parser failed"
    assert out["error_message"] == "parser failed"
    assert "parse_error" in out["normalize_errors"]
    assert "timestamp_invalid" in out["normalize_errors"]
    assert out["normalize_status"] == "error"


# ============================================================
# EMPTY / MISSING VALUE TESTS
# ============================================================


@pytest.mark.parametrize("value", [None, "", "-"])
def test_normalizer_clean_empty_text_values_to_none(value):
    """
    Test:
    - None, empty string, '-' đều normalize thành None cho text fields.

    Ý nghĩa:
    - Dùng NULL semantics rõ ràng thay vì empty string.
    - Dễ query SQL/parquet và giảm nhầm lẫn missing vs text rỗng.
    """
    out = normalize(user_agent=value, referrer=value)

    assert out["user_agent"] is None
    assert out["referrer"] is None


def test_normalizer_missing_raw_uri_becomes_none_fields_not_empty_strings():
    """
    Test:
    - raw_uri thiếu thì uri/query/fragment fields là None theo convention rõ ràng.

    Ý nghĩa:
    - Không tạo URI rỗng giả như một dữ liệu hợp lệ.
    """
    out = normalize(raw_uri=None, original_url=None)

    assert out["raw_uri"] is None
    assert out["original_url"] is None
    assert out["uri"] is None
    assert out["query_string"] is None
    assert out["fragment"] is None
    assert_normalize_success(out)


# ============================================================
# VALIDATION TESTS
# ============================================================


@pytest.mark.parametrize(
    "source_ip,expected",
    [
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "::1"),
        (" 10.0.0.1 ", "10.0.0.1"),
    ],
)
def test_normalizer_accepts_valid_ipv4_and_ipv6(source_ip, expected):
    """
    Test:
    - IPv4/IPv6 hợp lệ được chuẩn hóa.

    Ý nghĩa:
    - Hỗ trợ log thực tế có cả IPv4 và IPv6.
    """
    out = normalize(source_ip=source_ip)

    assert out["source_ip"] == expected
    assert_normalize_success(out)


@pytest.mark.parametrize(
    "source_ip",
    ["not-an-ip", "127.0.0.1';drop table x;--", "999.999.999.999", ""],
)
def test_normalizer_rejects_invalid_source_ip(source_ip):
    """
    Test:
    - source_ip không hợp lệ phải bị set None và ghi lỗi.

    Ý nghĩa:
    - Bắt rủi ro IP injection hoặc parser lệch field.
    """
    out = normalize(source_ip=source_ip)

    assert out["source_ip"] is None
    assert_normalize_error(out, "source_ip_invalid")


@pytest.mark.parametrize(
    "method",
    ["GET", "post", "Put", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"],
)
def test_normalizer_accepts_and_uppercases_valid_http_methods(method):
    """
    Test:
    - HTTP method hợp lệ được uppercase.

    Ý nghĩa:
    - 'get' -> 'GET' là normalize hợp lý.
    """
    out = normalize(http_method=method)

    assert out["http_method"] == method.upper()
    assert_normalize_success(out)


@pytest.mark.parametrize(
    "method",
    ["G E T", "GETS\x00", "BREW", "", None],
)
def test_normalizer_rejects_invalid_http_method(method):
    """
    Test:
    - Method ngoài whitelist phải bị set None và ghi lỗi.

    Ý nghĩa:
    - Bắt method injection hoặc request field bị parse sai.
    """
    out = normalize(http_method=method)

    assert out["http_method"] is None
    assert_normalize_error(out, "http_method_invalid")


@pytest.mark.parametrize(
    "status_code",
    ["100", "200", "301", "404", "500", "599"],
)
def test_normalizer_accepts_valid_http_status_range(status_code):
    """
    Test:
    - HTTP status hợp lệ 100..599 được convert sang int.

    Ý nghĩa:
    - Đảm bảo numeric field có type ổn định.
    """
    out = normalize(status_code=status_code)

    assert out["status_code"] == int(status_code)
    assert out["status_code_invalid"] is False
    assert_normalize_success(out)


@pytest.mark.parametrize(
    "status_code",
    [None, "", "0", "99", "600", "700", "-1", "abc"],
)
def test_normalizer_rejects_invalid_http_status_range(status_code):
    """
    Test:
    - status_code thiếu/sai/out-of-range không được thành 0 hợp lệ.

    Ý nghĩa:
    - Bắt lỗi _to_int() trả 0 khi parse fail.
    """
    out = normalize(status_code=status_code)

    assert out["status_code"] == 0
    assert out["status_code_invalid"] is True
    assert_normalize_error(out, "status_code_invalid")


@pytest.mark.parametrize(
    "response_size,expected,missing",
    [
        ("0", 0, False),
        ("123", 123, False),
        (0, 0, False),
        (123, 123, False),
        ("-", 0, True),
        (None, 0, True),
        ("", 0, True),
    ],
)
def test_normalizer_response_size_missing_and_valid_values(response_size, expected, missing):
    """
    Test:
    - response_size hợp lệ được convert int.
    - '-', None, '' được coi là missing, không phải invalid.

    Ý nghĩa:
    - Giữ convention Apache/Nginx '-' là không có size body.
    """
    out = normalize(response_size=response_size)

    assert out["response_size"] == expected
    assert out["response_size_missing"] is missing
    assert out["response_size_invalid"] is False
    assert_normalize_success(out)


@pytest.mark.parametrize("response_size", ["-1", "-10", "abc"])
def test_normalizer_rejects_invalid_response_size(response_size):
    """
    Test:
    - response_size âm hoặc không phải số phải bị flag invalid.

    Ý nghĩa:
    - Tránh thống kê/detect bị sai.
    """
    out = normalize(response_size=response_size)

    assert out["response_size"] == 0
    assert out["response_size_missing"] is False
    assert out["response_size_invalid"] is True
    assert_normalize_error(out, "response_size_invalid")


@pytest.mark.parametrize(
    "server_type,expected",
    [
        ("apache", "apache"),
        ("Apache", "apache"),
        ("NGINX ", "nginx"),
        ("iis", "iis"),
        (" IIS ", "iis"),
    ],
)
def test_normalizer_normalizes_valid_server_type(server_type, expected):
    """
    Test:
    - server_type được strip/lowercase.

    Ý nghĩa:
    - Tránh đi sai nhánh timestamp do 'NGINX ' hoặc 'Apache'.
    """
    timestamp = "2026-05-29 13:45:01" if expected == "iis" else "10/Oct/2000:13:55:36 +0000"

    out = normalize(server_type=server_type, timestamp=timestamp)

    assert out["server_type"] == expected
    assert_normalize_success(out)


@pytest.mark.parametrize("server_type", [None, "", "unknown", "tomcat"])
def test_normalizer_rejects_invalid_server_type(server_type):
    """
    Test:
    - server_type không thuộc apache/nginx/iis phải bị flag.

    Ý nghĩa:
    - Không parse timestamp bằng rule mơ hồ khi chưa biết log format.
    """
    out = normalize(server_type=server_type)

    assert out["server_type"] is None
    assert_normalize_error(out, "server_type_invalid")


# ============================================================
# TYPE CONSISTENCY TESTS
# ============================================================


def test_normalizer_timestamp_type_is_iso_string_or_none_only():
    """
    Test:
    - timestamp output chỉ được là ISO string hoặc None.

    Ý nghĩa:
    - Không để raw timestamp không-ISO lọt xuống downstream.
    """
    ok = normalize(timestamp="10/Oct/2000:13:55:36 +0000")
    bad = normalize(timestamp="bad-time")

    assert ok["timestamp"] == "2000-10-10T13:55:36+00:00"
    assert "T" in ok["timestamp"]
    assert bad["timestamp"] is None


def test_normalizer_numeric_types_are_consistent():
    """
    Test:
    - status_code và response_size luôn là int.
    - invalid/missing được biểu diễn bằng flag riêng.

    Ý nghĩa:
    - Feature extractor không bị lẫn str/int/None.
    """
    out = normalize(status_code="abc", response_size="-")

    assert isinstance(out["status_code"], int)
    assert isinstance(out["response_size"], int)
    assert out["status_code"] == 0
    assert out["response_size"] == 0
    assert out["status_code_invalid"] is True
    assert out["response_size_missing"] is True


def test_normalizer_boolean_flags_are_booleans():
    """
    Test:
    - Các flag phải là bool thật.

    Ý nghĩa:
    - Tránh downstream so sánh nhầm string 'False' là truthy.
    """
    out = normalize(status_code="abc", response_size="-10")

    bool_fields = [
        "parse_error",
        "status_code_invalid",
        "response_size_missing",
        "response_size_invalid",
    ]

    for field in bool_fields:
        assert isinstance(out[field], bool)
