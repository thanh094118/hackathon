from src.parser.apache_parser import ApacheParser
from src.parser.iis_parser import IISParser
from src.parser.nginx_parser import NginxParser


def test_apache_parser_success():
    line = '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /a.php?id=1 HTTP/1.1" 200 123 "-" "ua"'
    record = ApacheParser().parse_lines([line])[0]
    assert record["parse_error"] is False
    assert record["parse_status"] == "success"
    assert record["http_method"] == "GET"
    assert record["raw_uri"] == "/a.php?id=1"
    assert record["original_url"] == "/a.php?id=1"
    assert record["event_id"].startswith("apache:1:")


def test_apache_parser_malformed_line_becomes_error_record():
    line = "this is not apache combined format"
    record = ApacheParser().parse_lines([line])[0]
    assert record["parse_error"] is True
    assert record["parse_status"] == "error"
    assert "error_message" in record
    assert record["line_number"] == 1


def test_apache_parser_rejects_trailing_fields():
    line = (
        '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] '
        '"GET /a.php?id=1 HTTP/1.1" 200 123 "-" "ua" EXTRA_FIELD'
    )
    record = ApacheParser().parse_lines([line])[0]
    assert record["parse_error"] is True
    assert record["parse_status"] == "error"


def test_nginx_parser_server_type():
    line = '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] "POST /login HTTP/1.1" 401 44 "-" "ua"'
    record = NginxParser().parse_lines([line])[0]
    assert record["server_type"] == "nginx"
    assert record["http_method"] == "POST"


def test_nginx_parser_accepts_combined_with_trailing_custom_fields():
    line = (
        '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] '
        '"GET /search?q=1 HTTP/1.1" 200 512 "-" "ua" "example.com" 0.123'
    )
    record = NginxParser().parse_lines([line])[0]
    assert record["parse_error"] is False
    assert record["parse_status"] == "success"
    assert record["http_method"] == "GET"
    assert record["raw_uri"] == "/search?q=1"


def test_nginx_parser_common_log_profile():
    line = '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] "GET /health HTTP/1.1" 200 12'
    record = NginxParser().parse_lines([line])[0]
    assert record["parse_error"] is False
    assert record["user_agent"] == "-"
    assert record["referrer"] == "-"


def test_nginx_parser_missing_required_field_is_error():
    line = '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] "POST /login HTTP/1.1" 401'
    record = NginxParser().parse_lines([line])[0]
    assert record["parse_error"] is True
    assert record["parse_status"] == "error"


def test_nginx_parser_field_order_change_is_error():
    line = '10.0.0.2 - - [10/Oct/2000:13:55:36 +0000] 401 "POST /login HTTP/1.1" 44 "-" "ua"'
    record = NginxParser().parse_lines([line])[0]
    assert record["parse_error"] is True
    assert record["parse_status"] == "error"


def test_iis_parser_success_with_fields_header():
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent) cs(Referer)",
        "2026-05-18 10:10:10 192.168.1.1 GET /index.php id=1 200 100 Mozilla/5.0 -",
    ]
    record = IISParser().parse_lines(lines)[0]
    assert record["parse_error"] is False
    assert record["parse_status"] == "success"
    assert record["original_url"] == "/index.php?id=1"


def test_iis_parser_handles_quoted_user_agent_and_referrer_with_spaces():
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent) cs(Referer)",
        '2026-05-18 10:10:10 192.168.1.1 GET /index.php id=1 200 100 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "https://example.com/start page"',
    ]
    record = IISParser().parse_lines(lines)[0]
    assert record["parse_error"] is False
    assert record["user_agent"] == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    assert record["referrer"] == "https://example.com/start page"


def test_iis_parser_without_header_is_parse_error():
    line = "2026-05-18 10:10:10 192.168.1.1 GET /index.php id=1 200 100 Mozilla/5.0 -"
    record = IISParser().parse_lines([line])[0]
    assert record["parse_error"] is True
    assert record["parse_status"] == "error"
