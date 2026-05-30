import pytest
from src.preprocessor.request_preprocessor import RequestPreprocessor


# ============================================================
# REQUEST PREPROCESSOR TESTS
# Mục tiêu:
# - Kiểm tra decode URI/query đúng ngữ cảnh.
# - URI path dùng unquote(): giữ nguyên dấu '+' literal.
# - Query string dùng unquote_plus(): '+' thành space.
# - Decode được percent-encoding nhiều lớp và HTML entity.
# - Normalize Unicode NFKC để chống fullwidth/homoglyph bypass.
# - Loại bỏ control chars, null-byte, zero-width, soft hyphen.
# - Giữ ranh giới field trong normalized_request.
# - Có metadata decode_depth, decode_changed, decode_limit_reached.
# - Có preprocess_status/preprocess_errors để debug.
# - Không mutate input record.
# - Có guard khi preprocess lại record hoặc input quá dài.
# ============================================================


def test_preprocessor_decodes_and_normalizes_request_text():
    """
    Test:
    - URI percent-encoded được decode.
    - Query double-encoded được decode nhiều vòng.
    - User-Agent được lowercase.
    - normalized_request dùng boundary rõ ràng theo field.
    """
    record = {
        "http_method": "GET",
        "uri": "/search%2ephp",
        "query_string": "q=%2527%2520OR%25201%253D1",
        "user_agent": "SQLMap/1.7",
    }

    out = RequestPreprocessor().preprocess(record)

    assert out["decoded_uri"] == "/search.php"
    assert out["decoded_query_string"] == "q=' OR 1=1"
    assert out["normalized_uri"] == "/search.php"
    assert out["normalized_query_string"] == "q=' or 1=1"
    assert out["normalized_user_agent"] == "sqlmap/1.7"
    assert out["normalized_method"] == "get"
    assert out["normalized_url"] == "/search.php?q=' or 1=1"

    assert out["normalized_request"] == (
        "method=get | url=/search.php?q=' or 1=1 | user_agent=sqlmap/1.7"
    )
    assert out["normalized_request_fields"] == {
        "method": "get",
        "url": "/search.php?q=' or 1=1",
        "uri": "/search.php",
        "query_string": "q=' or 1=1",
        "user_agent": "sqlmap/1.7",
    }

    assert out["decode_depth_uri"] == 1
    assert out["decode_depth_query_string"] == 2
    assert out["decode_depth_user_agent"] == 0
    assert out["decode_depth"] == 2
    assert out["decode_changed"] is True
    assert out["decode_changed_uri"] is True
    assert out["decode_changed_query_string"] is True
    assert out["decode_changed_user_agent"] is False
    assert out["preprocess_status"] == "success"
    assert out["preprocess_errors"] == []


def test_preprocessor_uri_path_plus_is_preserved_but_query_plus_becomes_space():
    """
    Test:
    - Trong URI path, '+' là ký tự literal nên phải giữ nguyên.
    - Trong query string, '+' đại diện cho space theo form-urlencoded.
    """
    record = {
        "http_method": "GET",
        "uri": "/docs/c++/file.cpp",
        "query_string": "q=c%2B%2B+guide",
        "user_agent": "ua",
    }

    out = RequestPreprocessor().preprocess(record)

    assert out["decoded_uri"] == "/docs/c++/file.cpp"
    assert out["normalized_uri"] == "/docs/c++/file.cpp"

    assert out["decoded_query_string"] == "q=c++ guide"
    assert out["normalized_query_string"] == "q=c++ guide"

    assert out["normalized_url"] == "/docs/c++/file.cpp?q=c++ guide"
    assert out["preprocess_status"] == "success"


def test_preprocessor_decodes_html_entity_payload():
    """
    Test:
    - HTML entity dạng &lt;script&gt; được decode thành <script>.
    """
    record = {
        "http_method": "GET",
        "uri": "/search",
        "query_string": "q=&lt;script&gt;alert(1)&lt;/script&gt;",
        "user_agent": "ua",
    }

    out = RequestPreprocessor().preprocess(record)

    assert out["decoded_query_string"] == "q=<script>alert(1)</script>"
    assert out["normalized_query_string"] == "q=<script>alert(1)</script>"
    assert out["decode_depth_query_string"] == 1
    assert out["decode_changed_query_string"] is True


def test_preprocessor_decodes_mixed_percent_and_html_entity_across_rounds():
    """
    Test:
    - Payload mixed encoding: %26lt%3Bscript%26gt%3B.
    - Round 1: &lt;script&gt;.
    - Round 2: <script>.
    """
    record = {
        "http_method": "GET",
        "uri": "/search",
        "query_string": "q=%26lt%3Bscript%26gt%3B",
        "user_agent": "ua",
    }

    out = RequestPreprocessor(max_decode_rounds=5).preprocess(record)

    assert out["decoded_query_string"] == "q=<script>"
    assert out["normalized_query_string"] == "q=<script>"
    assert out["decode_depth_query_string"] == 2
    assert out["decode_changed_query_string"] is True
    assert out["decode_limit_reached_query_string"] is False


def test_preprocessor_decodes_triple_encoded_payload_when_rounds_allow():
    record = {
        "http_method": "GET",
        "uri": "/search",
        "query_string": "q=%25252527",
        "user_agent": "ua",
    }

    out = RequestPreprocessor(max_decode_rounds=5).preprocess(record)

    assert out["decoded_query_string"] == "q='"
    assert out["normalized_query_string"] == "q='"
    assert out["decode_depth_query_string"] == 4
    assert out["decode_limit_reached_query_string"] is False
    assert out["preprocess_status"] == "success"

def test_preprocessor_flags_decode_limit_reached():
    record = {
        "http_method": "GET",
        "uri": "/search",
        "query_string": "q=%25252527",
        "user_agent": "ua",
    }

    out = RequestPreprocessor(max_decode_rounds=2).preprocess(record)

    assert out["decoded_query_string"] == "q=%2527"
    assert out["decode_depth_query_string"] == 2
    assert out["decode_limit_reached_query_string"] is True
    assert out["decode_limit_reached"] is True
    assert "decode_limit_reached_query_string" in out["preprocess_errors"]
    assert out["preprocess_status"] == "error"


def test_preprocessor_removes_nulls_control_chars_and_extra_spaces():
    """
    Test:
    - Loại bỏ null-byte và control chars.
    - Collapse nhiều whitespace thành một space.
    - Ghi nhận removed_control_chars.
    """
    record = {
        "http_method": "GET",
        "uri": "/a",
        "query_string": "x=\x00\x00  1",
        "user_agent": "A\x00  B",
    }

    out = RequestPreprocessor().preprocess(record)

    assert "\x00" not in out["normalized_request"]
    assert "  " not in out["normalized_request"]

    assert out["normalized_query_string"] == "x= 1"
    assert out["normalized_user_agent"] == "a b"

    assert out["decode_depth"] == 0
    assert out["decode_changed"] is False

    assert out["removed_control_chars"] is True
    assert out["removed_control_chars_query_string"] is True
    assert out["removed_control_chars_user_agent"] is True
    assert "control_chars_removed_query_string" in out["preprocess_errors"]
    assert "control_chars_removed_user_agent" in out["preprocess_errors"]
    assert out["preprocess_status"] == "error"


def test_preprocessor_removes_unicode_format_chars_and_soft_hyphen():
    """
    Test:
    - Xóa zero-width char U+200B.
    - Xóa soft hyphen U+00AD.
    - Xóa ESC/control char.
    """
    record = {
        "http_method": "GET",
        "uri": "/a\u200bl\x1bert",
        "query_string": "q=1",
        "user_agent": "Moz\u00adilla",
    }

    out = RequestPreprocessor().preprocess(record)

    assert out["normalized_uri"] == "/alert"
    assert out["normalized_user_agent"] == "mozilla"
    assert out["removed_control_chars"] is True
    assert "control_chars_removed_uri" in out["preprocess_errors"]
    assert "control_chars_removed_user_agent" in out["preprocess_errors"]


def test_preprocessor_unicode_nfkc_normalizes_fullwidth_payload():
    """
    Test:
    - Fullwidth Unicode được NFKC normalize về ASCII tương đương.
    """
    record = {
        "http_method": "GET",
        "uri": "/search",
        "query_string": "q=ａｌｅｒｔ（１）",
        "user_agent": "ua",
    }

    out = RequestPreprocessor().preprocess(record)

    assert out["normalized_query_string"] == "q=alert(1)"
    assert out["normalized_url"] == "/search?q=alert(1)"


def test_preprocessor_keeps_field_boundaries_in_normalized_request():
    """
    Test:
    - normalized_request không gộp method/url/user-agent bằng space mơ hồ.
    - Có normalized_request_fields để rule engine scan theo field.
    """
    record = {
        "http_method": "GET",
        "uri": "/path",
        "query_string": "q=1",
        "user_agent": "script/alert(1)",
    }

    out = RequestPreprocessor().preprocess(record)

    assert out["normalized_request"] == (
        "method=get | url=/path?q=1 | user_agent=script/alert(1)"
    )
    assert out["normalized_request_fields"]["method"] == "get"
    assert out["normalized_request_fields"]["url"] == "/path?q=1"
    assert out["normalized_request_fields"]["uri"] == "/path"
    assert out["normalized_request_fields"]["query_string"] == "q=1"
    assert out["normalized_request_fields"]["user_agent"] == "script/alert(1)"


def test_preprocessor_supports_custom_field_separator():
    """
    Test:
    - Cho phép cấu hình separator khác nếu rule engine cần.
    """
    record = {
        "http_method": "GET",
        "uri": "/a",
        "query_string": "x=1",
        "user_agent": "ua",
    }

    out = RequestPreprocessor(field_separator=" || ").preprocess(record)

    assert out["normalized_request"] == "method=get || url=/a?x=1 || user_agent=ua"


def test_preprocessor_does_not_mutate_input_record():
    """
    Test:
    - preprocess() trả record mới, không sửa object gốc.
    """
    record = {
        "http_method": "GET",
        "uri": "/a",
        "query_string": "x=1",
        "user_agent": "ua",
    }

    out = RequestPreprocessor().preprocess(record)

    assert out is not record
    assert "decoded_uri" not in record
    assert "normalized_request" not in record


def test_preprocessor_conflict_can_raise_when_overwrite_disabled():
    """
    Test:
    - Nếu record đã có field preprocess và overwrite_existing=False,
      phải báo lỗi.
    """
    record = {
        "http_method": "GET",
        "uri": "/a",
        "query_string": "",
        "user_agent": "ua",
        "normalized_uri": "old-value",
    }

    pp = RequestPreprocessor(overwrite_existing=False)

    with pytest.raises(ValueError):
        pp.preprocess(record)


def test_preprocessor_conflict_is_reported_when_overwrite_enabled():
    """
    Test:
    - Nếu cho phép overwrite, vẫn phải ghi cảnh báo vào preprocess_errors.
    """
    record = {
        "http_method": "GET",
        "uri": "/a",
        "query_string": "",
        "user_agent": "ua",
        "normalized_uri": "old-value",
    }

    out = RequestPreprocessor(overwrite_existing=True).preprocess(record)

    assert out["normalized_uri"] == "/a"
    assert "preprocess_fields_overwritten" in out["preprocess_errors"]
    assert out["preprocess_status"] == "error"


def test_preprocessor_allows_preexisting_decoded_fields_from_normalizer():
    """
    Test:
    - decoded_uri và decoded_query_string có sẵn từ upstream (Normalizer)
      không bị xem là conflict overwrite.
    """
    record = {
        "http_method": "GET",
        "uri": "/a",
        "query_string": "x=1",
        "user_agent": "ua",
        "decoded_uri": "/a",
        "decoded_query_string": "x=1",
    }

    out = RequestPreprocessor(overwrite_existing=True).preprocess(record)

    assert out["decoded_uri"] == "/a"
    assert out["decoded_query_string"] == "x=1"
    assert "preprocess_fields_overwritten" not in out["preprocess_errors"]
    assert out["preprocess_status"] == "success"


def test_preprocessor_max_field_length_guard_truncates_and_flags():
    """
    Test:
    - Field quá dài bị truncate.
    - preprocess_errors ghi nhận field bị truncate.
    """
    record = {
        "http_method": "GET",
        "uri": "/abcdef",
        "query_string": "",
        "user_agent": "ua",
    }

    out = RequestPreprocessor(max_field_length=5).preprocess(record)

    assert out["decoded_uri"] == "/abcd"
    assert out["normalized_uri"] == "/abcd"
    assert "uri_truncated" in out["preprocess_errors"]
    assert out["preprocess_status"] == "error"


def test_preprocessor_missing_fields_become_empty_strings_without_error():
    """
    Test:
    - Missing uri/query/user_agent/http_method không làm crash.
    - Output vẫn có schema preprocess đầy đủ.
    """
    out = RequestPreprocessor().preprocess({})

    assert out["decoded_uri"] == ""
    assert out["decoded_query_string"] == ""
    assert out["decoded_user_agent"] == ""
    assert out["normalized_uri"] == ""
    assert out["normalized_query_string"] == ""
    assert out["normalized_user_agent"] == ""
    assert out["normalized_method"] == ""
    assert out["normalized_url"] == ""
    assert out["normalized_request"] == "method= | url= | user_agent="
    assert out["decode_depth"] == 0
    assert out["decode_changed"] is False
    assert out["preprocess_status"] == "success"
    assert out["preprocess_errors"] == []


def test_preprocessor_decode_changed_compares_final_result_with_original():
    """
    Test:
    - decode_changed phản ánh kết quả cuối khác input gốc.
    """
    out_changed = RequestPreprocessor().preprocess({
        "http_method": "GET",
        "uri": "/a%2fb",
        "query_string": "",
        "user_agent": "ua",
    })
    out_unchanged = RequestPreprocessor().preprocess({
        "http_method": "GET",
        "uri": "/a/b",
        "query_string": "",
        "user_agent": "ua",
    })

    assert out_changed["decoded_uri"] == "/a/b"
    assert out_changed["decode_changed_uri"] is True

    assert out_unchanged["decoded_uri"] == "/a/b"
    assert out_unchanged["decode_changed_uri"] is False


def test_preprocessor_constructor_validates_config():
    """
    Test:
    - Config không hợp lệ phải fail sớm.
    """
    with pytest.raises(ValueError):
        RequestPreprocessor(max_decode_rounds=0)

    with pytest.raises(ValueError):
        RequestPreprocessor(max_field_length=0)

    with pytest.raises(ValueError):
        RequestPreprocessor(field_separator="")
