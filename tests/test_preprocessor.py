from src.preprocessor.request_preprocessor import RequestPreprocessor


def test_preprocessor_decodes_and_normalizes_request_text():
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
    assert out["normalized_user_agent"] == "sqlmap/1.7"
    assert out["normalized_request"].startswith("get /search.php")
    assert out["decode_depth"] == 2
    assert out["decode_changed"] is True


def test_preprocessor_removes_nulls_and_extra_spaces():
    record = {
        "http_method": "GET",
        "uri": "/a",
        "query_string": "x=\x00\x00  1",
        "user_agent": "A\x00  B",
    }
    out = RequestPreprocessor().preprocess(record)
    assert "\x00" not in out["normalized_request"]
    assert "  " not in out["normalized_request"]
    assert out["decode_depth"] == 0
    assert out["decode_changed"] is False
