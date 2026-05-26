from src.normalizer.normalizer import Normalizer


def test_normalizer_splits_uri_and_query_and_keeps_original_url():
    parsed = {
        "timestamp": "10/Oct/2000:13:55:36 +0000",
        "source_ip": "127.0.0.1",
        "http_method": "get",
        "raw_uri": "/a.php?id=1&x=2",
        "original_url": "/a.php?id=1&x=2",
        "status_code": "200",
        "response_size": "-",
        "user_agent": "-",
        "referrer": "-",
        "server_type": "apache",
        "line_number": 1,
        "parse_error": False,
        "parse_status": "success",
    }
    out = Normalizer().normalize(parsed)
    assert out["uri"] == "/a.php"
    assert out["query_string"] == "id=1&x=2"
    assert out["http_method"] == "GET"
    assert out["response_size"] == 0
    assert out["original_url"] == "/a.php?id=1&x=2"
    assert out["normalize_status"] == "success"


def test_normalizer_propagates_parse_error_fields():
    parsed = {
        "timestamp": None,
        "source_ip": None,
        "http_method": None,
        "raw_uri": None,
        "status_code": 0,
        "response_size": 0,
        "user_agent": None,
        "referrer": None,
        "server_type": "apache",
        "line_number": 2,
        "parse_error": True,
        "parse_status": "error",
        "error_message": "bad line",
        "raw_log": "bad line",
    }
    out = Normalizer().normalize(parsed)
    assert out["parse_error"] is True
    assert out["parse_status"] == "error"
    assert out["normalize_status"] == "error"
    assert out["error_message"] == "bad line"
