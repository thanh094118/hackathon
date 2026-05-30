import types

from src.dashboard.query_adapter import DashboardQueryAdapter
import src.dashboard.query_adapter as query_adapter_module


def _force_mongodb_mode(adapter: DashboardQueryAdapter) -> None:
    adapter._status["mode"] = "mongodb"
    adapter._status["connection"] = "Connected"
    adapter.db = object()
    adapter.requests_collection_name = "requests"
    adapter.incidents_collection_name = "incidents"
    adapter.patterns_collection_name = "attack_patterns"


def test_dashboard_query_adapter_mock_mode(monkeypatch):
    monkeypatch.setenv("DASHBOARD_USE_MOCK", "1")
    monkeypatch.delenv("MONGODB_URI", raising=False)

    adapter = DashboardQueryAdapter()

    status = adapter.status()
    assert status["using_mock"] is True
    assert isinstance(adapter.get_soc_summary(), dict)
    assert isinstance(adapter.get_recent_incidents(limit=5), list)

    patterns = adapter.find_similar_attack_patterns([0.1, 0.2, 0.3], limit=3)
    assert isinstance(patterns, list)
    assert len(patterns) <= 3


def test_dashboard_query_adapter_falls_back_when_mongodb_uri_missing(monkeypatch):
    monkeypatch.delenv("DASHBOARD_USE_MOCK", raising=False)
    monkeypatch.delenv("MONGODB_URI", raising=False)

    adapter = DashboardQueryAdapter()
    status = adapter.status()

    assert status["using_mock"] is True
    assert "MONGODB_URI not set" in status.get("message", "")
    assert isinstance(adapter.get_attack_timeline(), list)


def test_find_similar_attack_patterns_delegates_to_central_query_module(monkeypatch):
    adapter = DashboardQueryAdapter(use_mock=True)
    _force_mongodb_mode(adapter)

    called = {}

    def fake_vector_search(db, embedding, limit=3, **kwargs):
        called["db"] = db
        called["embedding"] = embedding
        called["limit"] = limit
        called["kwargs"] = kwargs
        return [{"pattern_id": "pat-1", "attack_type": "SQLI", "name": "SQLI", "description": "x", "score": 0.9}]

    fake_module = types.SimpleNamespace(explain_threat_via_vector_search=fake_vector_search)
    monkeypatch.setattr(query_adapter_module, "mongodb_queries", fake_module)

    rows = adapter.find_similar_attack_patterns([0.1, 0.2, 0.3], limit=2)

    assert called["db"] is adapter.db
    assert called["embedding"] == [0.1, 0.2, 0.3]
    assert called["limit"] == 2
    assert rows and rows[0]["pattern_id"] == "pat-1"


def test_get_active_campaigns_delegates_to_central_query_module(monkeypatch):
    adapter = DashboardQueryAdapter(use_mock=True)
    _force_mongodb_mode(adapter)

    called = {}

    def fake_detect_campaigns(db, min_attacks=10, limit=10, **kwargs):
        called["db"] = db
        called["min_attacks"] = min_attacks
        called["limit"] = limit
        called["kwargs"] = kwargs
        return [
            {
                "_id": "185.24.9.10",
                "total_attacks": 12,
                "attack_types": ["SQLI", "XSS"],
                "target_uris": ["/login", "/search"],
                "first_seen": "2026-01-01T00:00:00Z",
                "last_seen": "2026-01-01T01:00:00Z",
            }
        ]

    fake_module = types.SimpleNamespace(detect_attack_campaigns=fake_detect_campaigns)
    monkeypatch.setattr(query_adapter_module, "mongodb_queries", fake_module)

    rows = adapter.get_active_campaigns(min_attacks=10)

    assert called["db"] is adapter.db
    assert called["min_attacks"] == 10
    assert rows and rows[0]["ip"] == "185.24.9.10"
    assert rows[0]["total_attacks"] == 12


def test_get_attack_timeline_delegates_to_central_query_module(monkeypatch):
    adapter = DashboardQueryAdapter(use_mock=True)
    _force_mongodb_mode(adapter)

    called = {}

    def fake_timeline(db, ip=None, hours_bucket=1, limit=100, **kwargs):
        called["db"] = db
        called["ip"] = ip
        called["hours_bucket"] = hours_bucket
        called["limit"] = limit
        called["kwargs"] = kwargs
        return [{"timestamp": "2026-01-01T00:00:00Z", "count": 4}]

    fake_module = types.SimpleNamespace(generate_attack_timeline=fake_timeline)
    monkeypatch.setattr(query_adapter_module, "mongodb_queries", fake_module)

    rows = adapter.get_attack_timeline()

    assert called["db"] is adapter.db
    assert called["hours_bucket"] == 1
    assert rows == [{"timestamp": "2026-01-01T00:00:00+00:00", "count": 4}]
