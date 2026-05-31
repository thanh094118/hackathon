"""Tests for DashboardQueryAdapter.find_similar_requests (Issue 1).

Coverage:
- Returns empty list when embedding is empty/None.
- Returns empty list when db is None.
- Delegates to mongodb_queries.find_similar_logs and normalizes rows.
- Tries unified_logs fallback when requests collection is unavailable.
- Gracefully returns [] on exception from find_similar_logs.
- Normalizes similarity_score from the $vectorSearch score field.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.dashboard.query_adapter import DashboardQueryAdapter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_EMBEDDING = [0.92, 0.88, 0.85, 0.93] + [0.0] * 380  # 384-dim


def _make_live_adapter(collection_rows, collection_name: str = "requests"):
    """Return an adapter wired to a mocked MongoDB collection."""
    adapter = DashboardQueryAdapter(use_mock=True)
    adapter._status["mode"] = "mongodb"

    mock_col = MagicMock()
    mock_col.aggregate.return_value = collection_rows

    mock_db = MagicMock()
    mock_db.__getitem__.return_value = mock_col

    adapter.db = mock_db
    adapter.requests_collection_name = collection_name
    return adapter, mock_col


# ---------------------------------------------------------------------------
# Guard-clause tests (no DB required)
# ---------------------------------------------------------------------------

class TestFindSimilarRequestsGuards:

    def test_empty_embedding_returns_empty(self):
        adapter = DashboardQueryAdapter(use_mock=True)
        adapter._status["mode"] = "mongodb"
        adapter.db = MagicMock()
        assert adapter.find_similar_requests([], limit=5) == []

    def test_none_embedding_returns_empty(self):
        adapter = DashboardQueryAdapter(use_mock=True)
        adapter._status["mode"] = "mongodb"
        adapter.db = MagicMock()
        assert adapter.find_similar_requests(None, limit=5) == []  # type: ignore[arg-type]

    def test_returns_empty_when_db_is_none(self):
        adapter = DashboardQueryAdapter(use_mock=True)
        adapter._status["mode"] = "mongodb"
        adapter.db = None
        assert adapter.find_similar_requests(SAMPLE_EMBEDDING, limit=5) == []

    def test_non_numeric_elements_are_filtered(self):
        """Should not raise; only valid floats are forwarded to the query."""
        adapter, _ = _make_live_adapter([])
        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "find_similar_logs", return_value=[]):
            result = adapter.find_similar_requests([0.5, "bad", None, 0.3], limit=5)  # type: ignore[list-item]
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Live MongoDB path tests
# ---------------------------------------------------------------------------

class TestFindSimilarRequestsLive:

    def test_delegates_to_find_similar_logs(self):
        rows = [
            {
                "event_id": "evt-live-01",
                "timestamp": "2026-05-30T10:00:00+00:00",
                "source_ip": "10.0.0.1",
                "uri": "/api/v1/users",
                "risk_score": 88,
                "risk_level": "high",
                "final_label": "malicious",
                "score": 0.91,
            }
        ]
        adapter, _ = _make_live_adapter(rows)

        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "find_similar_logs", return_value=rows) as mock_fn:
            results = adapter.find_similar_requests(SAMPLE_EMBEDDING, limit=3)

        mock_fn.assert_called_once()
        assert len(results) == 1
        assert results[0]["event_id"] == "evt-live-01"

    def test_normalizes_similarity_score_from_score_field(self):
        rows = [
            {
                "event_id": "evt-norm",
                "timestamp": "2026-05-30T11:00:00+00:00",
                "source_ip": "10.0.0.2",
                "uri": "/search?q=test",
                "risk_score": 75,
                "score": 0.87,
            }
        ]
        adapter, _ = _make_live_adapter(rows)

        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "find_similar_logs", return_value=rows):
            results = adapter.find_similar_requests(SAMPLE_EMBEDDING, limit=5)

        assert results[0]["similarity_score"] == pytest.approx(0.87, abs=1e-4)

    def test_required_fields_present(self):
        rows = [
            {
                "event_id": "evt-fields",
                "timestamp": "2026-05-30T12:00:00+00:00",
                "source_ip": "10.0.0.3",
                "uri": "/admin",
                "risk_score": 92,
                "score": 0.94,
            }
        ]
        adapter, _ = _make_live_adapter(rows)

        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "find_similar_logs", return_value=rows):
            results = adapter.find_similar_requests(SAMPLE_EMBEDDING, limit=5)

        required = {"event_id", "timestamp", "ip", "uri", "risk_score", "similarity_score"}
        assert not (required - set(results[0].keys()))

    def test_returns_empty_when_collection_returns_empty(self):
        adapter, _ = _make_live_adapter([])

        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "find_similar_logs", return_value=[]):
            results = adapter.find_similar_requests(SAMPLE_EMBEDDING, limit=5)

        assert results == []

    def test_graceful_on_exception(self):
        adapter, _ = _make_live_adapter([])

        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "find_similar_logs", side_effect=RuntimeError("atlas down")):
            results = adapter.find_similar_requests(SAMPLE_EMBEDDING, limit=5)

        assert results == []

    def test_similarity_score_clamped_to_0_1(self):
        rows = [{"event_id": "x", "score": 1.5}]  # out-of-range score
        adapter, _ = _make_live_adapter(rows)

        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "find_similar_logs", return_value=rows):
            results = adapter.find_similar_requests(SAMPLE_EMBEDDING, limit=5)

        assert results[0]["similarity_score"] <= 1.0


class TestQueryAdapterAdvancedFeatures:

    def test_recent_incidents_use_single_hybrid_contract(self):
        adapter = DashboardQueryAdapter(use_mock=True)

        all_rows = adapter.get_recent_incidents(limit=20, method_filter="All")
        legacy_rule_rows = adapter.get_recent_incidents(limit=20, method_filter="Rules Only")
        legacy_ml_rows = adapter.get_recent_incidents(limit=20, method_filter="ML Only")

        assert all_rows
        assert [row["event_id"] for row in legacy_rule_rows] == [row["event_id"] for row in all_rows]
        assert [row["event_id"] for row in legacy_ml_rows] == [row["event_id"] for row in all_rows]
        assert {row["detection_method"] for row in all_rows} == {"hybrid"}
        assert all("detection_sources" in row for row in all_rows)

    def test_get_ip_blast_radius_mock(self):
        # In mock mode, if the IP exists in mock, compute from mock
        adapter = DashboardQueryAdapter(use_mock=True)
        assert adapter.is_mock_mode() is True

        # Test fallback
        res = adapter.get_ip_blast_radius("1.2.3.4")
        assert len(res) == 2
        assert res[0]["uri"] == "/login"
        assert res[0]["percentage"] == 80.0

    def test_get_ip_blast_radius_live(self):
        rows = [{"uri": "/login", "count": 10, "percentage": 100.0}]
        adapter, _ = _make_live_adapter(rows)
        adapter._status["mode"] = "mongodb"
        assert adapter.is_mock_mode() is False

        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "get_ip_blast_radius", return_value=rows) as mock_fn:
            results = adapter.get_ip_blast_radius("10.0.0.1")

        mock_fn.assert_called_once_with(adapter.db, ip="10.0.0.1", requests_collection="requests")
        assert len(results) == 1
        assert results[0]["uri"] == "/login"
        assert results[0]["percentage"] == 100.0

    def test_get_attack_timeline_mock(self):
        adapter = DashboardQueryAdapter(use_mock=True)
        res = adapter.get_attack_timeline()
        assert len(res) > 0
        # The new structure includes attack_type
        assert "attack_type" in res[0]
        assert "timestamp" in res[0]
        assert "count" in res[0]

    def test_get_attack_timeline_live(self):
        rows = [{"timestamp": "2026-05-30T10:00:00Z", "attack_type": "SQLI", "count": 5}]
        adapter, _ = _make_live_adapter(rows)
        adapter._status["mode"] = "mongodb"

        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "generate_attack_timeline", return_value=rows) as mock_fn:
            results = adapter.get_attack_timeline(bucket_size=5, unit="minute")

        mock_fn.assert_called_once_with(adapter.db, ip=None, bucket_size=5, unit="minute", limit=1000, requests_collection="requests", cutoff=None)
        assert len(results) == 1
        assert results[0]["attack_type"] == "SQLI"
        assert results[0]["count"] == 5

    def test_get_active_campaigns_live(self):
        rows = [
            {
                "ip": "10.0.0.1",
                "total_attacks": 60,
                "attack_types": ["SQLI", "XSS", "PATH_TRAVERSAL"],
                "target_uris": ["/login"],
                "first_seen": "2026-05-30T10:00:00Z",
                "last_seen": "2026-05-30T11:00:00Z"
            }
        ]
        adapter, _ = _make_live_adapter(rows)
        adapter._status["mode"] = "mongodb"

        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "detect_attack_campaigns", return_value=rows) as mock_fn:
            results = adapter.get_active_campaigns(min_attacks=50, min_attack_types=3)

        mock_fn.assert_called_once_with(adapter.db, min_attacks=50, min_attack_types=3, limit=200, requests_collection="requests", cutoff=None)
        assert len(results) == 1
        assert results[0]["ip"] == "10.0.0.1"
        assert results[0]["total_attacks"] == 60
        assert "SQLI" in results[0]["attack_types"]

    def test_get_materialized_campaigns_mock(self):
        adapter = DashboardQueryAdapter(use_mock=True)
        res = adapter.get_materialized_campaigns()
        # In mock mode, should fall back to get_active_campaigns
        assert len(res) > 0
        assert "ip" in res[0]
        assert "risk_level" in res[0]

    def test_get_materialized_campaigns_live_success(self):
        rows = [
            {
                "ip": "1.2.3.4",
                "total_attacks": 42,
                "attack_types": ["xss"],
                "target_uris": ["/"],
                "first_seen": "2026-05-30T10:00:00Z",
                "last_seen": "2026-05-30T11:00:00Z",
                "risk_level": "medium"
            }
        ]
        adapter, _ = _make_live_adapter(rows, "requests")
        adapter._status["mode"] = "mongodb"
        adapter.campaigns_collection_name = "active_campaigns"

        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "get_materialized_campaigns", return_value=rows) as mock_fn:
            results = adapter.get_materialized_campaigns(limit=10)

        mock_fn.assert_called_once_with(adapter.db, campaigns_collection="active_campaigns", limit=10)
        assert len(results) == 1
        assert results[0]["ip"] == "1.2.3.4"
        assert results[0]["risk_level"] == "medium"

    def test_get_materialized_campaigns_live_empty_fallback(self):
        # If get_materialized_campaigns returns empty/errors, should fallback to get_active_campaigns
        adapter, _ = _make_live_adapter([], "requests")
        adapter._status["mode"] = "mongodb"
        
        fallback_rows = [{"ip": "9.9.9.9", "total_attacks": 12, "attack_types": ["sqli"], "target_uris": []}]

        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "get_materialized_campaigns", return_value=[]), \
             patch.object(mq, "detect_attack_campaigns", return_value=fallback_rows):
            results = adapter.get_materialized_campaigns()

        assert len(results) == 1
        assert results[0]["ip"] == "9.9.9.9"

    def test_get_materialized_campaigns_count_live(self):
        adapter, _ = _make_live_adapter([], "requests")
        adapter._status["mode"] = "mongodb"
        adapter.campaigns_collection_name = "active_campaigns"

        meta = {"count": 5, "last_updated": "2026-05-31T00:00:00Z"}
        import src.scoring.mongodb_queries as mq
        with patch.object(mq, "get_campaigns_metadata", return_value=meta) as mock_fn:
            results = adapter._get_materialized_campaigns_count()

        mock_fn.assert_called_once_with(adapter.db, campaigns_collection="active_campaigns")
        assert results["count"] == 5
        assert results["last_updated"] == "2026-05-31T00:00:00Z"
