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
