import pytest
from unittest.mock import MagicMock, patch
from src.features.embedding_engine import EmbeddingEngine
from src.exporters.mongodb_exporter import MongoDBExporter
from src.scoring.mongodb_queries import (
    find_similar_attack_patterns,
    find_similar_logs,
    get_ip_threat_scores,
    get_threat_timeline,
    search_patterns_by_text,
    search_logs_by_text
)


def test_embedding_engine_mocked():
    import numpy as np
    with patch("src.features.embedding_engine.SentenceTransformer") as mock_transformer:
        mock_model = MagicMock()
        def encode_side_effect(text_or_texts, **kwargs):
            if isinstance(text_or_texts, list):
                return np.array([[0.1] * 384 for _ in text_or_texts])
            return np.array([0.1] * 384)
        mock_model.encode.side_effect = encode_side_effect
        mock_transformer.return_value = mock_model

        engine = EmbeddingEngine()
        
        # Test single embedding
        emb = engine.get_embedding("test request")
        assert len(emb) == 384
        assert emb[0] == 0.1
        mock_model.encode.assert_called_with("test request", convert_to_numpy=True)

        # Test batch embedding
        embs = engine.get_embeddings(["req1", "req2"])
        assert len(embs) == 2
        assert len(embs[0]) == 384


def test_mongodb_exporter_bulk_upsert():
    mock_client = MagicMock()
    mock_db = MagicMock()
    mock_collection = MagicMock()
    
    mock_client.__getitem__.return_value = mock_db
    mock_db.__getitem__.return_value = mock_collection

    with patch("src.exporters.mongodb_exporter.MongoClient", return_value=mock_client):
        exporter = MongoDBExporter("mongodb://localhost:27017", "test_db", "test_collection")
        exporter.connect()
        
        records = [
            {"event_id": "evt1", "uri": "/index.php", "risk_score": 2.0},
            {"event_id": "evt2", "uri": "/admin", "risk_score": 8.0}
        ]
        
        exporter.export(records)
        
        # Assert that bulk_write was called with a list of UpdateOne operations
        assert mock_collection.bulk_write.called
        calls = mock_collection.bulk_write.call_args[0][0]
        assert len(calls) == 2
        
        # Check first update operation parameters
        op1 = calls[0]
        assert op1._filter == {"event_id": "evt1"}
        assert op1._doc == {"$set": {"event_id": "evt1", "uri": "/index.php", "risk_score": 2.0}}
        assert op1._upsert is True


def test_find_similar_attack_patterns():
    mock_collection = MagicMock()
    mock_collection.aggregate.return_value = [
        {"pattern_id": "sqli_boolean_or", "name": "SQLi", "score": 0.95}
    ]

    query_vector = [0.1] * 384
    results = find_similar_attack_patterns(mock_collection, query_vector, limit=3)
    
    assert len(results) == 1
    assert results[0]["pattern_id"] == "sqli_boolean_or"
    assert results[0]["score"] == 0.95
    
    # Verify aggregate structure
    assert mock_collection.aggregate.called
    pipeline = mock_collection.aggregate.call_args[0][0]
    assert len(pipeline) == 2
    assert "$vectorSearch" in pipeline[0]
    assert pipeline[0]["$vectorSearch"]["queryVector"] == query_vector
    assert pipeline[0]["$vectorSearch"]["limit"] == 3


def test_find_similar_logs():
    mock_collection = MagicMock()
    mock_collection.aggregate.return_value = [
        {"event_id": "evt1", "risk_score": 8.0, "score": 0.88}
    ]

    query_vector = [0.1] * 384
    results = find_similar_logs(mock_collection, query_vector, limit=2)
    
    assert len(results) == 1
    assert results[0]["event_id"] == "evt1"
    assert results[0]["score"] == 0.88
    
    pipeline = mock_collection.aggregate.call_args[0][0]
    assert len(pipeline) == 2
    assert "$vectorSearch" in pipeline[0]


def test_get_ip_threat_scores():
    mock_collection = MagicMock()
    mock_collection.aggregate.return_value = [
        {"source_ip": "192.168.1.1", "total_requests": 10, "total_alerts": 3, "max_risk_score": 8.5, "avg_risk_score": 4.2}
    ]

    results = get_ip_threat_scores(mock_collection, limit=5)
    assert len(results) == 1
    assert results[0]["source_ip"] == "192.168.1.1"
    assert results[0]["total_requests"] == 10
    
    pipeline = mock_collection.aggregate.call_args[0][0]
    assert any("$group" in stage for stage in pipeline)


def test_get_threat_timeline():
    mock_collection = MagicMock()
    mock_collection.aggregate.return_value = [
        {"time_bucket": "2026-05-30T09:00:00Z", "total_requests": 15, "total_alerts": 2}
    ]

    results = get_threat_timeline(mock_collection, interval="hour")
    assert len(results) == 1
    assert results[0]["total_requests"] == 15
    
    pipeline = mock_collection.aggregate.call_args[0][0]
    assert any("$dateTrunc" in str(stage) for stage in pipeline)


def test_search_by_text_helpers():
    mock_collection = MagicMock()
    mock_collection.aggregate.return_value = [{"pattern_id": "test_id", "score": 0.99}]
    
    mock_engine = MagicMock()
    mock_engine.get_embedding.return_value = [0.2] * 384

    # Test search_patterns_by_text
    patterns = search_patterns_by_text(mock_collection, "some pattern", mock_engine)
    assert len(patterns) == 1
    assert patterns[0]["pattern_id"] == "test_id"
    mock_engine.get_embedding.assert_called_with("some pattern")

    # Test search_logs_by_text
    mock_collection.aggregate.return_value = [{"event_id": "evt_test", "score": 0.92}]
    logs = search_logs_by_text(mock_collection, "some log", mock_engine)
    assert len(logs) == 1
    assert logs[0]["event_id"] == "evt_test"
