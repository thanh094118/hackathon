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
    search_logs_by_text,
    detect_attack_campaigns,
    get_ip_blast_radius,
    generate_attack_timeline
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
            {"event_id": "evt1", "uri": "/index.php", "risk_score": 2.0, "timestamp": "2026-05-30T10:00:00Z"},
            {"event_id": "evt2", "uri": "/admin", "risk_score": 8.0, "timestamp": "2026-05-30 11:00:00"}
        ]
        
        exporter.export(records)
        
        # Assert that bulk_write was called with a list of UpdateOne operations
        assert mock_collection.bulk_write.called
        calls = mock_collection.bulk_write.call_args[0][0]
        assert len(calls) == 2
        
        # Check first update operation parameters
        op1 = calls[0]
        assert op1._filter == {"event_id": "evt1"}
        assert op1._doc["$set"]["event_id"] == "evt1"
        assert op1._doc["$set"]["uri"] == "/index.php"
        from datetime import datetime
        assert isinstance(op1._doc["$set"]["timestamp"], datetime)
        assert op1._upsert is True

        # Check second update operation parameters
        op2 = calls[1]
        assert op2._filter == {"event_id": "evt2"}
        assert isinstance(op2._doc["$set"]["timestamp"], datetime)


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


def test_detect_attack_campaigns_apt_thresholds():
    mock_db = MagicMock()
    mock_collection = MagicMock()
    mock_db.__getitem__.return_value = mock_collection
    mock_collection.aggregate.return_value = [
        {
            "ip": "1.2.3.4",
            "total_attacks": 60,
            "attack_types": ["SQLI", "XSS", "PATH_TRAVERSAL"],
            "target_uris": ["/login", "/api"],
            "first_seen": "2026-05-30T10:00:00Z",
            "last_seen": "2026-05-30T11:00:00Z"
        }
    ]

    results = detect_attack_campaigns(mock_db, min_attacks=50, min_attack_types=3, limit=5)
    assert len(results) == 1
    assert results[0]["ip"] == "1.2.3.4"
    assert results[0]["total_attacks"] == 60

    # Verify pipeline stages
    pipeline = mock_collection.aggregate.call_args[0][0]
    match_stages = [stage["$match"] for stage in pipeline if "$match" in stage]
    # Check that second match uses strict And (total_attacks and attack_type_count)
    assert len(match_stages) >= 2
    assert "total_attacks" in match_stages[-1]
    assert "attack_type_count" in match_stages[-1]
    assert match_stages[-1]["total_attacks"] == {"$gte": 50}
    assert match_stages[-1]["attack_type_count"] == {"$gte": 3}


def test_get_ip_blast_radius():
    mock_db = MagicMock()
    mock_collection = MagicMock()
    mock_db.__getitem__.return_value = mock_collection
    mock_collection.aggregate.return_value = [
        {"uri": "/login", "count": 8, "percentage": 80.0},
        {"uri": "/api/users", "count": 2, "percentage": 20.0}
    ]

    results = get_ip_blast_radius(mock_db, ip="1.2.3.4")
    assert len(results) == 2
    assert results[0]["uri"] == "/login"
    assert results[0]["percentage"] == 80.0

    pipeline = mock_collection.aggregate.call_args[0][0]
    # Verify match stage on ip
    assert "$match" in pipeline[0]
    assert "$or" in pipeline[0]["$match"]


def test_generate_attack_timeline_multi_series():
    mock_db = MagicMock()
    mock_collection = MagicMock()
    mock_db.__getitem__.return_value = mock_collection
    mock_collection.aggregate.return_value = [
        {"timestamp": "2026-05-30T10:00:00Z", "attack_type": "SQLI", "count": 15},
        {"timestamp": "2026-05-30T10:00:00Z", "attack_type": "XSS", "count": 5}
    ]

    results = generate_attack_timeline(mock_db, bucket_size=5, unit="minute")
    assert len(results) == 2
    assert results[0]["attack_type"] == "SQLI"
    assert results[0]["count"] == 15

    pipeline = mock_collection.aggregate.call_args[0][0]
    # Verify group stage groups by both timestamp and attack_type
    group_stage = next(stage["$group"] for stage in pipeline if "$group" in stage)
    assert "timestamp" in group_stage["_id"]
    assert "attack_type" in group_stage["_id"]
    assert "$dateTrunc" in str(group_stage["_id"]["timestamp"])

