from __future__ import annotations

from unittest.mock import MagicMock, patch
from pymongo import ReplaceOne, UpdateOne
from src.exporters.mongodb_exporter import MongoDBExporter
from scripts.migrate_collections import run_migration
from src.dashboard.query_adapter import _normalize_request_record


@patch("src.exporters.mongodb_exporter.MongoClient")
@patch("scripts.migrate_collections.MongoClient")
def test_end_to_end_schema_and_migration_integration(mock_migration_client, mock_exporter_client):
    # --- PART 1: EXPORT (Dual-write) ---
    mock_exporter_conn = MagicMock()
    mock_exporter_client.return_value = mock_exporter_conn
    mock_exporter_db = MagicMock()
    mock_exporter_conn.__getitem__.return_value = mock_exporter_db
    mock_exporter_col = MagicMock()
    mock_exporter_db.__getitem__.return_value = mock_exporter_col

    exporter = MongoDBExporter(uri="mongodb://localhost:27017", database_name="test_db", collection_name="requests")
    
    flat_record = {
        "_id": "dummy_id",
        "event_id": "integration-test-1",
        "timestamp": "2026-05-31T00:00:00Z",
        "source_ip": "192.168.1.100",
        "http_method": "POST",
        "uri": "/login",
        "risk_score": 85,
        "final_label": "malicious",
    }

    exporter.export([flat_record])

    mock_exporter_col.bulk_write.assert_called_once()
    args, _ = mock_exporter_col.bulk_write.call_args
    operations = args[0]
    assert len(operations) == 1
    assert isinstance(operations[0], UpdateOne)
    
    set_doc = operations[0]._doc["$set"]
    assert set_doc["_schema_version"] == 2
    assert set_doc["request"]["source_ip"] == "192.168.1.100"
    assert set_doc["scoring"]["risk_score"] == 85
    assert "source_ip" not in set_doc
    assert "risk_score" not in set_doc

    # --- PART 2: MIGRATION ---
    mock_migration_conn = MagicMock()
    mock_migration_client.return_value = mock_migration_conn
    mock_migration_db = MagicMock()
    mock_migration_conn.__getitem__.return_value = mock_migration_db
    mock_migration_db.list_collection_names.return_value = ["requests", "incidents"]
    
    mock_requests_col = MagicMock()
    mock_incidents_col = MagicMock()
    mock_migration_db.__getitem__.side_effect = lambda name: mock_requests_col if name == "requests" else mock_incidents_col

    # Return old flat records for migration
    mock_requests_col.count_documents.return_value = 1
    mock_requests_col.find.return_value = [flat_record]

    success = run_migration("mongodb://localhost:27017", "test_db", batch_size=10, dry_run=False)
    assert success is True

    mock_requests_col.bulk_write.assert_called_once()
    args_mig, _ = mock_requests_col.bulk_write.call_args
    replace_ops = args_mig[0]
    assert len(replace_ops) == 1
    assert isinstance(replace_ops[0], ReplaceOne)
    
    migrated_doc = replace_ops[0]._doc
    assert migrated_doc["_schema_version"] == 2
    assert migrated_doc["request"]["source_ip"] == "192.168.1.100"
    assert migrated_doc["scoring"]["risk_score"] == 85

    # --- PART 3: ADAPTER NORMALIZATION ---
    # Normalizing migrated/nested document
    norm_nested = _normalize_request_record(migrated_doc)

    assert norm_nested["event_id"] == "integration-test-1"
    assert norm_nested["ip"] == "192.168.1.100"
    assert norm_nested["risk_score"] == 85
    assert norm_nested["verdict"] == "malicious"
    assert norm_nested["method"] == "POST"
    assert norm_nested["uri"] == "/login"
