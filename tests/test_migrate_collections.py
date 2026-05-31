from __future__ import annotations

from unittest.mock import MagicMock, patch
from pymongo import ReplaceOne
from scripts.migrate_collections import run_migration


@patch("scripts.migrate_collections.MongoClient")
def test_run_migration_calls_bulk_write_correctly(mock_mongo_client):
    # Setup mock collections and database
    mock_client = MagicMock()
    mock_mongo_client.return_value = mock_client
    mock_db = MagicMock()
    mock_client.__getitem__.return_value = mock_db
    
    mock_db.list_collection_names.return_value = ["requests", "incidents"]
    
    mock_requests = MagicMock()
    mock_incidents = MagicMock()
    mock_db.__getitem__.side_effect = lambda name: mock_requests if name == "requests" else mock_incidents

    # Sample flat documents in requests
    flat_docs = [
        {"_id": "doc1", "ip": "1.2.3.4", "risk_score": 80},
        {"_id": "doc2", "ip": "5.6.7.8", "risk_score": 40},
    ]
    mock_requests.count_documents.return_value = 2
    mock_requests.find.return_value = flat_docs

    # Sample flat documents in incidents
    incident_docs = [
        {"_id": "doc3", "ip": "1.2.3.4", "risk_score": 80},
    ]
    mock_incidents.count_documents.return_value = 1
    mock_incidents.find.return_value = incident_docs

    # Run migration
    success = run_migration("mongodb://localhost:27017", "threatlens", batch_size=10, dry_run=False)

    assert success is True
    
    # Assert counts were checked
    mock_requests.count_documents.assert_called_once()
    mock_incidents.count_documents.assert_called_once()

    # Assert bulk_write was called with ReplaceOne operations
    mock_requests.bulk_write.assert_called_once()
    args, kwargs = mock_requests.bulk_write.call_args
    batch_req = args[0]
    assert len(batch_req) == 2
    assert isinstance(batch_req[0], ReplaceOne)
    assert batch_req[0]._filter == {"_id": "doc1"}
    assert batch_req[0]._doc["request"]["source_ip"] == "1.2.3.4"
    assert batch_req[0]._doc["_schema_version"] == 2

    mock_incidents.bulk_write.assert_called_once()
    args_inc, kwargs_inc = mock_incidents.bulk_write.call_args
    batch_inc = args_inc[0]
    assert len(batch_inc) == 1
    assert isinstance(batch_inc[0], ReplaceOne)
    assert batch_inc[0]._filter == {"_id": "doc3"}
    assert batch_inc[0]._doc["request"]["source_ip"] == "1.2.3.4"
    assert batch_inc[0]._doc["_schema_version"] == 2
