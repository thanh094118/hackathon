from __future__ import annotations

from unittest.mock import MagicMock, patch
from pymongo import UpdateOne
from src.exporters.mongodb_exporter import MongoDBExporter


@patch("src.exporters.mongodb_exporter.MongoClient")
def test_mongodb_exporter_exports_dual_write(mock_mongo_client):
    # Setup mock collection and client
    mock_client = MagicMock()
    mock_mongo_client.return_value = mock_client
    mock_db = MagicMock()
    mock_client.__getitem__.return_value = mock_db
    mock_collection = MagicMock()
    mock_db.__getitem__.return_value = mock_collection

    exporter = MongoDBExporter(uri="mongodb://localhost:27017", database_name="test_db", collection_name="requests")
    
    records = [
        {
            "event_id": "test-exporter-1",
            "timestamp": "2026-05-31T00:00:00Z",
            "source_ip": "1.2.3.4",
            "risk_score": 85,
        }
    ]

    exporter.export(records)

    # Check bulk_write was called with UpdateOne containing dual-write fields
    mock_collection.bulk_write.assert_called_once()
    args, kwargs = mock_collection.bulk_write.call_args
    operations = args[0]
    assert len(operations) == 1
    assert isinstance(operations[0], UpdateOne)
    
    update_doc = operations[0]._doc
    assert "$set" in update_doc
    set_fields = update_doc["$set"]

    # Verify nested schema 2 fields are present
    assert set_fields["_schema_version"] == 2
    assert set_fields["request"]["source_ip"] == "1.2.3.4"
    assert set_fields["scoring"]["risk_score"] == 85

    # Verify flat compatibility fields are NOT present at top level
    assert "source_ip" not in set_fields
    assert "risk_score" not in set_fields
