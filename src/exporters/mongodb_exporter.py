import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone

try:
    from pymongo import MongoClient, UpdateOne
    from pymongo.errors import BulkWriteError, ConnectionFailure
    import certifi
    HAS_PYMONGO = True
except ImportError:
    HAS_PYMONGO = False
    # Define dummy classes for type hinting if needed
    class MongoClient: pass
    class UpdateOne: pass
    class BulkWriteError(Exception): pass
    class ConnectionFailure(Exception): pass


def _parse_timestamp(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None

    text = str(value).strip()
    if not text:
        return None

    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    return None


class MongoDBExporter:
    """
    Exporter for MongoDB Atlas.
    Supports bulk upserting of records to prevent duplication.
    """

    def __init__(
        self,
        uri: str,
        database_name: str = "security_logs",
        collection_name: str = "unified_logs"
    ):
        self.uri = uri
        self.database_name = database_name
        self.collection_name = collection_name
        self.client: Optional[MongoClient] = None
        self.db = None
        self.collection = None

    def connect(self):
        try:
            # Use certifi for up-to-date CA certificates
            self.client = MongoClient(
                self.uri,
                tls=True,
                tlsCAFile=certifi.where() if HAS_PYMONGO else None,
                tlsAllowInvalidCertificates=False
            )
            self.client.admin.command('ismaster')
            self.db = self.client[self.database_name]
            self.collection = self.db[self.collection_name]
            logging.info(f"Connected to MongoDB: {self.database_name}.{self.collection_name}")
        except ConnectionFailure as e:
            logging.error(f"Could not connect to MongoDB: {e}")
            raise

    def export(self, records: List[Dict]):
        if not self.collection:
            self.connect()

        if not records:
            return

        try:
            operations = []
            for record in records:
                event_id = record.get("event_id")
                if not event_id:
                    logging.warning("Skipping log record because event_id is missing.")
                    continue
                
                doc = dict(record)
                ts = doc.get("timestamp")
                if ts:
                    parsed_ts = _parse_timestamp(ts)
                    if parsed_ts:
                        doc["timestamp"] = parsed_ts
                
                # Update document matched by event_id, insert if it does not exist (upsert=True)
                operations.append(
                    UpdateOne({"event_id": event_id}, {"$set": doc}, upsert=True)
                )

            if not operations:
                return

            total_matched = 0
            total_upserted = 0
            total_modified = 0
            chunk_size = 1000

            for i in range(0, len(operations), chunk_size):
                chunk = operations[i:i + chunk_size]
                result = self.collection.bulk_write(chunk, ordered=False)
                if result:
                    total_matched += getattr(result, "matched_count", 0) or 0
                    total_upserted += getattr(result, "upserted_count", 0) or 0
                    total_modified += getattr(result, "modified_count", 0) or 0

            logging.info(
                f"Successfully exported records to MongoDB. "
                f"Matched: {total_matched}, Upserted: {total_upserted}, "
                f"Modified: {total_modified}."
            )
            return {
                "matched_count": total_matched,
                "upserted_count": total_upserted,
                "modified_count": total_modified
            }
        except BulkWriteError as bwe:
            logging.error(f"Bulk write error: {bwe.details}")
            return bwe.details
        except Exception as e:
            logging.error(f"Error exporting to MongoDB: {e}")
            raise

    def close(self):
        if self.client:
            self.client.close()
            logging.info("MongoDB connection closed.")
