import logging
from typing import Dict, List, Optional

try:
    from pymongo import MongoClient, UpdateOne
    from pymongo.errors import BulkWriteError, ConnectionFailure
    import certifi
    HAS_PYMONGO = True
except ImportError:
    HAS_PYMONGO = False
    certifi = None
    # Define dummy classes for type hinting if needed
    class MongoClient: pass
    class UpdateOne: pass
    class BulkWriteError(Exception): pass
    class ConnectionFailure(Exception): pass


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
        if not HAS_PYMONGO:
            raise ImportError("pymongo is required for MongoDB export")

        try:
            # Use certifi for up-to-date CA certificates
            self.client = MongoClient(
                self.uri,
                tls=True,
                tlsCAFile=certifi.where() if certifi else None,
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
        if self.collection is None:
            self.connect()

        if not records:
            return

        try:
            operations = []
            exported_records = []
            for record in records:
                event_id = record.get("event_id")
                if not event_id:
                    logging.warning("Skipping log record because event_id is missing.")
                    continue
                # Update document matched by event_id, insert if it does not exist (upsert=True)
                operations.append(
                    UpdateOne({"event_id": event_id}, {"$set": record}, upsert=True)
                )
                exported_records.append(record)

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
            self._send_alerts_for_exported_incidents(exported_records)
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

    def _send_alerts_for_exported_incidents(self, records: List[Dict]):
        if self.collection_name != "incidents":
            return

        try:
            from src.notifications.alerts import send_incident_alert
        except Exception as exc:
            logging.warning("Alert notification wrapper is unavailable: %s", exc.__class__.__name__)
            return

        for record in records:
            try:
                results = send_incident_alert(record)
                if results:
                    failures = [result for result in results if not getattr(result, "success", False)]
                    if failures:
                        logging.warning("Incident alert completed with %d failed channel(s).", len(failures))
                    else:
                        logging.info("Incident alert dispatched for event_id=%s.", record.get("event_id"))
            except Exception as exc:
                logging.warning("Incident alert failed safely: %s", exc.__class__.__name__)

    def close(self):
        if self.client:
            self.client.close()
            logging.info("MongoDB connection closed.")
