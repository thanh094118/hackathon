import logging
from typing import Dict, List, Optional

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
                # Update document matched by event_id, insert if it does not exist (upsert=True)
                operations.append(
                    UpdateOne({"event_id": event_id}, {"$set": record}, upsert=True)
                )

            if not operations:
                return

            result = self.collection.bulk_write(operations, ordered=False)
            logging.info(
                f"Successfully exported records to MongoDB. "
                f"Matched: {result.matched_count}, Upserted: {result.upserted_count}, "
                f"Modified: {result.modified_count}."
            )
            return result
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
