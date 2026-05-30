import logging
from typing import Dict, List, Optional

try:
    from pymongo import MongoClient
    from pymongo.errors import BulkWriteError, ConnectionFailure
    HAS_PYMONGO = True
except ImportError:
    HAS_PYMONGO = False
    # Define dummy classes for type hinting if needed
    class MongoClient: pass
    class BulkWriteError(Exception): pass
    class ConnectionFailure(Exception): pass


class MongoDBExporter:
    """
    Exporter for MongoDB Atlas.
    Supports bulk insertion of records.
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
            # Try connecting with standard settings
            # If you still get SSL errors, you can add tlsAllowInvalidCertificates=True for testing
            self.client = MongoClient(self.uri, tlsAllowInvalidCertificates=False)
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
            # Using insert_many for bulk insertion
            result = self.collection.insert_many(records, ordered=False)
            logging.info(f"Successfully exported {len(result.inserted_ids)} records to MongoDB.")
            return result
        except BulkWriteError as bwe:
            logging.error(f"Bulk write error: {bwe.details}")
            # Depending on requirements, we might want to re-raise or handle partial success
            return bwe.details
        except Exception as e:
            logging.error(f"Error exporting to MongoDB: {e}")
            raise

    def close(self):
        if self.client:
            self.client.close()
            logging.info("MongoDB connection closed.")
