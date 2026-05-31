#!/usr/bin/env python3
"""Migration script to convert MongoDB collections from flat to nested schema version 2."""

from __future__ import annotations

import os
import sys
import argparse
import logging
from typing import Any, List

try:
    from pymongo import MongoClient, ReplaceOne
    HAS_PYMONGO = True
except ImportError:
    HAS_PYMONGO = False

# Add project root to python path to import schemas
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.schemas.mongodb_schema import flat_to_nested, is_nested_schema


def run_migration(uri: str, db_name: str, batch_size: int = 1000, dry_run: bool = False) -> bool:
    if not HAS_PYMONGO:
        logging.error("[-] pymongo package is not installed. Cannot run migration.")
        return False

    logging.info("[*] Connecting to MongoDB...")
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        db = client[db_name]
        logging.info("[+] Successfully connected to database: %s", db_name)
    except Exception as exc:
        logging.error("[-] Connection failed: %s", exc)
        return False

    collections = ["requests", "incidents"]
    for col_name in collections:
        if col_name not in db.list_collection_names():
            logging.info("[!] Collection '%s' does not exist; skipping.", col_name)
            continue

        col = db[col_name]
        # Query for documents that do not have _schema_version set to 2 or higher
        query = {"$or": [{"_schema_version": {"$exists": False}}, {"_schema_version": {"$lt": 2}}]}
        total_count = col.count_documents(query)

        logging.info("[*] Found %d documents in '%s' needing migration.", total_count, col_name)
        if total_count == 0:
            continue

        if dry_run:
            logging.info("[*] DRY RUN: Would migrate %d documents in '%s'.", total_count, col_name)
            continue

        cursor = col.find(query)
        batch: List[ReplaceOne] = []
        migrated_count = 0

        for doc in cursor:
            doc_id = doc.get("_id")
            if not doc_id:
                logging.warning("[!] Skipping document without '_id' field: %s", doc.get("event_id", "unknown"))
                continue
            # Convert to nested
            nested_doc = flat_to_nested(doc)
            
            # Create bulk replace operation
            batch.append(ReplaceOne({"_id": doc_id}, nested_doc))

            if len(batch) >= batch_size:
                try:
                    result = col.bulk_write(batch, ordered=False)
                    migrated_count += result.modified_count
                    logging.info("[*] Progress: Migrated %d/%d documents in '%s'...", migrated_count, total_count, col_name)
                except Exception as exc:
                    logging.error("[-] Bulk write batch failed: %s", exc)
                batch = []

        # Flush remaining documents in batch
        if batch:
            try:
                result = col.bulk_write(batch, ordered=False)
                migrated_count += result.modified_count
            except Exception as exc:
                logging.error("[-] Bulk write final batch failed: %s", exc)

        logging.info("[+] Completed migration for '%s': Migrated %d documents.", col_name, migrated_count)

    client.close()
    return True


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    
    from dotenv import load_dotenv
    load_dotenv()

    parser = argparse.ArgumentParser(description="Migrate MongoDB security logs from flat to nested schema.")
    parser.add_argument("--uri", default=os.getenv("MONGODB_URI"), help="MongoDB connection URI")
    parser.add_argument("--db", default=os.getenv("MONGODB_DB_NAME", "threatlens"), help="MongoDB database name")
    parser.add_argument("--batch-size", type=int, default=1000, help="Bulk write batch size")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without modifying database")

    args = parser.parse_args()

    if not args.uri:
        logging.error("[-] MongoDB URI is not provided. Set MONGODB_URI env variable or pass --uri.")
        sys.exit(1)

    success = run_migration(args.uri, args.db, batch_size=args.batch_size, dry_run=args.dry_run)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
