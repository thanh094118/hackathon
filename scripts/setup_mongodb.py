#!/usr/bin/env python3
import os
import sys
import time
import logging
from pymongo import MongoClient
from pymongo.operations import SearchIndexModel
import certifi
from dotenv import load_dotenv

# Ensure workspace root is in python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def setup_indexes():
    load_dotenv()
    mongodb_uri = os.getenv("MONGODB_URI")
    if not mongodb_uri:
        logging.error("MONGODB_URI environment variable not found in .env file!")
        sys.exit(1)

    db_name = os.getenv("MONGODB_DB_NAME", "security_logs")
    log_collection_name = os.getenv("MONGODB_COLLECTION_NAME", "unified_logs")
    pattern_collection_name = "attack_patterns"

    logging.info(f"Connecting to MongoDB database '{db_name}'...")
    client = MongoClient(mongodb_uri, tls=True, tlsCAFile=certifi.where())
    db = client[db_name]

    # Definition for vector index
    vector_search_definition = {
        "fields": [
            {
                "type": "vector",
                "path": "embedding",
                "numDimensions": 384,
                "similarity": "cosine"
            },
            {
                "type": "filter",
                "path": "category"
            },
            {
                "type": "filter",
                "path": "severity"
            }
        ]
    }

    search_index_model = SearchIndexModel(
        definition=vector_search_definition,
        name="vector_index",
        type="vectorSearch"
    )

    collections_to_index = [log_collection_name, pattern_collection_name]

    for coll_name in collections_to_index:
        logging.info(f"Setting up collection '{coll_name}'...")
        # Create collection if it doesn't exist
        if coll_name not in db.list_collection_names():
            db.create_collection(coll_name)
            logging.info(f"Created collection: {coll_name}")

        collection = db[coll_name]

        # Check if vector index already exists
        index_exists = False
        try:
            existing_indexes = list(collection.list_search_indexes())
            for idx in existing_indexes:
                if idx.get("name") == "vector_index":
                    index_exists = True
                    logging.info(f"Vector search index 'vector_index' already exists on collection '{coll_name}'.")
                    break
        except Exception as e:
            logging.warning(f"Could not list search indexes (may be building or unsupported): {e}")

        if not index_exists:
            logging.info(f"Creating vector search index 'vector_index' on collection '{coll_name}'...")
            try:
                result = collection.create_search_index(model=search_index_model)
                logging.info(f"Initiated build for vector search index: {result}")
            except Exception as e:
                logging.error(f"Failed to programmatically create search index on '{coll_name}': {e}")
                print_fallback_instructions(db_name, coll_name, vector_search_definition)

    logging.info("Polling index build status...")
    for coll_name in collections_to_index:
        collection = db[coll_name]
        start_time = time.time()
        # Poll for up to 120 seconds or until index is ready
        while time.time() - start_time < 120:
            try:
                indexes = list(collection.list_search_indexes())
                vector_idx = next((idx for idx in indexes if idx.get("name") == "vector_index"), None)
                if vector_idx:
                    status = vector_idx.get("status")
                    logging.info(f"Index status on '{coll_name}': {status}")
                    if status == "READY":
                        logging.info(f"[+] Vector index is READY on collection '{coll_name}'!")
                        break
                    elif status == "FAILED":
                        logging.error(f"[-] Vector index build FAILED on collection '{coll_name}'.")
                        break
                else:
                    logging.info(f"Index not found yet on '{coll_name}', waiting...")
            except Exception:
                pass
            time.sleep(10)

    client.close()
    logging.info("MongoDB connection closed.")


def print_fallback_instructions(db_name: str, coll_name: str, definition: dict):
    print("\n" + "="*80)
    print(f"FALLBACK INSTRUCTIONS FOR CREATING ATLAS VECTOR SEARCH INDEX:")
    print(f"Collection: {db_name}.{coll_name}")
    print(f"Index Name: vector_index")
    print("="*80)
    print("Please follow these steps in your MongoDB Atlas UI Console:")
    print(f"1. Navigate to your Atlas Cluster and click on 'Search'.")
    print(f"2. Click 'Create Search Index'.")
    print(f"3. Select 'Atlas Vector Search' -> 'JSON Editor'.")
    print(f"4. Select the Database '{db_name}' and Collection '{coll_name}'.")
    print(f"5. Set the Index Name to 'vector_index'.")
    print(f"6. Replace the JSON configuration with the following:")
    import json
    print(json.dumps(definition, indent=2))
    print("="*80 + "\n")


if __name__ == "__main__":
    setup_indexes()
