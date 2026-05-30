import logging
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def find_similar_attack_patterns(
    collection,
    query_vector: List[float],
    limit: int = 3,
    filter_dict: Optional[Dict] = None
) -> List[Dict[str, Any]]:
    """
    Perform a vector search to find similar attack patterns in the 'attack_patterns' collection.
    Uses the 'vector_index' search index.
    """
    if not query_vector:
        logging.warning("Empty query vector provided to find_similar_attack_patterns.")
        return []

    vector_search_stage = {
        "index": "vector_index",
        "path": "embedding",
        "queryVector": query_vector,
        "numCandidates": max(limit * 10, 50),
        "limit": limit
    }
    
    if filter_dict:
        vector_search_stage["filter"] = filter_dict

    pipeline = [
        {
            "$vectorSearch": vector_search_stage
        },
        {
            "$project": {
                "_id": 0,
                "pattern_id": 1,
                "name": 1,
                "category": 1,
                "description": 1,
                "payload_example": 1,
                "severity": 1,
                "mitigation": 1,
                "score": {"$meta": "vectorSearchScore"}
            }
        }
    ]

    try:
        return list(collection.aggregate(pipeline))
    except Exception as e:
        logging.error(f"Error during find_similar_attack_patterns: {e}")
        return []


def find_similar_logs(
    collection,
    query_vector: List[float],
    limit: int = 5,
    filter_dict: Optional[Dict] = None
) -> List[Dict[str, Any]]:
    """
    Perform a vector search to find similar logs in the 'unified_logs' collection.
    Uses the 'vector_index' search index.
    """
    if not query_vector:
        logging.warning("Empty query vector provided to find_similar_logs.")
        return []

    vector_search_stage = {
        "index": "vector_index",
        "path": "embedding",
        "queryVector": query_vector,
        "numCandidates": max(limit * 10, 50),
        "limit": limit
    }
    
    if filter_dict:
        vector_search_stage["filter"] = filter_dict

    pipeline = [
        {
            "$vectorSearch": vector_search_stage
        },
        {
            "$project": {
                "_id": 0,
                "event_id": 1,
                "timestamp": 1,
                "source_ip": 1,
                "http_method": 1,
                "original_url": 1,
                "uri": 1,
                "query_string": 1,
                "status_code": 1,
                "user_agent": 1,
                "risk_score": 1,
                "risk_level": 1,
                "final_label": 1,
                "should_alert": 1,
                "score": {"$meta": "vectorSearchScore"}
            }
        }
    ]

    try:
        return list(collection.aggregate(pipeline))
    except Exception as e:
        logging.error(f"Error during find_similar_logs: {e}")
        return []


def get_ip_threat_scores(collection, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Aggregate request logs in 'unified_logs' to calculate threat statistics per IP address.
    """
    pipeline = [
        {
            "$group": {
                "_id": "$source_ip",
                "total_requests": {"$sum": 1},
                "total_alerts": {
                    "$sum": {
                        "$cond": [
                            {"$or": [
                                {"$eq": ["$should_alert", True]},
                                {"$in": ["$final_label", ["malicious", "suspicious"]]}
                            ]},
                            1,
                            0
                        ]
                    }
                },
                "max_risk_score": {"$max": "$risk_score"},
                "avg_risk_score": {"$avg": "$risk_score"},
                "triggered_rules": {"$addToSet": "$rule_id"}
            }
        },
        {
            "$project": {
                "source_ip": "$_id",
                "_id": 0,
                "total_requests": 1,
                "total_alerts": 1,
                "max_risk_score": 1,
                "avg_risk_score": 1,
                "triggered_rules": {
                    "$filter": {
                        "input": "$triggered_rules",
                        "as": "rule",
                        "cond": {"$ne": ["$$rule", None]}
                    }
                }
            }
        },
        {
            "$sort": {
                "max_risk_score": -1,
                "total_alerts": -1,
                "avg_risk_score": -1
            }
        },
        {"$limit": limit}
    ]

    try:
        return list(collection.aggregate(pipeline))
    except Exception as e:
        logging.error(f"Error during get_ip_threat_scores: {e}")
        return []


def get_threat_timeline(collection, interval: str = "hour") -> List[Dict[str, Any]]:
    """
    Aggregate logs by time buckets using $dateTrunc to analyze threat trend lines.
    Supports intervals: year, quarter, month, week, day, hour, minute, second.
    """
    valid_intervals = {"year", "quarter", "month", "week", "day", "hour", "minute", "second"}
    if interval not in valid_intervals:
        logging.warning(f"Invalid interval '{interval}' requested. Defaulting to 'hour'.")
        interval = "hour"

    pipeline = [
        {
            "$match": {
                "timestamp": {"$ne": None, "$type": "string"}
            }
        },
        {
            "$group": {
                "_id": {
                    "$dateTrunc": {
                        "date": {"$dateFromString": {"dateString": "$timestamp"}},
                        "unit": interval
                    }
                },
                "total_requests": {"$sum": 1},
                "total_alerts": {
                    "$sum": {
                        "$cond": [
                            {"$or": [
                                {"$eq": ["$should_alert", True]},
                                {"$in": ["$final_label", ["malicious", "suspicious"]]}
                            ]},
                            1,
                            0
                        ]
                    }
                },
                "avg_risk_score": {"$avg": "$risk_score"}
            }
        },
        {
            "$project": {
                "time_bucket": "$_id",
                "_id": 0,
                "total_requests": 1,
                "total_alerts": 1,
                "avg_risk_score": 1
            }
        },
        {
            "$sort": {"time_bucket": 1}
        }
    ]

    try:
        return list(collection.aggregate(pipeline))
    except Exception as e:
        logging.error(f"Error during get_threat_timeline: {e}")
        return []


def search_patterns_by_text(
    collection,
    query_text: str,
    embedding_engine,
    limit: int = 3,
    filter_dict: Optional[Dict] = None
) -> List[Dict[str, Any]]:
    """
    Convert a text query into a vector and search for similar attack patterns.
    """
    if not query_text:
        return []
    query_vector = embedding_engine.get_embedding(query_text)
    return find_similar_attack_patterns(collection, query_vector, limit, filter_dict)


def search_logs_by_text(
    collection,
    query_text: str,
    embedding_engine,
    limit: int = 5,
    filter_dict: Optional[Dict] = None
) -> List[Dict[str, Any]]:
    """
    Convert a text query into a vector and search for similar logs.
    """
    if not query_text:
        return []
    query_vector = embedding_engine.get_embedding(query_text)
    return find_similar_logs(collection, query_vector, limit, filter_dict)
