from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _collection(db: Any, name: Optional[str]):
    if db is None or not name:
        return None
    try:
        return db[name]
    except Exception:
        return None


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return int(default)


def _malicious_match_query() -> Dict[str, Any]:
    return {
        "$or": [
            {"detection.ml.label": {"$in": ["malicious", "suspicious", "attack"]}},
            {"detection.ml.should_alert": True},
            {"scoring.should_alert": True},
            {"detection.rules.attack_type": {"$exists": True, "$nin": [None, "", "Unknown", "unknown", "normal", "benign"]}},
            {"detection.ml.attack_type": {"$exists": True, "$nin": [None, "", "Unknown", "unknown", "normal", "benign"]}},
            {"scoring.risk_score": {"$gte": 70}},
        ]
    }


def _timeframe_filter(cutoff: Any) -> Dict[str, Any]:
    if not cutoff:
        return {}
    return {
        "$or": [
            {
                "$and": [
                    {"timestamp": {"$type": "date"}},
                    {"timestamp": {"$gte": cutoff}}
                ]
            },
            {
                "$and": [
                    {"timestamp": {"$type": "string"}},
                    {
                        "$expr": {
                            "$gte": [
                                {
                                    "$dateFromString": {
                                        "dateString": "$timestamp",
                                        "onError": None,
                                        "onNull": None
                                    }
                                },
                                cutoff
                            ]
                        }
                    }
                ]
            }
        ]
    }


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


def explain_threat_via_vector_search(
    db: Any,
    embedding: List[float],
    limit: int = 3,
    *,
    patterns_collection: str = "attack_patterns",
    index_name: str = "vector_index",
    num_candidates: int = 50,
) -> List[Dict[str, Any]]:
    collection = _collection(db, patterns_collection)
    if collection is None:
        return []

    vector = [float(x) for x in (embedding or []) if isinstance(x, (int, float))]
    if not vector:
        return []

    max_limit = max(1, _safe_int(limit, 3))
    pipeline = [
        {
            "$vectorSearch": {
                "index": index_name,
                "path": "embedding",
                "queryVector": vector,
                "numCandidates": max(max_limit * 5, _safe_int(num_candidates, 50)),
                "limit": max_limit,
            }
        },
        {
            "$project": {
                "_id": 0,
                "pattern_id": 1,
                "attack_type": 1,
                "category": 1,
                "name": 1,
                "description": 1,
                "examples": 1,
                "payload_example": 1,
                "remediation": 1,
                "mitigation": 1,
                "mitre": 1,
                "severity": 1,
                "score": {"$meta": "vectorSearchScore"},
            }
        },
    ]

    try:
        return [dict(row) for row in collection.aggregate(pipeline, allowDiskUse=True)]
    except Exception:
        # Keep dashboard resilient when Vector Search index/capability is unavailable.
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
                "source_ip": "$request.source_ip",
                "http_method": "$request.method",
                "original_url": "$request.uri",
                "uri": "$request.uri",
                "query_string": "$request.query_string",
                "status_code": "$request.status_code",
                "user_agent": "$request.user_agent",
                "risk_score": "$scoring.risk_score",
                "risk_level": "$scoring.risk_level",
                "final_label": "$scoring.final_label",
                "should_alert": "$scoring.should_alert",
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
                "_id": "$request.source_ip",
                "total_requests": {"$sum": 1},
                "total_alerts": {
                    "$sum": {
                        "$cond": [
                            {"$or": [
                                {"$eq": ["$scoring.should_alert", True]},
                                {"$in": ["$scoring.final_label", ["malicious", "suspicious"]]}
                            ]},
                            1,
                            0
                        ]
                    }
                },
                "max_risk_score": {"$max": "$scoring.risk_score"},
                "avg_risk_score": {"$avg": "$scoring.risk_score"},
                "triggered_rules": {"$addToSet": "$detection.rules.matched_ids"}
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


def get_attack_type_distribution(
    db: Any,
    *,
    requests_collection: str = "requests",
    limit: int = 20,
    cutoff: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    collection = _collection(db, requests_collection)
    if collection is None:
        return []

    match_query = _malicious_match_query()
    if cutoff:
        match_query = {
            "$and": [
                match_query,
                _timeframe_filter(cutoff)
            ]
        }

    pipeline = [
        {"$match": match_query},
        {
            "$group": {
                "_id": {
                    "$ifNull": [
                        "$detection.rules.attack_type",
                        {"$ifNull": ["$detection.ml.attack_type", "Unknown"]}
                    ]
                },
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": max(1, _safe_int(limit, 20))},
    ]

    try:
        return [dict(row) for row in collection.aggregate(pipeline, allowDiskUse=True)]
    except Exception:
        return []


def get_top_attacking_ips(
    db: Any,
    limit: int = 10,
    *,
    requests_collection: str = "requests",
    cutoff: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    collection = _collection(db, requests_collection)
    if collection is None:
        return []

    match_query = _malicious_match_query()
    if cutoff:
        match_query = {
            "$and": [
                match_query,
                _timeframe_filter(cutoff)
            ]
        }

    pipeline = [
        {"$match": match_query},
        {
            "$group": {
                "_id": {"$ifNull": ["$request.source_ip", "Unknown"]},
                "total_attacks": {"$sum": 1},
                "attack_types": {"$addToSet": "$detection.rules.attack_type"},
                "target_uris": {"$addToSet": "$request.uri"},
                "first_seen": {"$min": "$timestamp"},
                "last_seen": {"$max": "$timestamp"},
            }
        },
        {"$sort": {"total_attacks": -1}},
        {"$limit": max(1, _safe_int(limit, 10))},
    ]

    try:
        return [dict(row) for row in collection.aggregate(pipeline, allowDiskUse=True)]
    except Exception:
        return []


def detect_attack_campaigns(
    db: Any,
    min_attacks: int = 50,
    min_attack_types: int = 3,
    limit: int = 10,
    *,
    requests_collection: str = "requests",
    cutoff: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    collection = _collection(db, requests_collection)
    if collection is None:
        return []

    threshold = max(1, _safe_int(min_attacks, 50))
    min_types = max(1, _safe_int(min_attack_types, 3))
    max_limit = max(1, _safe_int(limit, 10))

    match_query = _malicious_match_query()
    if cutoff:
        match_query = {
            "$and": [
                match_query,
                _timeframe_filter(cutoff)
            ]
        }

    pipeline = [
        {"$match": match_query},
        {
            "$group": {
                "_id": {"$ifNull": ["$request.source_ip", "Unknown"]},
                "total_attacks": {"$sum": 1},
                "attack_types": {"$addToSet": "$detection.rules.attack_type"},
                "target_uris": {"$addToSet": "$request.uri"},
                "first_seen": {"$min": "$timestamp"},
                "last_seen": {"$max": "$timestamp"},
            }
        },
        {
            "$addFields": {
                "attack_type_count": {"$size": {"$ifNull": ["$attack_types", []]}},
                "target_count": {"$size": {"$ifNull": ["$target_uris", []]}},
            }
        },
        {
            "$match": {
                "total_attacks": {"$gte": threshold},
                "attack_type_count": {"$gte": min_types},
            }
        },
        {"$sort": {"total_attacks": -1}},
        {"$limit": max_limit},
    ]

    try:
        return [dict(row) for row in collection.aggregate(pipeline, allowDiskUse=True)]
    except Exception:
        return []


def get_ip_blast_radius(
    db: Any,
    ip: str,
    limit: int = 10,
    *,
    requests_collection: str = "requests",
) -> List[Dict[str, Any]]:
    collection = _collection(db, requests_collection)
    if collection is None or not ip:
        return []

    match_query = {
        "request.source_ip": str(ip)
    }
    max_limit = max(1, _safe_int(limit, 10))

    pipeline = [
        {"$match": match_query},
        {
            "$group": {
                "_id": {"$ifNull": ["$request.uri", "Unknown"]},
                "uri_count": {"$sum": 1}
            }
        },
        {
            "$group": {
                "_id": None,
                "grand_total": {"$sum": "$uri_count"},
                "uris": {
                    "$push": {
                        "uri": "$_id",
                        "uri_count": "$uri_count"
                    }
                }
            }
        },
        {"$unwind": "$uris"},
        {
            "$project": {
                "_id": 0,
                "uri": "$uris.uri",
                "count": "$uris.uri_count",
                "percentage": {
                    "$cond": [
                        {"$eq": ["$grand_total", 0]},
                        0.0,
                        {
                            "$multiply": [
                                {"$divide": ["$uris.uri_count", "$grand_total"]},
                                100.0
                            ]
                        }
                    ]
                }
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": max_limit}
    ]

    try:
        return [dict(row) for row in collection.aggregate(pipeline, allowDiskUse=True)]
    except Exception as e:
        logging.error(f"Error in get_ip_blast_radius: {e}")
        return []


def generate_attack_timeline(
    db: Any,
    ip: Optional[str] = None,
    bucket_size: int = 1,
    unit: str = "hour",
    limit: int = 100,
    *,
    hours_bucket: Optional[int] = None,
    requests_collection: str = "requests",
    cutoff: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    collection = _collection(db, requests_collection)
    if collection is None:
        return []

    match_query: Dict[str, Any] = dict(_malicious_match_query())
    if ip:
        match_query["request.source_ip"] = str(ip)

    if cutoff:
        match_query = {
            "$and": [
                match_query,
                _timeframe_filter(cutoff)
            ]
        }

    b_size = max(1, _safe_int(hours_bucket if hours_bucket is not None else bucket_size, 1))
    t_unit = str(unit) if hours_bucket is None else "hour"
    max_limit = max(1, _safe_int(limit, 100))

    pipeline = [
        {"$match": match_query},
        {
            "$addFields": {
                "_timeline_ts": {
                    "$convert": {
                        "input": "$timestamp",
                        "to": "date",
                        "onError": None,
                        "onNull": None,
                    }
                },
                "_attack_type": {
                    "$ifNull": [
                        "$detection.rules.attack_type",
                        {"$ifNull": ["$detection.ml.attack_type", "Unknown"]}
                    ]
                }
            }
        },
        {"$match": {"_timeline_ts": {"$ne": None}}},
        {
            "$group": {
                "_id": {
                    "timestamp": {
                        "$dateTrunc": {
                            "date": "$_timeline_ts",
                            "unit": t_unit,
                            "binSize": b_size,
                        }
                    },
                    "attack_type": "$_attack_type"
                },
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"_id.timestamp": 1, "_id.attack_type": 1}},
        {"$limit": max_limit},
        {
            "$project": {
                "_id": 0,
                "timestamp": "$_id.timestamp",
                "attack_type": "$_id.attack_type",
                "count": 1
            }
        },
    ]

    try:
        return [dict(row) for row in collection.aggregate(pipeline, allowDiskUse=True)]
    except Exception:
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
                                {"$eq": ["$scoring.should_alert", True]},
                                {"$in": ["$scoring.final_label", ["malicious", "suspicious"]]}
                            ]},
                            1,
                            0
                        ]
                    }
                },
                "avg_risk_score": {"$avg": "$scoring.risk_score"}
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


def get_materialized_campaigns(
    db: Any,
    *,
    campaigns_collection: str = "active_campaigns",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Read pre-computed campaigns from the Atlas-materialized view.
    
    The 'active_campaigns' collection is populated by an Atlas Scheduled
    Trigger running a $merge pipeline every 60 seconds. This function
    simply reads the latest snapshot — no heavy aggregation needed.
    """
    collection = _collection(db, campaigns_collection)
    if collection is None:
        return []
    try:
        return list(
            collection.find(
                {"status": "active"},
                {"_id": 0},
            )
            .sort("total_attacks", -1)
            .limit(max(1, _safe_int(limit, 50)))
        )
    except Exception as e:
        logging.error(f"Error during get_materialized_campaigns: {e}")
        return []


def get_campaigns_metadata(
    db: Any,
    *,
    campaigns_collection: str = "active_campaigns",
) -> Dict[str, Any]:
    """Return metadata about the materialized campaigns collection."""
    collection = _collection(db, campaigns_collection)
    if collection is None:
        return {"count": 0, "last_updated": None}
    try:
        count = collection.count_documents({"status": "active"})
        latest = collection.find_one(
            {}, {"materialized_at": 1}, sort=[("materialized_at", -1)]
        )
        return {
            "count": count,
            "last_updated": latest.get("materialized_at") if latest else None,
        }
    except Exception as e:
        logging.error(f"Error during get_campaigns_metadata: {e}")
        return {"count": 0, "last_updated": None}


def find_similar_false_positives(
    collection,
    query_vector: List[float],
    limit: int = 1,
    index_name: str = "vector_index",
) -> List[Dict[str, Any]]:
    """Perform Atlas Vector Search to find similar false positives."""
    if not query_vector:
        return []

    pipeline = [
        {
            "$vectorSearch": {
                "index": index_name,
                "path": "embedding",
                "queryVector": query_vector,
                "numCandidates": max(limit * 10, 20),
                "limit": limit,
            }
        },
        {
            "$project": {
                "_id": 1,
                "notes": 1,
                "incident_id": 1,
                "score": {"$meta": "vectorSearchScore"},
            }
        },
    ]
    try:
        return list(collection.aggregate(pipeline))
    except Exception as e:
        logging.error(f"Error in find_similar_false_positives: {e}")
        return []


def calculate_attack_baselines(db: Any, requests_collection: str = "requests", baseline_collection: str = "attack_baselines") -> Dict[str, Any]:
    """Runs aggregation over requests to calculate baseline statistics for each hour of the week per endpoint group."""
    coll_req = _collection(db, requests_collection)
    if coll_req is None:
        return {"status": "skipped", "reason": "database/collection not available"}

    pipeline = [
        {
            "$match": {
                "$or": [
                    {"scoring.should_alert": True},
                    {"scoring.final_label": {"$in": ["malicious", "suspicious"]}},
                ]
            }
        },
        {
            "$addFields": {
                "date_obj": {
                    "$cond": {
                        "if": {"$eq": [{"$type": "$timestamp"}, "date"]},
                        "then": "$timestamp",
                        "else": {
                            "$dateFromString": {
                                "dateString": "$timestamp",
                                "onError": None,
                                "onNull": None,
                             }
                        },
                    }
                },
                "uri_val": {"$ifNull": ["$request.uri", "$uri"]}
            }
        },
        {"$match": {"date_obj": {"$ne": None}}},
        {
            "$project": {
                "hour_of_week": {
                    "$add": [
                        {"$multiply": [{"$subtract": [{"$dayOfWeek": "$date_obj"}, 1]}, 24]},
                        {"$hour": "$date_obj"},
                    ]
                },
                "endpoint_group": {
                    "$cond": {
                        "if": { "$regexMatch": { "input": {"$ifNull": ["$uri_val", ""]}, "regex": "backup|db|admin|config|settings", "options": "i" } },
                        "then": "sensitive",
                        "else": {
                            "$let": {
                                "vars": {
                                    "parts": { "$split": [{"$ifNull": ["$uri_val", ""]}, "/"] }
                                },
                                "in": {
                                    "$cond": {
                                        "if": { "$gt": [{ "$size": "$$parts" }, 1] },
                                        "then": {
                                            "$cond": {
                                                "if": { "$eq": [{ "$arrayElemAt": ["$$parts", 1] }, "api"] },
                                                "then": {
                                                    "$cond": {
                                                        "if": { "$gt": [{ "$size": "$$parts" }, 2] },
                                                        "then": { "$concat": ["api_", { "$arrayElemAt": ["$$parts", 2] }] },
                                                        "else": "api"
                                                    }
                                                },
                                                "else": { "$arrayElemAt": ["$$parts", 1] }
                                            }
                                        },
                                        "else": "root"
                                    }
                                }
                            }
                        }
                    }
                },
                "week_year": {
                    "$concat": [
                        {"$toString": {"$isoWeekYear": "$date_obj"}},
                        "-",
                        {"$toString": {"$isoWeek": "$date_obj"}},
                    ]
                },
            }
        },
        {
            "$group": {
                "_id": {
                    "hour_of_week": "$hour_of_week",
                    "endpoint_group": "$endpoint_group",
                    "week_year": "$week_year"
                },
                "count": {"$sum": 1},
            }
        },
        {
            "$group": {
                "_id": {
                    "hour_of_week": "$_id.hour_of_week",
                    "endpoint_group": "$_id.endpoint_group"
                },
                "mean": {"$avg": "$count"},
                "std_dev": {"$stdDevPop": "$count"},
            }
        },
        {
            "$merge": {
                "into": baseline_collection,
                "on": "_id",
                "whenMatched": "merge",
                "whenNotMatched": "insert",
            }
        },
    ]

    try:
        coll_req.aggregate(pipeline)
        return {"status": "success", "message": "Baseline aggregation run successfully"}
    except Exception as e:
        logging.error(f"Error in calculate_attack_baselines: {e}")
        return {"status": "error", "message": str(e)}


def calculate_endpoint_min_floors(
    db: Any,
    requests_collection: str = "requests",
    min_floors_collection: str = "endpoint_min_floors",
    percentile: float = 0.90,
    scale_factor: float = 0.10,
) -> Dict[str, Any]:
    """
    Groups requests by endpoint_group and hourly buckets, sorts them,
    and calculates the given percentile scaled by scale_factor as min_floor.
    """
    coll_req = _collection(db, requests_collection)
    if coll_req is None:
        return {"status": "skipped", "reason": "database/collection not available"}

    pipeline = [
        {
            "$addFields": {
                "date_obj": {
                    "$cond": {
                        "if": {"$eq": [{"$type": "$timestamp"}, "date"]},
                        "then": "$timestamp",
                        "else": {
                            "$dateFromString": {
                                "dateString": "$timestamp",
                                "onError": None,
                                "onNull": None,
                            }
                        },
                    }
                },
                "uri_val": {"$ifNull": ["$request.uri", "$uri"]}
            }
        },
        {"$match": {"date_obj": {"$ne": None}}},
        {
            "$addFields": {
                "endpoint_group": {
                    "$cond": {
                        "if": { "$regexMatch": { "input": {"$ifNull": ["$uri_val", ""]}, "regex": "backup|db|admin|config|settings", "options": "i" } },
                        "then": "sensitive",
                        "else": {
                            "$let": {
                                "vars": {
                                    "parts": { "$split": [{"$ifNull": ["$uri_val", ""]}, "/"] }
                                },
                                "in": {
                                    "$cond": {
                                        "if": { "$gt": [{ "$size": "$$parts" }, 1] },
                                        "then": {
                                            "$cond": {
                                                "if": { "$eq": [{ "$arrayElemAt": ["$$parts", 1] }, "api"] },
                                                "then": {
                                                    "$cond": {
                                                        "if": { "$gt": [{ "$size": "$$parts" }, 2] },
                                                        "then": { "$concat": ["api_", { "$arrayElemAt": ["$$parts", 2] }] },
                                                        "else": "api"
                                                    }
                                                },
                                                "else": { "$arrayElemAt": ["$$parts", 1] }
                                            }
                                        },
                                        "else": "root"
                                    }
                                }
                            }
                        }
                    }
                },
                "hour_bucket": {
                    "$dateToString": {
                        "format": "%Y-%m-%dT%H:00:00Z",
                        "date": "$date_obj"
                    }
                }
            }
        },
        {
            "$group": {
                "_id": {
                    "endpoint_group": "$endpoint_group",
                    "hour_bucket": "$hour_bucket"
                },
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {"count": 1}
        },
        {
            "$group": {
                "_id": "$_id.endpoint_group",
                "counts": {"$push": "$count"}
            }
        },
        {
            "$project": {
                "_id": 1,
                "min_floor": {
                    "$let": {
                        "vars": {
                            "size": {"$size": "$counts"},
                            "index": {
                                "$floor": {
                                    "$multiply": [
                                        {"$size": "$counts"},
                                        percentile
                                    ]
                                }
                            }
                        },
                        "in": {
                            "$let": {
                                "vars": {
                                    "p_val": {
                                        "$arrayElemAt": [
                                            "$counts",
                                            {"$cond": [
                                                {"$gte": ["$$index", "$$size"]},
                                                {"$subtract": ["$$size", 1]},
                                                "$$index"
                                            ]}
                                        ]
                                    }
                                },
                                "in": {
                                    "$max": [
                                        2,
                                        {"$floor": {"$multiply": ["$$p_val", scale_factor]}}
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        },
        {
            "$merge": {
                "into": min_floors_collection,
                "on": "_id",
                "whenMatched": "merge",
                "whenNotMatched": "insert"
            }
        }
    ]

    try:
        coll_req.aggregate(pipeline)
        return {"status": "success", "message": "Min floors calculated and stored successfully"}
    except Exception as e:
        logging.error(f"Error in calculate_endpoint_min_floors: {e}")
        return {"status": "error", "message": str(e)}


def get_baseline_comparison_last_24h(
    db: Any,
    *,
    requests_collection: str = "requests",
    baseline_collection: str = "attack_baselines",
    sigma_multiplier: float = 3.0,
    now: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Return a 24-point hourly comparison of actual alert counts vs baseline thresholds."""
    baseline_coll = _collection(db, baseline_collection)
    requests_coll = _collection(db, requests_collection)

    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    end_hour = current_time.replace(minute=0, second=0, microsecond=0)
    start_hour = end_hour - timedelta(hours=23)

    thresholds_by_hour: Dict[int, float] = {}
    if baseline_coll is not None:
        try:
            for doc in baseline_coll.find():
                raw_key = doc.get("_id")
                if isinstance(raw_key, dict):
                    hour_of_week = _safe_int(raw_key.get("hour_of_week"), -1)
                else:
                    hour_of_week = _safe_int(raw_key, -1)
                if hour_of_week < 0:
                    continue
                mean = float(doc.get("mean", 0.0) or 0.0)
                std_dev = max(float(doc.get("std_dev", 0.0) or 0.0), 0.0)
                thresholds_by_hour[hour_of_week] = thresholds_by_hour.get(hour_of_week, 0.0) + mean + (sigma_multiplier * std_dev)
        except Exception as e:
            logging.error(f"Error loading baseline thresholds: {e}")

    actual_by_bucket: Dict[str, Dict[str, Any]] = {}
    if requests_coll is not None:
        pipeline = [
            {"$match": _malicious_match_query()},
            {
                "$addFields": {
                    "date_obj": {
                        "$cond": {
                            "if": {"$eq": [{"$type": "$timestamp"}, "date"]},
                            "then": "$timestamp",
                            "else": {
                                "$dateFromString": {
                                    "dateString": "$timestamp",
                                    "onError": None,
                                    "onNull": None,
                                }
                            },
                        }
                    }
                }
            },
            {
                "$match": {
                    "date_obj": {
                        "$gte": start_hour,
                        "$lt": end_hour + timedelta(hours=1),
                    }
                }
            },
            {
                "$project": {
                    "hour_bucket": {
                        "$dateToString": {
                            "format": "%Y-%m-%dT%H:00:00Z",
                            "date": "$date_obj",
                        }
                    },
                    "hour_of_week": {
                        "$add": [
                            {"$multiply": [{"$subtract": [{"$dayOfWeek": "$date_obj"}, 1]}, 24]},
                            {"$hour": "$date_obj"},
                        ]
                    },
                    "day_of_week": {"$dayOfWeek": "$date_obj"},
                    "hour": {"$hour": "$date_obj"},
                }
            },
            {
                "$group": {
                    "_id": "$hour_bucket",
                    "count": {"$sum": 1},
                    "hour_of_week": {"$first": "$hour_of_week"},
                    "day_of_week": {"$first": "$day_of_week"},
                    "hour": {"$first": "$hour"},
                }
            },
        ]
        try:
            for row in requests_coll.aggregate(pipeline):
                actual_by_bucket[str(row.get("_id"))] = {
                    "count": _safe_int(row.get("count"), 0),
                    "hour_of_week": _safe_int(row.get("hour_of_week"), -1),
                    "day_of_week": _safe_int(row.get("day_of_week"), 0),
                    "hour": _safe_int(row.get("hour"), 0),
                }
        except Exception as e:
            logging.error(f"Error loading actual baseline comparison counts: {e}")

    series: List[Dict[str, Any]] = []
    for offset in range(24):
        bucket_time = start_hour + timedelta(hours=offset)
        bucket_key = bucket_time.strftime("%Y-%m-%dT%H:00:00Z")
        sunday_based_day = (bucket_time.weekday() + 1) % 7
        hour_of_week = (sunday_based_day * 24) + bucket_time.hour
        mongo_day_of_week = sunday_based_day + 1
        actual_row = actual_by_bucket.get(bucket_key, {})
        series.append(
            {
                "timestamp": bucket_time.isoformat(),
                "label": bucket_time.strftime("%H:00"),
                "hour_of_week": hour_of_week,
                "day_of_week": _safe_int(actual_row.get("day_of_week"), mongo_day_of_week),
                "hour": _safe_int(actual_row.get("hour"), bucket_time.hour),
                "actual_count": _safe_int(actual_row.get("count"), 0),
                "threshold": round(float(thresholds_by_hour.get(hour_of_week, 0.0)), 2),
            }
        )

    return series

