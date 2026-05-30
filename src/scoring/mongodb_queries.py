from __future__ import annotations

from typing import Any, Dict, List, Optional


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
            {"prediction.label": {"$in": ["malicious", "suspicious", "attack"]}},
            {"attack_type": {"$exists": True, "$nin": [None, "", "Unknown", "unknown", "normal", "benign"]}},
            {"risk_score": {"$gte": 70}},
        ]
    }


def explain_threat_via_vector_search(
    db: Any,
    embedding: List[float],
    limit: int = 3,
    *,
    patterns_collection: str = "attack_patterns",
    index_name: str = "attack_patterns_vector_index",
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
                "name": 1,
                "description": 1,
                "examples": 1,
                "remediation": 1,
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


def get_attack_type_distribution(
    db: Any,
    *,
    requests_collection: str = "requests",
    limit: int = 20,
) -> List[Dict[str, Any]]:
    collection = _collection(db, requests_collection)
    if collection is None:
        return []

    pipeline = [
        {"$match": _malicious_match_query()},
        {
            "$group": {
                "_id": {"$ifNull": ["$attack_type", "Unknown"]},
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
) -> List[Dict[str, Any]]:
    collection = _collection(db, requests_collection)
    if collection is None:
        return []

    pipeline = [
        {"$match": _malicious_match_query()},
        {
            "$group": {
                "_id": {"$ifNull": ["$ip", "Unknown"]},
                "total_attacks": {"$sum": 1},
                "attack_types": {"$addToSet": "$attack_type"},
                "target_uris": {"$addToSet": "$uri"},
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
    min_attacks: int = 10,
    limit: int = 10,
    *,
    requests_collection: str = "requests",
) -> List[Dict[str, Any]]:
    collection = _collection(db, requests_collection)
    if collection is None:
        return []

    threshold = max(1, _safe_int(min_attacks, 10))
    max_limit = max(1, _safe_int(limit, 10))

    pipeline = [
        {"$match": _malicious_match_query()},
        {
            "$group": {
                "_id": {"$ifNull": ["$ip", "Unknown"]},
                "total_attacks": {"$sum": 1},
                "attack_types": {"$addToSet": "$attack_type"},
                "target_uris": {"$addToSet": "$uri"},
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
                "$or": [
                    {"total_attacks": {"$gte": threshold}},
                    {"attack_type_count": {"$gt": 1}},
                    {"target_count": {"$gt": 1}},
                ]
            }
        },
        {"$sort": {"total_attacks": -1}},
        {"$limit": max_limit},
    ]

    try:
        return [dict(row) for row in collection.aggregate(pipeline, allowDiskUse=True)]
    except Exception:
        return []


def generate_attack_timeline(
    db: Any,
    ip: Optional[str] = None,
    hours_bucket: int = 1,
    limit: int = 100,
    *,
    requests_collection: str = "requests",
) -> List[Dict[str, Any]]:
    collection = _collection(db, requests_collection)
    if collection is None:
        return []

    match_query: Dict[str, Any] = dict(_malicious_match_query())
    if ip:
        match_query["ip"] = str(ip)

    bucket_size = max(1, _safe_int(hours_bucket, 1))
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
                }
            }
        },
        {"$match": {"_timeline_ts": {"$ne": None}}},
        {
            "$group": {
                "_id": {
                    "$dateTrunc": {
                        "date": "$_timeline_ts",
                        "unit": "hour",
                        "binSize": bucket_size,
                    }
                },
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"_id": 1}},
        {"$limit": max_limit},
        {"$project": {"_id": 0, "timestamp": "$_id", "count": 1}},
    ]

    try:
        return [dict(row) for row in collection.aggregate(pipeline, allowDiskUse=True)]
    except Exception:
        return []
