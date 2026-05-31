import os
import sys
from pathlib import Path
from typing import Optional

# Add project root to sys.path to allow importing from src
root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src.dashboard.query_adapter import DashboardQueryAdapter
from src.alerts.crypto import AlertSettingsCryptoError
from src.alerts.models import AlertEvent
from src.alerts.settings_store import AlertSettingsStore, public_settings_from_config
from src.alerts.config import load_alert_config
from src.alerts.dispatcher import build_default_dispatcher

app = FastAPI(title="ThreatLens AI API", description="REST API backend for ThreatLens AI SOC Co-Pilot")

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instantiate the query engine
# Using a single query engine instance
query_engine = DashboardQueryAdapter()


def _alert_settings_store() -> AlertSettingsStore:
    if query_engine.db is None:
        raise HTTPException(status_code=503, detail="MongoDB is not connected")
    return AlertSettingsStore(query_engine.db)

# Serve static files path
STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)

@app.get("/api/status")
def get_status():
    return query_engine.status()

@app.get("/api/settings/alerts")
def get_alert_settings():
    try:
        return _alert_settings_store().get_public_settings()
    except HTTPException:
        return public_settings_from_config(load_alert_config(), source="environment")

@app.put("/api/settings/alerts")
def save_alert_settings(payload: dict):
    try:
        return _alert_settings_store().save_settings(payload)
    except AlertSettingsCryptoError as exc:
        raise HTTPException(status_code=503, detail=f"{exc}. Generate a valid key with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"") from exc

@app.post("/api/settings/alerts/test")
def test_alert_settings(payload: dict | None = None):
    store = _alert_settings_store()
    config = store.load_config()
    if config is None:
        raise HTTPException(status_code=404, detail="Alert settings have not been saved. Save settings successfully before sending a test alert.")

    incident = {
        "incident_id": "settings-test",
        "timestamp": "now",
        "severity": "high",
        "attack_type": "settings-test",
        "risk_score": 90,
        "source_ip": "127.0.0.1",
        "method": "GET",
        "uri": "/settings/test",
        "message": "Dashboard alert settings test",
        "recommendations": ["Confirm the selected alert channel received this test."],
    }
    if payload and isinstance(payload.get("incident"), dict):
        incident.update(payload["incident"])

    results = build_default_dispatcher(config).send(AlertEvent.from_incident(incident))
    return {"results": [result.__dict__ for result in results]}

@app.get("/api/summary")
def get_summary(timeframe: Optional[str] = Query(None)):
    return query_engine.get_soc_summary(timeframe=timeframe)

@app.get("/api/attack-types")
def get_attack_types(timeframe: Optional[str] = Query(None)):
    return query_engine.get_attack_type_distribution(timeframe=timeframe)

@app.get("/api/top-ips")
def get_top_ips(limit: int = Query(10, ge=1), timeframe: Optional[str] = Query(None)):
    return query_engine.get_top_attacking_ips(limit=limit, timeframe=timeframe)

@app.get("/api/timeline")
def get_timeline(bucket_size: int = Query(5, ge=1), unit: str = "minute", timeframe: Optional[str] = Query(None)):
    return query_engine.get_attack_timeline(bucket_size=bucket_size, unit=unit, timeframe=timeframe)

@app.get("/api/blast-radius")
def get_blast_radius(ip: str):
    if not ip:
        raise HTTPException(status_code=400, detail="IP address parameter is required")
    return query_engine.get_ip_blast_radius(ip)

@app.get("/api/campaigns")
def get_campaigns(min_attacks: int = Query(50, ge=1), min_attack_types: int = Query(3, ge=1), timeframe: Optional[str] = Query(None)):
    return query_engine.get_active_campaigns(min_attacks=min_attacks, min_attack_types=min_attack_types, timeframe=timeframe)

@app.get("/api/materialized-campaigns")
def get_materialized_campaigns(limit: int = Query(50, ge=1)):
    return query_engine.get_materialized_campaigns(limit=limit)

@app.get("/api/incidents")
def get_incidents(limit: int = Query(100, ge=1), method: str = "All", timeframe: Optional[str] = Query(None)):
    return query_engine.get_recent_incidents(limit=limit, method_filter=method, timeframe=timeframe)

@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    detail = query_engine.get_incident_detail(incident_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    
    # We should augment the incident with similar patterns, recommendations, and rule based explanation
    embedding = detail.get("embedding") or []
    patterns = []
    if embedding:
        patterns = query_engine.find_similar_attack_patterns(embedding, limit=3)
    
    recommendations = query_engine.get_response_recommendations(detail, patterns=patterns)
    hybrid_explanation = query_engine.build_rule_based_explanation(detail)
    
    # Merge them into the response
    detail["patterns"] = patterns
    detail["recommendations"] = recommendations
    detail["hybrid_explanation"] = hybrid_explanation
    detail["rule_explanation"] = hybrid_explanation
    return detail

@app.get("/api/incidents/{incident_id}/similar-incidents")
def get_similar_incidents(incident_id: str, limit: int = Query(5, ge=1)):
    detail = query_engine.get_incident_detail(incident_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    
    embedding = detail.get("embedding") or []
    if not embedding:
        return []
    
    return query_engine.find_similar_requests(embedding, limit=limit)

@app.get("/api/incidents/managed")
def get_managed_incidents(limit: int = Query(100, ge=1)):
    if query_engine.db is None:
        raise HTTPException(status_code=503, detail="MongoDB is not connected")
    try:
        coll = query_engine.db["managed_incidents"]
        cursor = coll.find().sort("created_at", -1).limit(limit)
        results = list(cursor)
        for doc in results:
            doc["_id"] = str(doc["_id"])
            if "created_at" in doc and hasattr(doc["created_at"], "isoformat"):
                doc["created_at"] = doc["created_at"].isoformat()
            if "updated_at" in doc and hasattr(doc["updated_at"], "isoformat"):
                doc["updated_at"] = doc["updated_at"].isoformat()
            if "cooldown_until" in doc and hasattr(doc["cooldown_until"], "isoformat"):
                doc["cooldown_until"] = doc["cooldown_until"].isoformat()
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/incidents/{incident_id}/false-positive")
def mark_incident_false_positive(incident_id: str, payload: dict | None = None):
    if query_engine.db is None:
        raise HTTPException(status_code=503, detail="MongoDB is not connected")
    notes = ""
    if payload:
        notes = payload.get("notes") or ""
    
    from src.alerts.fp_suppression import FPSuppressionEngine
    engine = FPSuppressionEngine(query_engine.db)
    success = engine.mark_false_positive(incident_id, notes)
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to mark incident {incident_id} as false positive")
    return {"status": "success", "message": f"Incident {incident_id} successfully marked as false positive"}


@app.get("/api/baseline/status")
def get_baseline_status():
    if query_engine.db is None:
        raise HTTPException(status_code=503, detail="MongoDB is not connected")
    try:
        coll = query_engine.db["attack_baselines"]
        baselines = list(coll.find())
        for b in baselines:
            b["_id"] = int(b["_id"])
        
        if not baselines:
            from src.alerts.dynamic_baseline import DynamicBaseline
            engine = DynamicBaseline(query_engine.db)
            engine.calculate_baselines()
            baselines = list(coll.find())
            for b in baselines:
                b["_id"] = int(b["_id"])

        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        coll_req = query_engine.db["requests"]
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
                    }
                }
            },
            {"$match": {"date_obj": {"$gte": now - timedelta(hours=24)}}},
            {
                "$project": {
                    "hour": {"$hour": "$date_obj"},
                    "dayOfWeek": {"$dayOfWeek": "$date_obj"}
                }
            },
            {
                "$group": {
                    "_id": {"dayOfWeek": "$dayOfWeek", "hour": "$hour"},
                    "count": {"$sum": 1}
                }
            }
        ]
        actual_hourly = list(coll_req.aggregate(pipeline))
        for act in actual_hourly:
            day = act["_id"]["dayOfWeek"] - 1
            hour = act["_id"]["hour"]
            act["hour_of_week"] = day * 24 + hour
        
        return {
            "baselines": baselines,
            "actual_last_24h": actual_hourly
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Serves index.html at root "/"
@app.get("/")
def read_index():
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        return {"message": "ThreatLens AI dashboard static assets are missing. Please build or create static/index.html"}
    return FileResponse(index_path)

# Serve all other static assets if any
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

