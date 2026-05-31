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

# Serve static files path
STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)

@app.get("/api/status")
def get_status():
    return query_engine.status()

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

# Serves index.html at root "/"
@app.get("/")
def read_index():
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        return {"message": "ThreatLens AI dashboard static assets are missing. Please build or create static/index.html"}
    return FileResponse(index_path)

# Serve all other static assets if any
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
