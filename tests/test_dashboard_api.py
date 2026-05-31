import os
import pytest
from fastapi.testclient import TestClient
from cryptography.fernet import Fernet

# Set mock mode environment variable for testing
os.environ["DASHBOARD_USE_MOCK"] = "1"

from src.dashboard.api import app

client = TestClient(app)

def test_api_status():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert "connection" in data
    assert data["connection"] == "Mock Mode" or data["connection"] == "Connected"

def test_api_summary():
    response = client.get("/api/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_requests" in data
    assert "malicious_requests" in data
    assert "total_incidents" in data
    assert "active_campaigns" in data
    assert "total_requests_trend" in data
    assert "malicious_requests_trend" in data

def test_api_attack_types():
    response = client.get("/api/attack-types")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        assert "attack_type" in data[0]
        assert "count" in data[0]

def test_api_top_ips():
    response = client.get("/api/top-ips?limit=5")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) <= 5

def test_api_timeline():
    response = client.get("/api/timeline?bucket_size=5&unit=minute")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_api_blast_radius():
    # In mock mode, we have "185.24.9.10"
    response = client.get("/api/blast-radius?ip=185.24.9.10")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_api_blast_radius_missing_ip():
    response = client.get("/api/blast-radius")
    assert response.status_code == 422 # missing query param

def test_api_campaigns():
    response = client.get("/api/campaigns?min_attacks=2&min_attack_types=1")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_api_incidents():
    response = client.get("/api/incidents?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if data:
        assert {row["detection_method"] for row in data} == {"hybrid"}

    legacy_response = client.get("/api/incidents?limit=10&method=Rules%20Only")
    assert legacy_response.status_code == 200
    assert legacy_response.json() == data

def test_api_incident_detail_not_found():
    response = client.get("/api/incidents/non-existent-id")
    assert response.status_code == 404

def test_api_index_html():
    response = client.get("/")
    assert response.status_code == 200

def test_api_timeframe_parameters():
    for timeframe in ["15m", "1h", "24h", "7d", "all"]:
        response = client.get(f"/api/summary?timeframe={timeframe}")
        assert response.status_code == 200
        
        response = client.get(f"/api/attack-types?timeframe={timeframe}")
        assert response.status_code == 200
        
        response = client.get(f"/api/top-ips?limit=5&timeframe={timeframe}")
        assert response.status_code == 200
        
        response = client.get(f"/api/timeline?bucket_size=5&unit=minute&timeframe={timeframe}")
        assert response.status_code == 200
        
        response = client.get(f"/api/campaigns?min_attacks=2&min_attack_types=1&timeframe={timeframe}")
        assert response.status_code == 200
        
        response = client.get(f"/api/incidents?limit=10&timeframe={timeframe}")
        assert response.status_code == 200

def test_api_materialized_campaigns():
    response = client.get("/api/materialized-campaigns?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_api_alert_settings_get_env_fallback():
    response = client.get("/api/settings/alerts")
    assert response.status_code == 200
    data = response.json()
    assert data["source"] in {"environment", "mongodb"}
    assert "encryption" in data
    assert "smtp_password_set" in data["email"]
    assert "smtp_password_mask" in data["email"]
    assert "webhook_url" not in data.get("slack", {})

def test_api_alert_settings_save_requires_mongo_when_disconnected():
    response = client.put("/api/settings/alerts", json={"alerts_enabled": True})
    assert response.status_code in {200, 503}

def test_api_alert_settings_save_with_patched_store(monkeypatch):
    from src.dashboard import api

    monkeypatch.setenv("ALERT_SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    db = FakeDb()
    monkeypatch.setattr(api.query_engine, "db", db)

    response = client.put(
        "/api/settings/alerts",
        json={
            "alerts_enabled": True,
            "channels": ["slack"],
            "slack": {"enabled": True, "webhook_url": "https://hooks.slack.test/secret"},
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["slack"]["webhook_url_set"] is True
    assert "https://hooks.slack.test/secret" not in str(data)
    assert "https://hooks.slack.test/secret" not in str(db["alert_settings"].document)

def test_api_alert_settings_save_reports_invalid_key(monkeypatch):
    from src.dashboard import api

    monkeypatch.setenv("ALERT_SETTINGS_ENCRYPTION_KEY", "not-a-fernet-key")
    monkeypatch.setattr(api.query_engine, "db", FakeDb())

    response = client.put(
        "/api/settings/alerts",
        json={"slack": {"enabled": True, "webhook_url": "https://hooks.slack.test/secret"}},
    )

    assert response.status_code == 503
    assert "Generate a valid key" in response.json()["detail"]


class FakeDb:
    def __init__(self) -> None:
        self.collections = {"alert_settings": FakeCollection()}

    def __getitem__(self, name: str) -> "FakeCollection":
        return self.collections.setdefault(name, FakeCollection())


class FakeCollection:
    def __init__(self) -> None:
        self.document = None

    def find_one(self, query):
        return self.document if self.document and self.document.get("_id") == query.get("_id") else None

    def replace_one(self, query, document, upsert=False):
        self.document = dict(document)
        return None
