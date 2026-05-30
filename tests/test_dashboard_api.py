import os
import pytest
from fastapi.testclient import TestClient

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

def test_api_incident_detail_not_found():
    response = client.get("/api/incidents/non-existent-id")
    assert response.status_code == 404

def test_api_index_html():
    response = client.get("/")
    assert response.status_code == 200
