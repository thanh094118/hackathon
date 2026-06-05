import os
from datetime import datetime, timezone

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

def test_api_managed_incidents_route_not_shadowed(monkeypatch):
    from src.dashboard import api

    db = FakeDb(
        collections={
            "managed_incidents": FakeCollection(
                [
                    {
                        "_id": "INC-20260605-ROUTE",
                        "title": "Managed route regression",
                        "status": "cooldown",
                        "behavior_type": "reconnaissance",
                        "created_at": "2026-06-05T10:00:00+00:00",
                    }
                ]
            )
        }
    )
    monkeypatch.setattr(api.query_engine, "db", db)

    response = client.get("/api/incidents/managed?limit=100")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["_id"] == "INC-20260605-ROUTE"

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


def test_api_baseline_status_returns_extended_fields(monkeypatch):
    from src.dashboard import api

    db = FakeDb(
        collections={
            "attack_baselines": FakeCollection(
                [
                    {"_id": {"hour_of_week": 10, "endpoint_group": "api_v1"}, "mean": 4.0, "std_dev": 1.5},
                ]
            ),
            "endpoint_min_floors": FakeCollection(
                [
                    {"_id": "api_v1", "min_floor": 3},
                    {"_id": "sensitive", "min_floor": 2},
                ]
            ),
        }
    )
    monkeypatch.setattr(api.query_engine, "db", db)
    monkeypatch.setattr(
        api.mongodb_queries,
        "get_baseline_comparison_last_24h",
        lambda current_db: [
            {
                "timestamp": "2026-06-05T00:00:00+00:00",
                "label": "00:00",
                "hour_of_week": 10,
                "day_of_week": 1,
                "hour": 0,
                "actual_count": 5,
                "threshold": 8.5,
            }
        ],
    )

    response = client.get("/api/baseline/status")

    assert response.status_code == 200
    data = response.json()
    assert "generated_at" in data
    assert data["baselines"][0]["_id"]["endpoint_group"] == "api_v1"
    assert data["endpoint_floors"][0]["endpoint_group"] == "api_v1"
    assert data["comparison_last_24h"][0]["actual_count"] == 5
    assert data["actual_last_24h"][0]["count"] == 5


def test_api_baseline_status_lazy_creates_missing_collections(monkeypatch):
    from src.dashboard import api

    db = FakeDb(
        collections={
            "attack_baselines": FakeCollection(),
            "endpoint_min_floors": FakeCollection(),
        }
    )
    monkeypatch.setattr(api.query_engine, "db", db)

    class FakeDynamicBaseline:
        def __init__(self, current_db):
            self.db = current_db

        def calculate_baselines(self):
            self.db["attack_baselines"].insert_one(
                {"_id": {"hour_of_week": 8, "endpoint_group": "root"}, "mean": 10.0, "std_dev": 2.0}
            )
            return {"status": "success", "message": "baseline seeded"}

        def calculate_min_floors(self):
            self.db["endpoint_min_floors"].insert_one({"_id": "root", "min_floor": 7})
            return {"status": "success", "message": "floors seeded"}

    monkeypatch.setattr(api, "DynamicBaseline", FakeDynamicBaseline)
    monkeypatch.setattr(api.mongodb_queries, "get_baseline_comparison_last_24h", lambda current_db: [])

    response = client.get("/api/baseline/status")

    assert response.status_code == 200
    data = response.json()
    assert data["baselines"][0]["_id"]["endpoint_group"] == "root"
    assert data["endpoint_floors"][0]["endpoint_group"] == "root"


def test_api_baseline_recalculate_returns_operation_results(monkeypatch):
    from src.dashboard import api

    db = FakeDb(
        collections={
            "attack_baselines": FakeCollection(
                [{"_id": {"hour_of_week": 4, "endpoint_group": "root"}, "mean": 2.0, "std_dev": 0.5}]
            ),
            "endpoint_min_floors": FakeCollection([{"_id": "root", "min_floor": 2}]),
        }
    )
    monkeypatch.setattr(api.query_engine, "db", db)

    class FakeDynamicBaseline:
        def __init__(self, current_db):
            self.db = current_db

        def calculate_baselines(self):
            self.db["attack_baselines"].documents = [
                {"_id": {"hour_of_week": 4, "endpoint_group": "root"}, "mean": 12.0, "std_dev": 3.0}
            ]
            return {"status": "success", "message": "baseline recalculated"}

        def calculate_min_floors(self):
            self.db["endpoint_min_floors"].documents = [{"_id": "root", "min_floor": 11}]
            return {"status": "success", "message": "floors recalculated"}

    monkeypatch.setattr(api, "DynamicBaseline", FakeDynamicBaseline)
    monkeypatch.setattr(
        api.mongodb_queries,
        "get_baseline_comparison_last_24h",
        lambda current_db: [
            {
                "timestamp": "2026-06-05T04:00:00+00:00",
                "label": "04:00",
                "hour_of_week": 4,
                "day_of_week": 1,
                "hour": 4,
                "actual_count": 9,
                "threshold": 21.0,
            }
        ],
    )

    response = client.post("/api/baseline/recalculate")

    assert response.status_code == 200
    data = response.json()
    assert data["baseline_calculation"]["status"] == "success"
    assert data["min_floor_calculation"]["status"] == "success"
    assert data["baselines"][0]["mean"] == 12.0
    assert data["endpoint_floors"][0]["min_floor"] == 11
    assert data["comparison_last_24h"][0]["threshold"] == 21.0


def test_api_false_positive_success(monkeypatch):
    from src.dashboard import api

    db = FakeDb(
        collections={
            "managed_incidents": FakeCollection(
                [
                    {
                        "_id": "INC-20260605-ABC123",
                        "title": "Correlated incident",
                        "behavior_type": "reconnaissance",
                        "embedding": [0.1, 0.2, 0.3],
                        "status": "cooldown",
                    }
                ]
            ),
            "false_positives": FakeCollection(),
        }
    )
    monkeypatch.setattr(api.query_engine, "db", db)

    response = client.post(
        "/api/incidents/INC-20260605-ABC123/false-positive",
        json={"notes": "known scanner"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["resolution"] == "false_positive"
    stored_fp = db["false_positives"].find_one({"incident_id": "INC-20260605-ABC123"})
    assert stored_fp is not None
    managed = db["managed_incidents"].find_one({"_id": "INC-20260605-ABC123"})
    assert managed["resolution"] == "false_positive"
    assert managed["status"] == "resolved"


def test_api_false_positive_failure(monkeypatch):
    from src.dashboard import api

    db = FakeDb(
        collections={
            "managed_incidents": FakeCollection(
                [
                    {
                        "_id": "INC-20260605-NOEMBED",
                        "title": "Correlated incident",
                        "behavior_type": "single",
                        "status": "cooldown",
                    }
                ]
            ),
            "false_positives": FakeCollection(),
        }
    )
    monkeypatch.setattr(api.query_engine, "db", db)

    response = client.post("/api/incidents/INC-20260605-NOEMBED/false-positive", json={"notes": "missing vector"})

    assert response.status_code == 400
    assert "Failed to mark incident" in response.json()["detail"]


class FakeDb:
    def __init__(self, collections=None) -> None:
        self.collections = collections or {"alert_settings": FakeCollection()}

    def __getitem__(self, name: str) -> "FakeCollection":
        return self.collections.setdefault(name, FakeCollection())


class FakeCursor:
    def __init__(self, documents):
        self.documents = [dict(document) for document in documents]

    def sort(self, field, direction):
        reverse = direction == -1
        self.documents.sort(key=lambda row: row.get(field), reverse=reverse)
        return self

    def limit(self, count):
        self.documents = self.documents[:count]
        return self

    def __iter__(self):
        return iter(self.documents)


class FakeCollection:
    def __init__(self, documents=None) -> None:
        self.documents = [dict(document) for document in (documents or [])]
        self.document = self.documents[0] if len(self.documents) == 1 else None

    def _sync_document(self):
        self.document = self.documents[0] if len(self.documents) == 1 else None

    def _matches(self, document, query):
        if not query:
            return True
        for key, expected in query.items():
            value = document.get(key)
            if isinstance(expected, dict):
                if "$in" in expected and value not in expected["$in"]:
                    return False
                if "$gt" in expected and not (value is not None and value > expected["$gt"]):
                    return False
                continue
            if value != expected:
                return False
        return True

    def find(self, query=None, projection=None):
        matched = [dict(document) for document in self.documents if self._matches(document, query or {})]
        return FakeCursor(matched)

    def find_one(self, query=None, projection=None, sort=None):
        matched = [dict(document) for document in self.documents if self._matches(document, query or {})]
        if sort:
            field, direction = sort[0]
            matched.sort(key=lambda row: row.get(field), reverse=direction == -1)
        return matched[0] if matched else None

    def replace_one(self, query, document, upsert=False):
        for index, existing in enumerate(self.documents):
            if self._matches(existing, query):
                self.documents[index] = dict(document)
                self._sync_document()
                return None
        if upsert:
            self.documents.append(dict(document))
            self._sync_document()
        return None

    def update_one(self, query, update, upsert=False):
        for document in self.documents:
            if self._matches(document, query):
                document.update(update.get("$set", {}))
                self._sync_document()
                return None
        if upsert:
            new_document = dict(query)
            new_document.update(update.get("$set", {}))
            self.documents.append(new_document)
            self._sync_document()
        return None

    def insert_one(self, document):
        self.documents.append(dict(document))
        self._sync_document()
        return None

    def count_documents(self, query):
        return sum(1 for document in self.documents if self._matches(document, query))
