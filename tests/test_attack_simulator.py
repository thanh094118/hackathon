from __future__ import annotations

import urllib.request

from scripts.simulate_attacks import build_parser
from src.alerts import AlertSendResult
from src.simulator.engine import (
    build_simulated_event,
    simulate_attack,
    simulate_direct_mongo,
    simulate_target_url,
)


def test_build_simulated_event_creates_valid_sqli_event():
    event = build_simulated_event("sqli", source_ip="198.51.100.10")

    assert event["event_id"].startswith("sim-")
    assert event["attack_type"] == "SQLI"
    assert event["ip"] == "198.51.100.10"
    assert event["source_ip"] == "198.51.100.10"
    assert event["risk_score"] >= 80
    assert event["is_simulated"] is True
    assert "UNION SELECT" in event["raw"]


def test_build_simulated_event_creates_valid_xss_event():
    event = build_simulated_event("xss")

    assert event["attack_type"] == "XSS"
    assert "<script>" in event["uri"]
    assert event["prediction"]["label"] == "malicious"


def test_build_simulated_event_creates_valid_traversal_event():
    event = build_simulated_event("traversal")

    assert event["attack_type"] == "TRAVERSAL"
    assert "../" in event["uri"]
    assert event["severity"] == "high"


def test_direct_mongo_mode_inserts_request_and_incident_with_fake_db():
    db = FakeDB()

    results = simulate_direct_mongo(
        attack_type="sqli",
        count=1,
        db=db,
        send_alerts=False,
    )

    assert len(results) == 1
    assert results[0].success is True
    assert results[0].inserted_request_id == "requests-1"
    assert results[0].inserted_incident_id == "incidents-1"
    assert len(db["requests"].docs) == 1
    assert len(db["incidents"].docs) == 1
    assert db["requests"].docs[0]["is_simulated"] is True
    assert db["incidents"].docs[0]["request_event_id"] == db["requests"].docs[0]["event_id"]


def test_direct_mongo_mode_triggers_alert_for_high_risk_incident():
    dispatcher = FakeDispatcher()

    results = simulate_direct_mongo(
        attack_type="xss",
        count=1,
        db=FakeDB(),
        send_alerts=True,
        alert_dispatcher=dispatcher,
    )

    assert results[0].success is True
    assert dispatcher.sent is True
    assert results[0].alert_results == [AlertSendResult("fake", True, "sent")]


def test_target_url_mode_blocks_public_hosts():
    results = simulate_target_url(
        attack_type="sqli",
        target_url="https://example.com",
        dry_run=True,
    )

    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error == "host_not_allowed"


def test_target_url_mode_supports_dry_run_without_network_call(monkeypatch):
    def fail_urlopen(*args, **kwargs):
        raise AssertionError("network should not be called in dry-run")

    monkeypatch.setattr(urllib.request, "urlopen", fail_urlopen)

    results = simulate_target_url(
        attack_type="xss",
        target_url="http://localhost:8080",
        count=2,
        dry_run=True,
    )

    assert len(results) == 2
    assert all(result.success for result in results)
    assert all(result.message == "target-url dry-run" for result in results)


def test_cli_argument_parsing_for_direct_mongo():
    args = build_parser().parse_args(
        ["--mode", "direct-mongo", "--attack-type", "sqli", "--count", "3", "--send-alerts"]
    )

    assert args.mode == "direct-mongo"
    assert args.attack_type == "sqli"
    assert args.count == 3
    assert args.send_alerts is True


def test_cli_argument_parsing_for_target_url():
    args = build_parser().parse_args(
        [
            "--mode",
            "target-url",
            "--target-url",
            "http://localhost:8080",
            "--attack-type",
            "xss",
            "--count",
            "5",
            "--delay",
            "1",
            "--dry-run",
        ]
    )

    assert args.mode == "target-url"
    assert args.target_url == "http://localhost:8080"
    assert args.attack_type == "xss"
    assert args.count == 5
    assert args.delay == 1
    assert args.dry_run is True


def test_simulate_attack_cycles_all_attack_types_in_dry_run():
    results = simulate_attack(mode="direct-mongo", attack_type="all", count=4, dry_run=True)

    assert [result.attack_type for result in results] == ["sqli", "xss", "traversal", "sqli"]
    assert all(result.success for result in results)


class FakeInsertResult:
    def __init__(self, inserted_id: str) -> None:
        self.inserted_id = inserted_id


class FakeCollection:
    def __init__(self, name: str) -> None:
        self.name = name
        self.docs = []

    def insert_one(self, doc):
        self.docs.append(dict(doc))
        return FakeInsertResult(f"{self.name}-{len(self.docs)}")


class FakeDB:
    def __init__(self) -> None:
        self.collections = {
            "requests": FakeCollection("requests"),
            "incidents": FakeCollection("incidents"),
        }

    def __getitem__(self, name: str):
        return self.collections[name]


class FakeDispatcher:
    def __init__(self) -> None:
        self.sent = False

    def send(self, alert):
        self.sent = True
        return [AlertSendResult("fake", True, "sent")]
