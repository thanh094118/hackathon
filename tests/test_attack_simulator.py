from __future__ import annotations

import urllib.request

from scripts.simulate_attacks import build_parser
from src.simulator.engine import build_attack_request, run_simulation, simulate_target_url


def test_target_url_mode_blocks_public_hosts(monkeypatch):
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


def test_target_url_all_cycles_payloads(monkeypatch):
    results = simulate_target_url(
        attack_type="all",
        target_url="http://localhost:8080",
        count=4,
        dry_run=True,
    )
    assert [result.attack_type for result in results] == ["sqli", "xss", "traversal", "sqli"]


def test_count_is_capped_by_env(monkeypatch):
    monkeypatch.setenv("SIMULATOR_MAX_COUNT", "2")
    results = simulate_target_url(
        attack_type="sqli",
        target_url="http://localhost:8080",
        count=9,
        dry_run=True,
    )
    assert len(results) == 2


def test_build_attack_request_url_encodes_payload():
    url, headers = build_attack_request("http://localhost:8080", "sqli")
    assert "UNION+SELECT" in url
    assert headers["User-Agent"] == "attack-simulator-sqli/1.0"


def test_cli_argument_parsing_target_url_only():
    args = build_parser().parse_args(
        [
            "--mode",
            "target-url",
            "--target-url",
            "http://localhost:8080",
            "--attack-type",
            "xss",
            "--interval",
            "1",
            "--max-events",
            "5",
            "--dry-run",
        ]
    )
    assert args.mode == "target-url"
    assert args.target_url == "http://localhost:8080"
    assert args.attack_type == "xss"
    assert args.interval == 1
    assert args.max_events == 5
    assert args.dry_run is True


def test_run_simulation_rejects_unsupported_mode():
    results = run_simulation(mode="legacy-mode", attack_type="sqli", count=1)
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error == "unsupported_mode"
