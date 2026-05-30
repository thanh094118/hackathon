from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency
    load_dotenv = None

from src.simulator.engine import SimulationResult, simulate_attack


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run controlled demo web attack simulations.")
    parser.add_argument("--mode", choices=["direct-mongo", "target-url"], default="direct-mongo")
    parser.add_argument("--attack-type", choices=["sqli", "xss", "traversal", "all"], default="sqli")
    parser.add_argument("--target-url", default=None)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--source-ip", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--send-alerts", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    if load_dotenv is not None:
        load_dotenv(PROJECT_ROOT / ".env")

    args = build_parser().parse_args(argv)
    results = simulate_attack(
        mode=args.mode,
        attack_type=args.attack_type,
        count=args.count,
        delay=args.delay,
        source_ip=args.source_ip,
        target_url=args.target_url,
        dry_run=args.dry_run,
        send_alerts=bool(args.send_alerts),
    )

    _print_results(results)
    return 0 if all(result.success for result in results) else 2


def _print_results(results: list[SimulationResult]) -> None:
    for result in results:
        status = "OK" if result.success else "FAIL"
        details = [
            f"mode={result.mode}",
            f"attack={result.attack_type}",
        ]
        if result.event_id:
            details.append(f"event_id={result.event_id}")
        if result.inserted_request_id:
            details.append(f"request_id={result.inserted_request_id}")
        if result.inserted_incident_id:
            details.append(f"incident_id={result.inserted_incident_id}")
        if result.http_status is not None:
            details.append(f"http_status={result.http_status}")
        if result.alert_results:
            ok_count = sum(1 for item in result.alert_results if getattr(item, "success", False))
            details.append(f"alerts={ok_count}/{len(result.alert_results)}")
        if result.error:
            details.append(f"error={result.error}")
        print(f"{status} {result.message} " + " ".join(details))


if __name__ == "__main__":
    raise SystemExit(main())
