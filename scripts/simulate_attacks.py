from __future__ import annotations

import argparse
import itertools
import random
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency
    load_dotenv = None

from src.simulator.engine import SimulationResult, run_simulation


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run realtime traffic simulator (continuous).")
    parser.add_argument("--mode", choices=["target-url"], default="target-url")
    parser.add_argument("--attack-type", choices=["sqli", "xss", "traversal", "all"], default="all")
    parser.add_argument("--target-url", default=None)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--max-events", type=int, default=0, help="0 means run forever.")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    if load_dotenv is not None:
        load_dotenv(PROJECT_ROOT / ".env")

    args = build_parser().parse_args(argv)
    return _run_continuous(args)


def _run_continuous(args: argparse.Namespace) -> int:
    sent = 0
    attack_cycle = itertools.cycle(["sqli", "xss", "traversal"] if args.attack_type == "all" else [args.attack_type])
    try:
        while True:
            if args.max_events > 0 and sent >= args.max_events:
                break
            results = run_simulation(
                mode=args.mode,
                attack_type="normal",
                count=1,
                delay=0.0,
                target_url=args.target_url,
                dry_run=bool(args.dry_run),
                force=True,
            )
            _print_results(results)
            sent += 1

            if sent % 10 == 0:
                attack_burst = random.randint(1, 2)
                for _ in range(attack_burst):
                    if args.max_events > 0 and sent >= args.max_events:
                        break
                    attack = next(attack_cycle)
                    attack_results = run_simulation(
                        mode=args.mode,
                        attack_type=attack,
                        count=1,
                        delay=0.0,
                        target_url=args.target_url,
                        dry_run=bool(args.dry_run),
                        force=True,
                    )
                    _print_results(attack_results)
                    sent += 1
            time.sleep(max(0.1, float(args.interval)))
    except KeyboardInterrupt:
        print("Stopped by user.")
    return 0


def _print_results(results: list[SimulationResult]) -> None:
    for result in results:
        status = "OK" if result.success else "FAIL"
        details = [
            f"mode={result.mode}",
            f"attack={result.attack_type}",
        ]
        if result.event_id:
            details.append(f"event_id={result.event_id}")
        if result.http_status is not None:
            details.append(f"http_status={result.http_status}")
        if result.error:
            details.append(f"error={result.error}")
        print(f"{status} {result.message} " + " ".join(details))


if __name__ == "__main__":
    raise SystemExit(main())
