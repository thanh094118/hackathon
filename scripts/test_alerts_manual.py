from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.alerts import AlertEvent, build_default_dispatcher, load_alert_config
from src.alerts.formatter import format_alert_text


CHANNELS = ("email", "telegram", "slack")
SECRET_ENV_KEYS = (
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "SLACK_WEBHOOK_URL",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Manually test the standalone alerts module.")
    parser.add_argument(
        "--channels",
        default=None,
        help="Comma-separated channels to test. Defaults to ALERT_CHANNELS or email,telegram,slack.",
    )
    parser.add_argument(
        "--real",
        action="store_true",
        help="Send real alerts using credentials from the environment or .env.",
    )
    parser.add_argument(
        "--no-dotenv",
        action="store_true",
        help="Do not load a local .env file before reading alert config.",
    )
    args = parser.parse_args()

    if not args.no_dotenv:
        _load_dotenv_if_available()

    selected_channels = _parse_channels(
        args.channels or os.environ.get("ALERT_CHANNELS", "email,telegram,slack")
    )
    env = dict(os.environ)
    _apply_test_defaults(env, selected_channels=selected_channels, real_send=args.real)

    config = load_alert_config(env)
    alert = AlertEvent.from_incident(_sample_incident())
    dispatcher = build_default_dispatcher(config)
    results = dispatcher.send(alert)

    print("Alert config:")
    print(f"- enabled: {config.alerts_enabled}")
    print(f"- dry_run: {config.dry_run}")
    print(f"- channels: {', '.join(config.channels) or '(none)'}")
    for key in SECRET_ENV_KEYS:
        print(f"- {key}: {'set' if env.get(key) else 'missing'}")

    print("\nFormatted message:")
    print(format_alert_text(alert))

    print("\nSend results:")
    if not results:
        print("- no results; alerts are disabled or no channels are enabled")
        return 1

    for result in results:
        status = "OK" if result.success else "FAIL"
        error = f" error={result.error}" if result.error else ""
        print(
            f"- {result.channel}: {status} dry_run={result.dry_run} "
            f"message={result.message}{error}"
        )

    return 0 if all(result.success for result in results) else 2


def _load_dotenv_if_available() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    load_dotenv(REPO_ROOT / ".env")


def _parse_channels(value: str) -> list[str]:
    channels = [item.strip().lower() for item in value.split(",") if item.strip()]
    unknown = sorted(set(channels) - set(CHANNELS))
    if unknown:
        raise SystemExit(f"Unknown alert channel(s): {', '.join(unknown)}")
    return channels


def _apply_test_defaults(env: dict[str, str], *, selected_channels: list[str], real_send: bool) -> None:
    env["ALERTS_ENABLED"] = "1"
    env["ALERT_DRY_RUN"] = "0" if real_send else "1"
    env["ALERT_CHANNELS"] = ",".join(selected_channels)
    env.setdefault("ALERT_DASHBOARD_URL", "http://localhost:8501")
    env["ALERT_EMAIL_ENABLED"] = "1" if "email" in selected_channels else "0"
    env["ALERT_TELEGRAM_ENABLED"] = "1" if "telegram" in selected_channels else "0"
    env["ALERT_SLACK_ENABLED"] = "1" if "slack" in selected_channels else "0"


def _sample_incident() -> dict[str, object]:
    return {
        "_id": "manual-alert-test-001",
        "event_time": "2026-05-31T00:00:00Z",
        "risk_level": "high",
        "category": "sqli",
        "score": 91,
        "ip": "203.0.113.10",
        "http_method": "GET",
        "original_url": "/login?id=1' OR '1'='1",
        "message": "Manual alert module test event",
        "prediction": {"label": "malicious", "score": 0.97},
        "mitre": ["T1190"],
        "matched_pattern": "sqli_boolean_condition",
        "similarity_score": 0.84,
        "raw": '203.0.113.10 - - "GET /login?id=1 HTTP/1.1" 200',
        "recommendations": ["Confirm this is a test", "Keep dry-run enabled unless testing delivery"],
        "metadata": {"source": "scripts/test_alerts_manual.py"},
    }


if __name__ == "__main__":
    raise SystemExit(main())
