from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Mapping

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency
    load_dotenv = None

try:
    from pymongo import MongoClient
except Exception:  # pragma: no cover - optional dependency
    MongoClient = None  # type: ignore[assignment]


def _get_bool(env: Mapping[str, str], key: str, default: bool = False) -> bool:
    value = env.get(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "y"}


def _get_int(env: Mapping[str, str], key: str, default: int) -> int:
    value = env.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _channels(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip().lower() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class AlertConfig:
    alerts_enabled: bool = False
    dry_run: bool = True
    channels: list[str] = field(default_factory=list)
    dashboard_url: str | None = None

    email_enabled: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_to: str | None = None
    smtp_use_tls: bool = True

    telegram_enabled: bool = False
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None

    slack_enabled: bool = False
    slack_webhook_url: str | None = None

    def channel_enabled(self, channel: str) -> bool:
        channel_name = channel.lower()
        if not self.alerts_enabled:
            return False
        if self.channels and channel_name not in self.channels:
            return False
        return {
            "email": self.email_enabled,
            "telegram": self.telegram_enabled,
            "slack": self.slack_enabled,
        }.get(channel_name, False)


def load_alert_config(env: Mapping[str, str] | None = None) -> AlertConfig:
    source = os.environ if env is None else env
    return AlertConfig(
        alerts_enabled=_get_bool(source, "ALERTS_ENABLED", False),
        dry_run=_get_bool(source, "ALERT_DRY_RUN", True),
        channels=_channels(source.get("ALERT_CHANNELS", "email,telegram,slack")),
        dashboard_url=source.get("ALERT_DASHBOARD_URL"),
        email_enabled=_get_bool(source, "ALERT_EMAIL_ENABLED", False),
        smtp_host=source.get("SMTP_HOST"),
        smtp_port=_get_int(source, "SMTP_PORT", 587),
        smtp_username=source.get("SMTP_USERNAME"),
        smtp_password=source.get("SMTP_PASSWORD"),
        smtp_from=source.get("SMTP_FROM"),
        smtp_to=source.get("SMTP_TO"),
        smtp_use_tls=_get_bool(source, "SMTP_USE_TLS", True),
        telegram_enabled=_get_bool(source, "ALERT_TELEGRAM_ENABLED", False),
        telegram_bot_token=source.get("TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=source.get("TELEGRAM_CHAT_ID"),
        slack_enabled=_get_bool(source, "ALERT_SLACK_ENABLED", False),
        slack_webhook_url=source.get("SLACK_WEBHOOK_URL"),
    )


def load_effective_alert_config(
    env: Mapping[str, str] | None = None,
    *,
    db: Any | None = None,
) -> AlertConfig:
    source = os.environ if env is None else env

    if db is not None:
        try:
            from .settings_store import AlertSettingsStore

            stored = AlertSettingsStore(db).load_config()
            if stored is not None:
                return stored
        except Exception:
            pass

    if env is None and load_dotenv is not None:
        load_dotenv()

    uri = str(source.get("MONGODB_URI", "")).strip()
    database_name = (
        str(source.get("MONGODB_DB_NAME", "")).strip()
        or str(source.get("MONGODB_DATABASE", "")).strip()
        or "threatlens"
    )
    if uri and MongoClient is not None:
        try:
            from .settings_store import AlertSettingsStore

            client = MongoClient(uri, serverSelectionTimeoutMS=3000)
            stored = AlertSettingsStore(client[database_name]).load_config()
            client.close()
            if stored is not None:
                return stored
        except Exception:
            pass

    return load_alert_config(env)
