from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping

from .config import AlertConfig, load_alert_config
from .crypto import decrypt_secret, encrypt_secret, get_crypto_status, mask_secret


SETTINGS_ID = "default"
COLLECTION_NAME = "alert_settings"
SECRET_INPUT_FIELDS = {
    ("email", "smtp_password"): "smtp_password_encrypted",
    ("telegram", "bot_token"): "bot_token_encrypted",
    ("slack", "webhook_url"): "webhook_url_encrypted",
}


class AlertSettingsStore:
    def __init__(self, db: Any, collection_name: str = COLLECTION_NAME) -> None:
        self.db = db
        self.collection = db[collection_name]

    def get_document(self) -> dict[str, Any] | None:
        doc = self.collection.find_one({"_id": SETTINGS_ID})
        return dict(doc) if doc else None

    def get_public_settings(self) -> dict[str, Any]:
        doc = self.get_document()
        if doc is None:
            return public_settings_from_config(load_alert_config(), source="environment")
        return to_public_settings(doc, source="mongodb")

    def save_settings(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        existing = self.get_document() or {}
        now = datetime.now(timezone.utc)
        document = merge_settings(existing, payload)
        document["_id"] = SETTINGS_ID
        document["updated_at"] = now
        if "created_at" not in document:
            document["created_at"] = now

        self.collection.replace_one({"_id": SETTINGS_ID}, document, upsert=True)
        return to_public_settings(document, source="mongodb")

    def load_config(self) -> AlertConfig | None:
        doc = self.get_document()
        if not doc:
            return None
        return config_from_document(doc)


def merge_settings(existing: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    document = deepcopy(dict(existing))

    for field in ("alerts_enabled", "dry_run", "channels", "dashboard_url"):
        if field in payload:
            document[field] = payload[field]

    _merge_email(document, _mapping(payload.get("email")))
    _merge_telegram(document, _mapping(payload.get("telegram")))
    _merge_slack(document, _mapping(payload.get("slack")))
    return document


def to_public_settings(document: Mapping[str, Any], *, source: str = "mongodb") -> dict[str, Any]:
    email = _mapping(document.get("email"))
    telegram = _mapping(document.get("telegram"))
    slack = _mapping(document.get("slack"))

    return {
        "source": source,
        "encryption": get_crypto_status().__dict__,
        "alerts_enabled": bool(document.get("alerts_enabled", False)),
        "dry_run": bool(document.get("dry_run", True)),
        "channels": list(document.get("channels") or []),
        "dashboard_url": document.get("dashboard_url"),
        "email": {
            "enabled": bool(email.get("enabled", False)),
            "smtp_host": email.get("smtp_host"),
            "smtp_port": int(email.get("smtp_port") or 587),
            "smtp_username": email.get("smtp_username"),
            "smtp_password_set": bool(email.get("smtp_password_encrypted") or email.get("smtp_password")),
            "smtp_password_mask": mask_secret(bool(email.get("smtp_password_encrypted") or email.get("smtp_password"))),
            "smtp_from": email.get("smtp_from"),
            "smtp_to": email.get("smtp_to"),
            "smtp_use_tls": bool(email.get("smtp_use_tls", True)),
        },
        "telegram": {
            "enabled": bool(telegram.get("enabled", False)),
            "bot_token_set": bool(telegram.get("bot_token_encrypted") or telegram.get("bot_token")),
            "bot_token_mask": mask_secret(bool(telegram.get("bot_token_encrypted") or telegram.get("bot_token"))),
            "chat_id": telegram.get("chat_id"),
        },
        "slack": {
            "enabled": bool(slack.get("enabled", False)),
            "webhook_url_set": bool(slack.get("webhook_url_encrypted") or slack.get("webhook_url")),
            "webhook_url_mask": mask_secret(bool(slack.get("webhook_url_encrypted") or slack.get("webhook_url"))),
        },
        "updated_at": _to_text(document.get("updated_at")),
    }


def public_settings_from_config(config: AlertConfig, *, source: str) -> dict[str, Any]:
    document = {
        "alerts_enabled": config.alerts_enabled,
        "dry_run": config.dry_run,
        "channels": config.channels,
        "dashboard_url": config.dashboard_url,
        "email": {
            "enabled": config.email_enabled,
            "smtp_host": config.smtp_host,
            "smtp_port": config.smtp_port,
            "smtp_username": config.smtp_username,
            "smtp_password": config.smtp_password,
            "smtp_from": config.smtp_from,
            "smtp_to": config.smtp_to,
            "smtp_use_tls": config.smtp_use_tls,
        },
        "telegram": {
            "enabled": config.telegram_enabled,
            "bot_token": config.telegram_bot_token,
            "chat_id": config.telegram_chat_id,
        },
        "slack": {
            "enabled": config.slack_enabled,
            "webhook_url": config.slack_webhook_url,
        },
    }
    return to_public_settings(document, source=source)


def config_from_document(document: Mapping[str, Any]) -> AlertConfig:
    email = _mapping(document.get("email"))
    telegram = _mapping(document.get("telegram"))
    slack = _mapping(document.get("slack"))

    return AlertConfig(
        alerts_enabled=bool(document.get("alerts_enabled", False)),
        dry_run=bool(document.get("dry_run", True)),
        channels=list(document.get("channels") or []),
        dashboard_url=document.get("dashboard_url"),
        email_enabled=bool(email.get("enabled", False)),
        smtp_host=email.get("smtp_host"),
        smtp_port=int(email.get("smtp_port") or 587),
        smtp_username=email.get("smtp_username"),
        smtp_password=decrypt_secret(email.get("smtp_password_encrypted")),
        smtp_from=email.get("smtp_from"),
        smtp_to=email.get("smtp_to"),
        smtp_use_tls=bool(email.get("smtp_use_tls", True)),
        telegram_enabled=bool(telegram.get("enabled", False)),
        telegram_bot_token=decrypt_secret(telegram.get("bot_token_encrypted")),
        telegram_chat_id=telegram.get("chat_id"),
        slack_enabled=bool(slack.get("enabled", False)),
        slack_webhook_url=decrypt_secret(slack.get("webhook_url_encrypted")),
    )


def _merge_email(document: dict[str, Any], payload: Mapping[str, Any]) -> None:
    email = dict(_mapping(document.get("email")))
    for field in ("enabled", "smtp_host", "smtp_port", "smtp_username", "smtp_from", "smtp_to", "smtp_use_tls"):
        if field in payload:
            email[field] = payload[field]
    if payload.get("smtp_password"):
        email["smtp_password_encrypted"] = encrypt_secret(str(payload["smtp_password"]))
    document["email"] = email


def _merge_telegram(document: dict[str, Any], payload: Mapping[str, Any]) -> None:
    telegram = dict(_mapping(document.get("telegram")))
    for field in ("enabled", "chat_id"):
        if field in payload:
            telegram[field] = payload[field]
    if payload.get("bot_token"):
        telegram["bot_token_encrypted"] = encrypt_secret(str(payload["bot_token"]))
    document["telegram"] = telegram


def _merge_slack(document: dict[str, Any], payload: Mapping[str, Any]) -> None:
    slack = dict(_mapping(document.get("slack")))
    if "enabled" in payload:
        slack["enabled"] = payload["enabled"]
    if payload.get("webhook_url"):
        slack["webhook_url_encrypted"] = encrypt_secret(str(payload["webhook_url"]))
    document["slack"] = slack


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _to_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
