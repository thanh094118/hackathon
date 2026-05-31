from __future__ import annotations

from cryptography.fernet import Fernet

from src.alerts.config import load_effective_alert_config
from src.alerts.settings_store import AlertSettingsStore, config_from_document, merge_settings


def test_alert_settings_encrypts_and_masks_secrets(monkeypatch):
    monkeypatch.setenv("ALERT_SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())

    document = merge_settings(
        {},
        {
            "alerts_enabled": True,
            "dry_run": False,
            "channels": ["email", "telegram", "slack"],
            "email": {
                "enabled": True,
                "smtp_host": "smtp.example.com",
                "smtp_port": 2525,
                "smtp_username": "user",
                "smtp_password": "secret-password",
                "smtp_from": "alerts@example.com",
                "smtp_to": "soc@example.com",
                "smtp_use_tls": True,
            },
            "telegram": {"enabled": True, "bot_token": "telegram-secret", "chat_id": "42"},
            "slack": {"enabled": True, "webhook_url": "https://hooks.slack.test/secret"},
        },
    )

    assert "secret-password" not in str(document)
    assert "telegram-secret" not in str(document)
    assert "hooks.slack.test/secret" not in str(document)

    config = config_from_document(document)
    assert config.alerts_enabled is True
    assert config.dry_run is False
    assert config.smtp_password == "secret-password"
    assert config.telegram_bot_token == "telegram-secret"
    assert config.slack_webhook_url == "https://hooks.slack.test/secret"


def test_store_preserves_existing_secret_when_update_omits_secret(monkeypatch):
    monkeypatch.setenv("ALERT_SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    db = FakeDb()
    store = AlertSettingsStore(db)

    store.save_settings({"email": {"enabled": True, "smtp_password": "first-secret"}})
    first_doc = db["alert_settings"].document
    first_token = first_doc["email"]["smtp_password_encrypted"]

    public = store.save_settings({"email": {"enabled": False, "smtp_host": "smtp2.example.com"}})
    second_doc = db["alert_settings"].document

    assert second_doc["email"]["smtp_password_encrypted"] == first_token
    assert public["email"]["smtp_password_set"] is True
    assert public["email"]["smtp_password_mask"] == "********"
    assert public["email"]["smtp_host"] == "smtp2.example.com"


def test_effective_config_prefers_mongo_settings(monkeypatch):
    monkeypatch.setenv("ALERT_SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    db = FakeDb()
    AlertSettingsStore(db).save_settings(
        {
            "alerts_enabled": True,
            "channels": ["slack"],
            "slack": {"enabled": True, "webhook_url": "https://hooks.slack.test/mongo"},
        }
    )

    config = load_effective_alert_config({"ALERTS_ENABLED": "0"}, db=db)

    assert config.alerts_enabled is True
    assert config.channel_enabled("slack") is True
    assert config.slack_webhook_url == "https://hooks.slack.test/mongo"


def test_missing_encryption_key_refuses_secret_write(monkeypatch):
    monkeypatch.delenv("ALERT_SETTINGS_ENCRYPTION_KEY", raising=False)

    try:
        merge_settings({}, {"slack": {"webhook_url": "https://hooks.slack.test/secret"}})
    except RuntimeError as exc:
        assert "ALERT_SETTINGS_ENCRYPTION_KEY" in str(exc)
    else:
        raise AssertionError("missing encryption key should fail secret write")


def test_public_settings_include_encryption_status(monkeypatch):
    monkeypatch.setenv("ALERT_SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())
    db = FakeDb()
    public = AlertSettingsStore(db).save_settings({"alerts_enabled": True})

    assert public["encryption"]["configured"] is True
    assert public["encryption"]["valid"] is True
    assert "valid" in public["encryption"]["message"]


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
