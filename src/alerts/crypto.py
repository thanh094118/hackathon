from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:  # pragma: no cover - dependency guard
    Fernet = None  # type: ignore[assignment]
    InvalidToken = Exception  # type: ignore[assignment]


class AlertSettingsCryptoError(RuntimeError):
    """Raised when alert credential encryption is unavailable or invalid."""


@dataclass(frozen=True)
class AlertSettingsCryptoStatus:
    configured: bool
    valid: bool
    message: str


def _get_key() -> bytes:
    key = os.getenv("ALERT_SETTINGS_ENCRYPTION_KEY", "").strip()
    if not key:
        raise AlertSettingsCryptoError("ALERT_SETTINGS_ENCRYPTION_KEY is not set")
    return key.encode("utf-8")


def get_crypto_status() -> AlertSettingsCryptoStatus:
    key = os.getenv("ALERT_SETTINGS_ENCRYPTION_KEY", "").strip()
    if not key:
        return AlertSettingsCryptoStatus(
            configured=False,
            valid=False,
            message="ALERT_SETTINGS_ENCRYPTION_KEY is not set",
        )
    if Fernet is None:
        return AlertSettingsCryptoStatus(
            configured=True,
            valid=False,
            message="cryptography is required for encrypted alert settings",
        )
    try:
        Fernet(key.encode("utf-8"))
    except Exception:
        return AlertSettingsCryptoStatus(
            configured=True,
            valid=False,
            message="ALERT_SETTINGS_ENCRYPTION_KEY is invalid; generate a Fernet key with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"",
        )
    return AlertSettingsCryptoStatus(
        configured=True,
        valid=True,
        message="ALERT_SETTINGS_ENCRYPTION_KEY is valid",
    )


def _fernet() -> "Fernet":
    if Fernet is None:
        raise AlertSettingsCryptoError("cryptography is required for encrypted alert settings")
    try:
        return Fernet(_get_key())
    except Exception as exc:
        raise AlertSettingsCryptoError("ALERT_SETTINGS_ENCRYPTION_KEY is invalid") from exc


def encrypt_secret(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    if text == "":
        return None
    return _fernet().encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise AlertSettingsCryptoError("encrypted alert credential cannot be decrypted") from exc


def mask_secret(is_set: bool) -> str:
    return "********" if is_set else ""
