from __future__ import annotations

import json
import urllib.parse
import urllib.error
import urllib.request

from .base import BaseNotifier
from .config import AlertConfig
from .formatter import format_alert_text
from .models import AlertEvent, AlertSendResult


class TelegramNotifier(BaseNotifier):
    channel = "telegram"

    def __init__(self, config: AlertConfig) -> None:
        super().__init__(enabled=config.channel_enabled(self.channel), dry_run=config.dry_run)
        self.config = config

    def send(self, alert: AlertEvent) -> AlertSendResult:
        if not self.enabled:
            return AlertSendResult(self.channel, True, "telegram alerts disabled", dry_run=self.dry_run)

        if self.dry_run:
            return AlertSendResult(self.channel, True, "telegram alert dry-run", dry_run=True)

        missing = self._missing_fields()
        if missing:
            return AlertSendResult(
                self.channel,
                False,
                "telegram credentials incomplete",
                dry_run=False,
                error="missing:" + ",".join(missing),
            )

        try:
            url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
            data = urllib.parse.urlencode(
                {"chat_id": self.config.telegram_chat_id, "text": format_alert_text(alert)}
            ).encode("utf-8")
            request = urllib.request.Request(url, data=data, method="POST")
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
            return AlertSendResult(self.channel, True, "telegram alert sent", dry_run=False)
        except Exception as exc:  # pragma: no cover - exact network failures vary by runtime
            return AlertSendResult(
                self.channel,
                False,
                "telegram alert failed",
                dry_run=False,
                error=_format_network_error(exc),
            )

    def _missing_fields(self) -> list[str]:
        required = {
            "TELEGRAM_BOT_TOKEN": self.config.telegram_bot_token,
            "TELEGRAM_CHAT_ID": self.config.telegram_chat_id,
        }
        return [name for name, value in required.items() if not value]


def _format_network_error(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        detail = _read_error_body(exc)
        if detail:
            return f"HTTP {exc.code}: {detail}"
        return f"HTTP {exc.code}: {exc.reason}"
    if isinstance(exc, urllib.error.URLError):
        return f"URL error: {exc.reason}"
    text = str(exc).strip()
    if text:
        return f"{exc.__class__.__name__}: {text}"
    return exc.__class__.__name__


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read()
    except Exception:
        return ""
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace").strip()
    try:
        payload = json.loads(text)
        if isinstance(payload, dict) and payload.get("description"):
            return str(payload["description"])[:500]
    except Exception:
        pass
    return text[:500]
