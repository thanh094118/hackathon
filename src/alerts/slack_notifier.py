from __future__ import annotations

import json
import urllib.error
import urllib.request

from .base import BaseNotifier
from .config import AlertConfig
from .formatter import format_slack_payload
from .models import AlertEvent, AlertSendResult


class SlackNotifier(BaseNotifier):
    channel = "slack"

    def __init__(self, config: AlertConfig) -> None:
        super().__init__(enabled=config.channel_enabled(self.channel), dry_run=config.dry_run)
        self.config = config

    def send(self, alert: AlertEvent) -> AlertSendResult:
        if not self.enabled:
            return AlertSendResult(self.channel, True, "slack alerts disabled", dry_run=self.dry_run)

        if self.dry_run:
            return AlertSendResult(self.channel, True, "slack alert dry-run", dry_run=True)

        if not self.config.slack_webhook_url:
            return AlertSendResult(
                self.channel,
                False,
                "slack credentials incomplete",
                dry_run=False,
                error="missing:SLACK_WEBHOOK_URL",
            )

        try:
            payload = json.dumps(format_slack_payload(alert)).encode("utf-8")
            request = urllib.request.Request(
                self.config.slack_webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
            return AlertSendResult(self.channel, True, "slack alert sent", dry_run=False)
        except Exception as exc:  # pragma: no cover - exact network failures vary by runtime
            return AlertSendResult(
                self.channel,
                False,
                "slack alert failed",
                dry_run=False,
                error=_format_network_error(exc),
            )


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
        if isinstance(payload, dict) and payload.get("error"):
            return str(payload["error"])[:500]
    except Exception:
        pass
    return text[:500]
