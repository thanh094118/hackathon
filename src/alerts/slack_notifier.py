from __future__ import annotations

import json
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
                error=exc.__class__.__name__,
            )
