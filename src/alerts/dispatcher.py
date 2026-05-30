from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from .base import BaseNotifier
from .config import AlertConfig, load_alert_config
from .email_notifier import EmailNotifier
from .models import AlertEvent, AlertSendResult
from .slack_notifier import SlackNotifier
from .telegram_notifier import TelegramNotifier


class AlertDispatcher:
    def __init__(self, config: AlertConfig, notifiers: Iterable[BaseNotifier] | None = None) -> None:
        self.config = config
        self.notifiers = list(notifiers or [])

    def send(self, alert: AlertEvent) -> list[AlertSendResult]:
        if not self.config.alerts_enabled:
            return []

        if self.config.dashboard_url and not alert.dashboard_url:
            alert = replace(alert, dashboard_url=self.config.dashboard_url)

        results: list[AlertSendResult] = []
        for notifier in self.notifiers:
            if not notifier.enabled:
                continue
            try:
                results.append(notifier.send(alert))
            except Exception as exc:
                results.append(
                    AlertSendResult(
                        channel=getattr(notifier, "channel", "unknown"),
                        success=False,
                        message="alert notifier failed",
                        dry_run=getattr(notifier, "dry_run", self.config.dry_run),
                        error=exc.__class__.__name__,
                    )
                )
        return results


def build_default_dispatcher(config: AlertConfig | None = None) -> AlertDispatcher:
    resolved = config or load_alert_config()
    return AlertDispatcher(
        resolved,
        notifiers=[
            EmailNotifier(resolved),
            TelegramNotifier(resolved),
            SlackNotifier(resolved),
        ],
    )
