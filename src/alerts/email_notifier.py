from __future__ import annotations

import smtplib
from email.message import EmailMessage

from .base import BaseNotifier
from .config import AlertConfig
from .formatter import format_email_body, format_email_subject
from .models import AlertEvent, AlertSendResult


class EmailNotifier(BaseNotifier):
    channel = "email"

    def __init__(self, config: AlertConfig) -> None:
        super().__init__(enabled=config.channel_enabled(self.channel), dry_run=config.dry_run)
        self.config = config

    def send(self, alert: AlertEvent) -> AlertSendResult:
        if not self.enabled:
            return AlertSendResult(self.channel, True, "email alerts disabled", dry_run=self.dry_run)

        if self.dry_run:
            return AlertSendResult(self.channel, True, "email alert dry-run", dry_run=True)

        missing = self._missing_fields()
        if missing:
            return AlertSendResult(
                self.channel,
                False,
                "email credentials incomplete",
                dry_run=False,
                error="missing:" + ",".join(missing),
            )

        try:
            message = EmailMessage()
            message["Subject"] = format_email_subject(alert)
            message["From"] = self.config.smtp_from or ""
            message["To"] = self.config.smtp_to or ""
            message.set_content(format_email_body(alert))

            with smtplib.SMTP(self.config.smtp_host or "", self.config.smtp_port, timeout=10) as smtp:
                if self.config.smtp_use_tls:
                    smtp.starttls()
                if self.config.smtp_username and self.config.smtp_password:
                    smtp.login(self.config.smtp_username, self.config.smtp_password)
                smtp.send_message(message)

            return AlertSendResult(self.channel, True, "email alert sent", dry_run=False)
        except Exception as exc:  # pragma: no cover - exact smtplib failures vary by runtime
            return AlertSendResult(
                self.channel,
                False,
                "email alert failed",
                dry_run=False,
                error=exc.__class__.__name__,
            )

    def _missing_fields(self) -> list[str]:
        required = {
            "SMTP_HOST": self.config.smtp_host,
            "SMTP_FROM": self.config.smtp_from,
            "SMTP_TO": self.config.smtp_to,
        }
        return [name for name, value in required.items() if not value]
