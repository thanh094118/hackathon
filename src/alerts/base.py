from __future__ import annotations

from abc import ABC, abstractmethod

from .models import AlertEvent, AlertSendResult


class BaseNotifier(ABC):
    channel: str = "unknown"

    def __init__(self, *, enabled: bool = True, dry_run: bool = False) -> None:
        self.enabled = enabled
        self.dry_run = dry_run

    @abstractmethod
    def send(self, alert: AlertEvent) -> AlertSendResult:
        raise NotImplementedError
