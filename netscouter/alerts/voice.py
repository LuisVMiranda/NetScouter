"""Voice alert service with pluggable text-to-speech backends."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Protocol


class AlertSeverity(IntEnum):
    """Severity scale for threat alerts."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50


class TTSBackend(Protocol):
    """Pluggable backend interface."""

    def speak(self, text: str) -> None:
        """Convert text to voice output."""


class NullTTSBackend:
    """No-op backend used when voice output is disabled."""

    def speak(self, text: str) -> None:
        _ = text


@dataclass(slots=True)
class VoiceAlertService:
    """Routes alert messages to a configured backend when threshold is met."""

    backend: TTSBackend
    threshold: AlertSeverity = AlertSeverity.HIGH
    enabled: bool = True

    def should_announce(self, severity: AlertSeverity) -> bool:
        return self.enabled and severity >= self.threshold

    def announce(self, message: str, severity: AlertSeverity) -> bool:
        if not self.should_announce(severity):
            return False
        self.backend.speak(message)
        return True
