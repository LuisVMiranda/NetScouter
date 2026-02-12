"""Remote action channel for mobile response workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
from typing import Callable


@dataclass(slots=True)
class RemoteCommand:
    action: str
    ip: str
    sender: str
    timestamp: datetime
    nonce: str
    signature: str


@dataclass(slots=True)
class CommandAuthPolicy:
    """Shared-secret auth policy with allowlist and replay protection."""

    shared_secret: str
    allowlist: set[str] = field(default_factory=set)
    replay_window_seconds: int = 90
    _seen_nonces: dict[str, datetime] = field(default_factory=dict)

    def _build_payload(self, command: RemoteCommand) -> str:
        ts = command.timestamp.astimezone(timezone.utc).isoformat()
        return f"{command.sender}|{command.action}|{command.ip}|{ts}|{command.nonce}"

    def _expected_signature(self, command: RemoteCommand) -> str:
        payload = self._build_payload(command).encode("utf-8")
        return hmac.new(self.shared_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    def _prune_nonce_cache(self, now: datetime) -> None:
        deadline = now - timedelta(seconds=self.replay_window_seconds)
        stale_keys = [nonce for nonce, seen_at in self._seen_nonces.items() if seen_at < deadline]
        for nonce in stale_keys:
            self._seen_nonces.pop(nonce, None)

    def validate(self, command: RemoteCommand, now: datetime | None = None) -> tuple[bool, str]:
        now = now or datetime.now(timezone.utc)
        self._prune_nonce_cache(now)

        if self.allowlist and command.sender not in self.allowlist:
            return False, "sender_not_allowed"

        delta = abs((now - command.timestamp.astimezone(timezone.utc)).total_seconds())
        if delta > self.replay_window_seconds:
            return False, "timestamp_outside_window"

        if command.nonce in self._seen_nonces:
            return False, "replay_detected"

        expected = self._expected_signature(command)
        if not hmac.compare_digest(expected, command.signature):
            return False, "invalid_signature"

        self._seen_nonces[command.nonce] = now
        return True, "ok"


@dataclass(slots=True)
class RemoteActionChannel:
    """Accepts mobile-origin actions such as /BLOCK and dispatches handlers."""

    auth_policy: CommandAuthPolicy
    handlers: dict[str, Callable[[str], None]]

    def handle(self, command: RemoteCommand) -> tuple[bool, str]:
        allowed, reason = self.auth_policy.validate(command)
        if not allowed:
            return False, reason

        action = command.action.strip().upper()
        if action not in self.handlers:
            return False, "unknown_action"

        self.handlers[action](command.ip)
        return True, "executed"


class TelegramCommandAdapter:
    """Parses Telegram messages into signed remote commands."""

    @staticmethod
    def build_signature(secret: str, sender: str, action: str, ip: str, timestamp: datetime, nonce: str) -> str:
        payload = f"{sender}|{action}|{ip}|{timestamp.astimezone(timezone.utc).isoformat()}|{nonce}".encode("utf-8")
        return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    @staticmethod
    def parse_text(message_text: str, sender: str, signature: str, timestamp: datetime | None = None, nonce: str | None = None) -> RemoteCommand:
        timestamp = timestamp or datetime.now(timezone.utc)
        nonce = nonce or secrets.token_hex(8)
        parts = message_text.strip().split(maxsplit=1)
        action = parts[0].lstrip("/").upper()
        ip = parts[1] if len(parts) > 1 else ""
        return RemoteCommand(action=action, ip=ip, sender=sender, timestamp=timestamp, nonce=nonce, signature=signature)
