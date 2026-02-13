"""SQLite-backed preference and history storage for NetScouter."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

DB_PATH = Path.home() / ".netscouter" / "netscouter.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS preferences (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    return conn


def set_preference(key: str, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False)
    stamp = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO preferences(key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (key, payload, stamp),
        )


def get_preference(key: str, default: Any = None) -> Any:
    with _connect() as conn:
        row = conn.execute("SELECT value FROM preferences WHERE key = ?", (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(str(row[0]))
    except json.JSONDecodeError:
        return default


def record_scan_history(scan_type: str, summary: dict[str, Any]) -> None:
    stamp = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scan_history(scan_type, summary, created_at) VALUES (?, ?, ?)",
            (scan_type, json.dumps(summary, ensure_ascii=False), stamp),
        )


def list_scan_history(limit: int = 25) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT scan_type, summary, created_at FROM scan_history ORDER BY id DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
    history: list[dict[str, Any]] = []
    for scan_type, summary, created_at in rows:
        try:
            decoded = json.loads(str(summary))
        except json.JSONDecodeError:
            decoded = {"raw": str(summary)}
        history.append({"scan_type": scan_type, "summary": decoded, "created_at": created_at})
    return history


def record_threat_event(event: dict[str, Any]) -> None:
    stamp = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO threat_events(event_json, created_at) VALUES (?, ?)",
            (json.dumps(event, ensure_ascii=False), stamp),
        )


def list_threat_events(limit: int = 500) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT event_json, created_at FROM threat_events ORDER BY id DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
    events: list[dict[str, Any]] = []
    for payload, created_at in reversed(rows):
        try:
            decoded = json.loads(str(payload))
            if isinstance(decoded, dict):
                decoded.setdefault("timestamp", decoded.get("timestamp") or created_at)
                events.append(decoded)
        except json.JSONDecodeError:
            events.append({"timestamp": created_at, "ip": "", "action": "unknown", "status": "failed", "reason": str(payload)})
    return events
