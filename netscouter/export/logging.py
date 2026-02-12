"""Persistent logging utilities for scan exports."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import threading
from typing import Any, Iterator

_APPEND_LOCK = threading.Lock()


@contextmanager
def _advisory_file_lock(path: Path) -> Iterator[None]:
    """Apply a best-effort cross-platform advisory lock for a file path."""
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    with lock_path.open("a+", encoding="utf-8") as lock_file:
        try:
            import fcntl  # type: ignore

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            yield
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            return
        except ModuleNotFoundError:
            pass

        try:
            import msvcrt  # type: ignore

            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
            yield
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            return
        except ModuleNotFoundError:
            pass

        # Fallback: process-level lock only.
        yield


def _with_timestamp(record: dict[str, Any]) -> dict[str, Any]:
    payload = dict(record)
    payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    return payload


def append_scan_result(
    record: dict[str, Any],
    path: str | Path = "sentinel_master_log.json",
    *,
    as_json_lines: bool = True,
) -> Path:
    """Append a scan result to the master JSON log.

    When ``as_json_lines`` is ``True`` this appends one object per line.
    Otherwise, it maintains a JSON array in the target file using advisory locking.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = _with_timestamp(record)

    with _APPEND_LOCK, _advisory_file_lock(target):
        if as_json_lines:
            with target.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
            return target

        current: list[dict[str, Any]] = []
        if target.exists() and target.stat().st_size > 0:
            with target.open("r", encoding="utf-8") as handle:
                existing = json.load(handle)
                if isinstance(existing, list):
                    current = [entry for entry in existing if isinstance(entry, dict)]

        current.append(payload)
        with target.open("w", encoding="utf-8") as handle:
            json.dump(current, handle, indent=2, ensure_ascii=False)

    return target


def append_quarantine_interaction(
    record: dict[str, Any],
    path: str | Path = "quarantine_interactions.jsonl",
) -> Path:
    """Append quarantine interaction metadata as JSON lines."""
    payload = dict(record)
    payload.setdefault("kind", "quarantine_interaction")
    return append_scan_result(payload, path=path, as_json_lines=True)
