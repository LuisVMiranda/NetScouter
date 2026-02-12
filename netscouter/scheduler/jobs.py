"""Recurring scan job setup and metadata logging for timeline overlays."""

from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler

_JOB_EVENTS: list[dict[str, Any]] = []
_JOB_EVENTS_LOCK = Lock()


def build_scheduler() -> BackgroundScheduler:
    """Create and return a background scheduler instance."""
    return BackgroundScheduler()


def log_schedule_event(
    *,
    action: str,
    job_id: str,
    scheduled_for: str | None = None,
    source: str = "scheduler",
    scan_id: int | str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Store scheduler event metadata used for timeline causality overlays."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "job_id": job_id,
        "scheduled_for": scheduled_for or "",
        "source": source,
        "scan_id": str(scan_id) if scan_id is not None else "",
        "metadata": dict(metadata or {}),
    }
    with _JOB_EVENTS_LOCK:
        _JOB_EVENTS.append(event)
    return event


def get_schedule_events(*, job_id: str | None = None) -> list[dict[str, Any]]:
    """Return a snapshot of recorded scheduler metadata events."""
    with _JOB_EVENTS_LOCK:
        items = list(_JOB_EVENTS)
    if job_id:
        return [event for event in items if str(event.get("job_id")) == job_id]
    return items
