"""Recurring scan job setup using APScheduler."""

from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler


def build_scheduler() -> BackgroundScheduler:
    """Create and return a background scheduler instance."""
    return BackgroundScheduler()
