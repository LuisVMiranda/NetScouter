"""Persistence helpers for user preferences and prompt templates."""

from .preferences import (
    get_preference,
    list_scan_history,
    record_scan_history,
    set_preference,
)

__all__ = ["get_preference", "set_preference", "record_scan_history", "list_scan_history"]
