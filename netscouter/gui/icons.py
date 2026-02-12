"""Helpers for optional Windows icon detection with text fallback labels."""

from __future__ import annotations

import ctypes
import os
import platform


def _has_windows_icon(exe_path: str) -> bool:
    if platform.system().lower() != "windows":
        return False

    try:
        extract_icon = ctypes.windll.shell32.ExtractIconW
        destroy_icon = ctypes.windll.user32.DestroyIcon
        handle = extract_icon(0, exe_path, 0)
        if not handle:
            return False
        destroy_icon(handle)
        return True
    except Exception:  # noqa: BLE001
        return False


def get_process_identity_label(process_name: str | None, exe_path: str | None) -> str:
    """Return a compact, icon-like label for process identity columns."""
    normalized_name = (process_name or "Unknown").strip() or "Unknown"
    normalized_path = (exe_path or "").strip()

    if normalized_path and os.path.exists(normalized_path) and _has_windows_icon(normalized_path):
        return f"🧩 {normalized_name}"

    return f"📄 {normalized_name}"
