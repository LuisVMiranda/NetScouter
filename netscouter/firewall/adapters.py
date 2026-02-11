"""Platform firewall adapter selection."""

from __future__ import annotations

import platform


def get_platform_adapter() -> str:
    """Return the firewall adapter key for the active OS."""
    system = platform.system().lower()
    if "windows" in system:
        return "windows"
    if "linux" in system:
        return "linux"
    if "darwin" in system:
        return "macos"
    return "unknown"
