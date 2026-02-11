"""Threaded TCP scanning primitives."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ScanTarget:
    host: str
    port: int


def parse_connection(raw: str) -> ScanTarget:
    """Parse a `host:port` connection descriptor."""
    host, port = raw.rsplit(":", 1)
    return ScanTarget(host=host, port=int(port))
