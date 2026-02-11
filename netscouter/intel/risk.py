"""Geo-lookup and risk scoring stubs."""

from __future__ import annotations


def score_ip_risk(country_code: str, open_ports: int) -> int:
    """Return a simple heuristic risk score from 0-100."""
    base = 20 if country_code.upper() not in {"US", "CA", "GB", "AU"} else 5
    port_factor = min(open_ports * 3, 75)
    return min(base + port_factor, 100)
