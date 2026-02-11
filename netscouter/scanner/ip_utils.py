"""IP helpers for scan safety and classification."""

from __future__ import annotations

import ipaddress


def to_ip_address(value: str) -> ipaddress._BaseAddress | None:
    """Convert a host value to an ``ipaddress`` object when possible."""
    if not value:
        return None

    host = value.strip().lower()
    if host == "localhost":
        return ipaddress.ip_address("127.0.0.1")

    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def is_loopback_or_localhost(value: str) -> bool:
    """Return ``True`` when ``value`` points to loopback localhost space."""
    ip_obj = to_ip_address(value)
    return bool(ip_obj and ip_obj.is_loopback)


def is_private_lan(value: str) -> bool:
    """Return ``True`` when ``value`` is a private RFC1918/ULA style address."""
    ip_obj = to_ip_address(value)
    return bool(ip_obj and ip_obj.is_private)


def is_local_or_private(value: str) -> bool:
    """Return ``True`` for loopback/localhost and private LAN addresses."""
    return is_loopback_or_localhost(value) or is_private_lan(value)
