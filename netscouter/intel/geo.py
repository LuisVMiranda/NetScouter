"""Geo lookup and normalization for IP intelligence."""

from __future__ import annotations

import time
from ipaddress import ip_address
from typing import Any

import requests

from .risk import assess_ip_risk, is_local_or_private_ip

IP_API_ENDPOINT = "http://ip-api.com/json/{ip}"
DEFAULT_TIMEOUT_SECONDS = 5
DEFAULT_CACHE_TTL_SECONDS = 900

_CACHE: dict[str, dict[str, Any]] = {}


def _normalize_result(ip: str, data: dict[str, Any], risk_level: str) -> dict[str, Any]:
    return {
        "ip": ip,
        "country": data.get("country") or "",
        "city": data.get("city") or "",
        "provider": data.get("org") or data.get("isp") or "",
        "risk_level": risk_level,
    }


def _get_cached(ip: str) -> dict[str, Any] | None:
    entry = _CACHE.get(ip)
    if not entry:
        return None
    if entry["expires_at"] <= time.time():
        _CACHE.pop(ip, None)
        return None
    return entry["value"]


def _set_cache(ip: str, value: dict[str, Any], ttl_seconds: int) -> None:
    _CACHE[ip] = {
        "value": value,
        "expires_at": time.time() + ttl_seconds,
    }


def _fetch_geo_metadata(ip: str, timeout_seconds: int) -> dict[str, Any]:
    response = requests.get(
        IP_API_ENDPOINT.format(ip=ip),
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    return response.json()


def get_ip_intel(
    ip: str,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    cache_ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    high_risk_regions: set[str] | None = None,
    additional_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return normalized intel for an IP address."""
    parsed_ip = ip_address(ip)
    normalized_ip = str(parsed_ip)

    cached = _get_cached(normalized_ip)
    if cached is not None:
        return cached

    if is_local_or_private_ip(normalized_ip):
        local_data = {
            "country": "Local",
            "city": "Local Network",
            "isp": "Local",
            "org": "Local",
            "countryCode": "",
        }
        risk_level = assess_ip_risk(
            normalized_ip,
            local_data,
            high_risk_regions=high_risk_regions,
            additional_context=additional_context,
        )
        result = _normalize_result(normalized_ip, local_data, risk_level)
        _set_cache(normalized_ip, result, cache_ttl_seconds)
        return result

    metadata = _fetch_geo_metadata(normalized_ip, timeout_seconds)
    risk_level = assess_ip_risk(
        normalized_ip,
        metadata,
        high_risk_regions=high_risk_regions,
        additional_context=additional_context,
    )
    result = _normalize_result(normalized_ip, metadata, risk_level)
    _set_cache(normalized_ip, result, cache_ttl_seconds)
    return result


def clear_geo_cache() -> None:
    """Clear the in-memory geo intelligence cache."""
    _CACHE.clear()
