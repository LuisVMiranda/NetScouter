"""Reputation lookups and consensus policy for remote IP addresses."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError, as_completed
import json
import os
from typing import Any, Callable

import requests

ProviderResult = dict[str, bool | float | str]

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

DEFAULT_TIMEOUT_SECONDS = 4.0
DEFAULT_THRESHOLD = 3


def _format_excerpt(data: Any, *, limit: int = 240) -> str:
    try:
        excerpt = json.dumps(data, sort_keys=True)
    except TypeError:
        excerpt = str(data)
    return excerpt[:limit]


def _error_result(reason: str) -> ProviderResult:
    return {
        "flagged": False,
        "confidence": 0.0,
        "reason": reason,
        "raw_excerpt": "",
    }


def _abuseipdb_lookup(ip: str, api_key: str, timeout_seconds: float) -> ProviderResult:
    response = requests.get(
        ABUSEIPDB_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    data = response.json().get("data", {})
    score = float(data.get("abuseConfidenceScore", 0.0))
    reports = int(data.get("totalReports", 0))
    flagged = score >= 60.0 or reports >= 3
    return {
        "flagged": flagged,
        "confidence": min(1.0, max(0.0, score / 100.0)),
        "reason": f"abuse_score={score:.0f}, reports={reports}",
        "raw_excerpt": _format_excerpt(
            {
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "totalReports": data.get("totalReports"),
                "countryCode": data.get("countryCode"),
            }
        ),
    }


def _virustotal_lookup(ip: str, api_key: str, timeout_seconds: float) -> ProviderResult:
    response = requests.get(
        VIRUSTOTAL_URL.format(ip=ip),
        headers={"x-apikey": api_key},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    total = max(1, malicious + suspicious + harmless + int(stats.get("undetected", 0)))
    verdict_hits = malicious + suspicious
    confidence = min(1.0, verdict_hits / total)
    flagged = malicious > 0 or suspicious >= 2
    return {
        "flagged": flagged,
        "confidence": confidence,
        "reason": f"malicious={malicious}, suspicious={suspicious}, total={total}",
        "raw_excerpt": _format_excerpt(stats),
    }


def _otx_lookup(ip: str, api_key: str, timeout_seconds: float) -> ProviderResult:
    response = requests.get(
        OTX_URL.format(ip=ip),
        headers={"X-OTX-API-KEY": api_key},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    data = response.json()
    pulse_info = data.get("pulse_info", {})
    count = int(pulse_info.get("count", 0))
    pulses = pulse_info.get("pulses", []) or []
    confidence = min(1.0, count / 10.0)
    flagged = count > 0
    top_pulse = ""
    if pulses:
        top_pulse = str((pulses[0] or {}).get("name", ""))
    return {
        "flagged": flagged,
        "confidence": confidence,
        "reason": f"pulses={count}" + (f", top={top_pulse}" if top_pulse else ""),
        "raw_excerpt": _format_excerpt({"count": count, "top_pulse": top_pulse}),
    }


def _safe_provider_lookup(
    provider_name: str,
    ip: str,
    lookup: Callable[[str, str, float], ProviderResult],
    api_key: str | None,
    timeout_seconds: float,
) -> tuple[str, ProviderResult]:
    if not api_key:
        return provider_name, _error_result("missing API key")
    try:
        return provider_name, lookup(ip, api_key, timeout_seconds)
    except requests.Timeout:
        return provider_name, _error_result("timeout")
    except Exception as exc:  # noqa: BLE001
        return provider_name, _error_result(f"error: {exc}")


def evaluate_reputation_consensus(
    ip: str,
    *,
    threshold: int = DEFAULT_THRESHOLD,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    api_keys: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Query providers in parallel and return normalized consensus disposition."""
    configured_keys = {
        "abuseipdb": (api_keys or {}).get("abuseipdb") or os.getenv("ABUSEIPDB_API_KEY", ""),
        "virustotal": (api_keys or {}).get("virustotal")
        or os.getenv("VIRUSTOTAL_API_KEY", "")
        or os.getenv("VT_API_KEY", ""),
        "otx": (api_keys or {}).get("otx") or os.getenv("OTX_API_KEY", ""),
    }
    provider_functions: dict[str, Callable[[str, str, float], ProviderResult]] = {
        "abuseipdb": _abuseipdb_lookup,
        "virustotal": _virustotal_lookup,
        "otx": _otx_lookup,
    }

    results: dict[str, ProviderResult] = {}
    with ThreadPoolExecutor(max_workers=len(provider_functions), thread_name_prefix="reputation") as executor:
        futures = [
            executor.submit(
                _safe_provider_lookup,
                provider_name,
                ip,
                provider_functions[provider_name],
                configured_keys.get(provider_name),
                timeout_seconds,
            )
            for provider_name in provider_functions
        ]

        try:
            for future in as_completed(futures, timeout=(timeout_seconds * len(futures)) + 2):
                provider_name, result = future.result()
                results[provider_name] = result
        except TimeoutError:
            pass

    for provider_name in provider_functions:
        if provider_name not in results:
            results[provider_name] = _error_result("timeout")

    callable_provider_count = sum(1 for value in configured_keys.values() if bool(value))
    flagged_count = sum(1 for value in results.values() if bool(value["flagged"]))
    confidence_values = [float(value["confidence"]) for value in results.values()]
    consensus_confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
    effective_threshold = max(1, threshold)
    should_block = callable_provider_count > 0 and flagged_count >= effective_threshold
    disposition = "block" if should_block else "allow"

    return {
        "ip": ip,
        "providers": results,
        "flagged_count": flagged_count,
        "provider_count": len(results),
        "configured_provider_count": callable_provider_count,
        "threshold": effective_threshold,
        "consensus_score": f"{flagged_count}/{len(results)}",
        "consensus_confidence": round(consensus_confidence, 3),
        "disposition": disposition,
        "should_block": should_block,
    }
