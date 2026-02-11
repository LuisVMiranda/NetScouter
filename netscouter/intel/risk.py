"""Risk scoring helpers for IP intelligence."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

DEFAULT_HIGH_RISK_REGIONS = {
    "KP",  # North Korea
    "IR",  # Iran
    "SY",  # Syria
    "RU",  # Russia
}

CLOUD_PROVIDER_KEYWORDS = (
    "aws",
    "amazon",
    "google",
    "gcp",
    "azure",
    "microsoft",
)

HOSTING_INDICATORS = (
    "datacenter",
    "hosting",
    "colo",
    "colocation",
    "vps",
    "cloud",
)


LOCAL_RISK = "low"
AVERAGE_RISK = "average"
HIGH_RISK = "high"


def is_local_or_private_ip(ip: str) -> bool:
    """Return True when an address is localhost or private/LAN."""
    parsed = ip_address(ip)
    return (
        parsed.is_loopback
        or parsed.is_private
        or parsed.is_link_local
        or parsed.is_reserved
    )


def evaluate_additional_signals(ip: str, context: dict[str, Any] | None = None) -> str | None:
    """Hook for future AI or reputation features.

    Return one of ``{"low", "average", "high"}`` to override calculated risk,
    or ``None`` to keep the built-in heuristic result.
    """
    _ = (ip, context)
    return None


def _contains_any_keyword(value: str, keywords: tuple[str, ...]) -> bool:
    lowered = value.lower()
    return any(keyword in lowered for keyword in keywords)


def assess_ip_risk(
    ip: str,
    metadata: dict[str, Any] | None = None,
    *,
    high_risk_regions: set[str] | None = None,
    additional_context: dict[str, Any] | None = None,
) -> str:
    """Return a normalized risk label (low/average/high)."""
    if is_local_or_private_ip(ip):
        return LOCAL_RISK

    data = metadata or {}
    provider_blob = " ".join(
        str(data.get(field, "")) for field in ("isp", "org", "as", "asname")
    ).strip()
    country_code = str(data.get("countryCode", "")).upper()

    if country_code and country_code in (high_risk_regions or DEFAULT_HIGH_RISK_REGIONS):
        base_risk = HIGH_RISK
    elif bool(data.get("hosting")) or _contains_any_keyword(provider_blob, HOSTING_INDICATORS):
        base_risk = HIGH_RISK
    elif _contains_any_keyword(provider_blob, CLOUD_PROVIDER_KEYWORDS):
        base_risk = AVERAGE_RISK
    elif data.get("status") == "success" and not data.get("proxy") and not data.get("hosting"):
        base_risk = AVERAGE_RISK
    else:
        base_risk = AVERAGE_RISK

    hook_result = evaluate_additional_signals(
        ip,
        {
            "metadata": data,
            "base_risk": base_risk,
            **(additional_context or {}),
        },
    )
    if hook_result in {LOCAL_RISK, AVERAGE_RISK, HIGH_RISK}:
        return hook_result
    return base_risk
