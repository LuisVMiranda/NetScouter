"""IoT-focused outbound anomaly heuristics."""

from __future__ import annotations

from typing import Any

UNEXPECTED_PROVIDER_KEYWORDS = (
    "vpn",
    "proxy",
    "hosting",
    "cloud",
    "datacenter",
)

HIGH_RISK_COUNTRIES = {"RU", "KP", "IR", "SY"}


def evaluate_iot_anomaly(
    *,
    device: dict[str, Any],
    flow: Any,
    remote_intel: dict[str, Any],
) -> dict[str, str] | None:
    """Return anomaly metadata for suspicious IoT outbound traffic, else ``None``."""
    device_type = str(device.get("device_type", "")).lower()
    if device_type != "iot":
        return None

    country = str(remote_intel.get("country") or "Unknown")
    country_code = str(remote_intel.get("countryCode") or "").upper()
    provider = str(remote_intel.get("provider") or remote_intel.get("org") or "Unknown")

    allowed_countries = {str(item) for item in device.get("allowed_countries", []) if str(item)}
    allowed_providers = {str(item).lower() for item in device.get("allowed_providers", []) if str(item)}

    if country_code and country_code in HIGH_RISK_COUNTRIES:
        return {"risk": "high", "reason": f"IoT device reached high-risk country: {country}"}

    if allowed_countries and country not in allowed_countries and country != "Local":
        return {"risk": "high", "reason": f"IoT device reached unexpected country: {country}"}

    lowered_provider = provider.lower()
    if any(keyword in lowered_provider for keyword in UNEXPECTED_PROVIDER_KEYWORDS):
        return {"risk": "high", "reason": f"IoT device reached hosting/vpn provider: {provider}"}

    if allowed_providers and lowered_provider and lowered_provider not in allowed_providers:
        return {"risk": "average", "reason": f"IoT device reached new provider: {provider}"}

    remote_port = int(getattr(flow, "remote_port", 0) or 0)
    if remote_port in {23, 2323, 4444, 5555}:
        return {"risk": "high", "reason": f"IoT device opened suspicious remote port {remote_port}"}

    return None
