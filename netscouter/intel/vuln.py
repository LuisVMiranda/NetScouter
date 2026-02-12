"""Software normalization and CVE feed lookup utilities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from typing import Any

import requests

_CACHE: dict[str, tuple[datetime, list[dict[str, Any]]]] = {}
CACHE_TTL_SECONDS = 1800
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SOFTWARE_ALIASES = {
    "openssh": "openbsd:openssh",
    "nginx": "nginx:nginx",
    "apache": "apache:http_server",
    "apache-http-server": "apache:http_server",
    "mysql": "oracle:mysql",
    "postgres": "postgresql:postgresql",
    "postgresql": "postgresql:postgresql",
    "vsftpd": "vsftpd:vsftpd",
    "proftpd": "proftpd:proftpd",
}


@dataclass(slots=True)
class NormalizedSoftware:
    vendor: str
    product: str
    version: str
    cpe_hint: str



def normalize_software_version(software: str, version: str) -> NormalizedSoftware:
    normalized_name = re.sub(r"[^a-z0-9.+_-]", "-", software.strip().lower())
    normalized_version = re.sub(r"[^a-z0-9.+_-]", "", version.strip().lower())
    normalized_version = re.sub(r"^[vr_]+", "", normalized_version)

    alias = SOFTWARE_ALIASES.get(normalized_name)
    if alias:
        vendor, product = alias.split(":", maxsplit=1)
    else:
        vendor, product = "unknown", normalized_name or "unknown"

    cpe = f"cpe:2.3:a:{vendor}:{product}:{normalized_version or '*'}:*:*:*:*:*:*:*"
    return NormalizedSoftware(vendor=vendor, product=product, version=normalized_version, cpe_hint=cpe)


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _exploitability_hint(score: float, kev: bool) -> str:
    if kev or score >= 9.0:
        return "Act immediately: internet-exposed exploitation likely."
    if score >= 7.0:
        return "Prioritize patching in next maintenance window."
    if score >= 4.0:
        return "Patch on normal cycle and monitor exploit chatter."
    return "Monitor and patch opportunistically."


def _parse_nvd(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in items:
        cve = item.get("cve", {})
        cve_id = str(cve.get("id", ""))
        description = ""
        for desc in cve.get("descriptions", []):
            if str(desc.get("lang", "")).lower() == "en":
                description = str(desc.get("value", ""))
                break

        metrics = cve.get("metrics", {})
        vectors = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or []
        base_score = 0.0
        if vectors:
            base_score = float(vectors[0].get("cvssData", {}).get("baseScore", 0.0) or 0.0)

        kev = bool(cve.get("cisaExploitAdd"))
        severity = _severity_from_cvss(base_score)
        findings.append(
            {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": base_score,
                "severity": severity,
                "exploitability_hint": _exploitability_hint(base_score, kev),
                "known_exploited": kev,
                "published": str(cve.get("published", "")),
                "last_modified": str(cve.get("lastModified", "")),
                "remediation": "Upgrade to the latest vendor-supported version and restrict network exposure.",
            }
        )
    return findings


def _read_local_feed(path: Path, product: str, version: str) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return []
    matches: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("product", "")).lower() != product.lower():
            continue
        affected = str(entry.get("version", "")).lower()
        if affected and version and affected != version.lower():
            continue
        score = float(entry.get("cvss_score", 0.0) or 0.0)
        sev = str(entry.get("severity", _severity_from_cvss(score))).lower()
        matches.append(
            {
                "cve_id": str(entry.get("cve_id", "")),
                "description": str(entry.get("description", "")),
                "cvss_score": score,
                "severity": sev,
                "exploitability_hint": str(entry.get("exploitability_hint", _exploitability_hint(score, False))),
                "known_exploited": bool(entry.get("known_exploited", False)),
                "published": str(entry.get("published", "")),
                "last_modified": str(entry.get("last_modified", "")),
                "remediation": str(entry.get("remediation", "Upgrade to a non-vulnerable version.")),
            }
        )
    return matches


def lookup_cves(
    software: str,
    version: str,
    *,
    timeout_seconds: float = 5.0,
    max_results: int = 8,
) -> list[dict[str, Any]]:
    normalized = normalize_software_version(software, version)
    cache_key = f"{normalized.vendor}:{normalized.product}:{normalized.version}"
    now = datetime.now(timezone.utc)
    cached = _CACHE.get(cache_key)
    if cached and now - cached[0] < timedelta(seconds=CACHE_TTL_SECONDS):
        return cached[1]

    local_feed = os.getenv("NETSCOUTER_CVE_FEED", "").strip()
    findings: list[dict[str, Any]] = []
    if local_feed:
        findings = _read_local_feed(Path(local_feed), normalized.product, normalized.version)
    else:
        params: dict[str, Any] = {"keywordSearch": normalized.product, "resultsPerPage": max_results}
        if normalized.version:
            params["keywordSearch"] = f"{normalized.product} {normalized.version}"
        response = requests.get(NVD_API_URL, params=params, timeout=timeout_seconds)
        response.raise_for_status()
        findings = _parse_nvd(list(response.json().get("vulnerabilities", [])))

    findings = sorted(findings, key=lambda item: float(item.get("cvss_score", 0.0)), reverse=True)[:max_results]
    _CACHE[cache_key] = (now, findings)
    return findings


def summarize_vuln_badge(vulns: list[dict[str, Any]]) -> str:
    if not vulns:
        return "✅ 0"
    critical = sum(1 for item in vulns if str(item.get("severity", "")).lower() == "critical")
    high = sum(1 for item in vulns if str(item.get("severity", "")).lower() == "high")
    if critical:
        return f"🔥 C{critical}/H{high}"
    if high:
        return f"⚠️ H{high}"
    return f"ℹ️ {len(vulns)}"
