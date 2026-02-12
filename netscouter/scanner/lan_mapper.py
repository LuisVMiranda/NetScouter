"""LAN device discovery, in-memory registry, and outbound IoT flow correlation."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import platform
import re
import socket
import subprocess
from typing import Any

import psutil

from netscouter.intel.geo import get_ip_intel
from netscouter.intel.iot_risk import evaluate_iot_anomaly
from netscouter.intel.risk import is_local_or_private_ip

IOT_KEYWORDS = (
    "camera",
    "thermostat",
    "tv",
    "speaker",
    "roku",
    "chromecast",
    "ring",
    "alexa",
    "iot",
    "printer",
    "sensor",
)

VENDOR_BY_OUI = {
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "44:65:0D": "Amazon Technologies",
    "FC:A1:83": "Google",
    "00:17:88": "Philips Lighting",
    "00:1A:11": "Google Nest",
    "A4:77:33": "LG Electronics",
    "3C:5A:B4": "Google",
    "00:1D:A5": "Samsung Electronics",
}


@dataclass(slots=True)
class OutboundFlow:
    """Correlated outbound flow from a local device to a remote destination."""

    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str
    process_name: str


class DeviceRegistry:
    """In-memory registry keyed by MAC and/or IP with tracking timestamps."""

    def __init__(self) -> None:
        self._devices: dict[str, dict[str, Any]] = {}

    @property
    def devices(self) -> list[dict[str, Any]]:
        return sorted(self._devices.values(), key=lambda item: str(item.get("ip", "")))

    def upsert(
        self,
        *,
        ip: str,
        mac: str,
        hostname: str,
        vendor: str,
        device_type: str,
        seen_at: datetime | None = None,
    ) -> dict[str, Any]:
        timestamp = (seen_at or datetime.now(timezone.utc)).isoformat()
        normalized_ip = str(ip).strip()
        normalized_mac = normalize_mac(mac)
        key = normalized_mac or normalized_ip

        existing = self._devices.get(key)
        if existing:
            existing["last_seen"] = timestamp
            existing["ip"] = normalized_ip or str(existing.get("ip", ""))
            if normalized_mac:
                existing["mac"] = normalized_mac
            if hostname:
                existing["hostname"] = hostname
            if vendor:
                existing["vendor"] = vendor
            if device_type:
                existing["device_type"] = device_type
            return existing

        record = {
            "ip": normalized_ip,
            "mac": normalized_mac,
            "hostname": hostname or "Unknown",
            "vendor": vendor or "Unknown",
            "device_type": device_type or "unknown",
            "first_seen": timestamp,
            "last_seen": timestamp,
            "allowed_countries": ["Local"],
            "allowed_providers": [],
        }
        self._devices[key] = record
        return record


def normalize_mac(value: str | None) -> str:
    if not value:
        return ""
    compact = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(compact) != 12:
        return value.upper().strip()
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).upper()


def _default_subnet() -> ipaddress.IPv4Network | None:
    for interface_addrs in psutil.net_if_addrs().values():
        for addr in interface_addrs:
            if getattr(addr, "family", None) != socket.AF_INET:
                continue
            if not addr.address or not addr.netmask:
                continue
            ip = ipaddress.ip_address(addr.address)
            if ip.is_loopback or ip.is_link_local:
                continue
            try:
                return ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            except ValueError:
                continue
    return None


def _ping_host(ip: str, timeout_seconds: float = 0.25) -> bool:
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_seconds * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_seconds))), ip]

    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    return proc.returncode == 0


def _parse_arp_lines(lines: list[str]) -> dict[str, str]:
    discovered: dict[str, str] = {}
    for line in lines:
        match = re.search(r"(\d+\.\d+\.\d+\.\d+).*?(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", line)
        if not match:
            continue
        ip = match.group(1)
        mac = normalize_mac(match.group(2))
        discovered[ip] = mac
    return discovered


def _read_arp_table() -> dict[str, str]:
    commands: list[list[str]] = [["ip", "neigh", "show"], ["arp", "-a"]]
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
        except OSError:
            continue
        if proc.returncode != 0 and not proc.stdout:
            continue
        parsed = _parse_arp_lines((proc.stdout or "").splitlines())
        if parsed:
            return parsed
    return {}


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"


def _guess_device_type(hostname: str, vendor: str) -> str:
    blob = f"{hostname} {vendor}".lower()
    if any(keyword in blob for keyword in IOT_KEYWORDS):
        return "iot"
    if "apple" in blob or "windows" in blob or "linux" in blob:
        return "computer"
    return "unknown"


def discover_lan_devices(
    subnet: str | None = None,
    *,
    max_hosts: int = 256,
    workers: int = 96,
) -> list[dict[str, Any]]:
    """Run a ping sweep + ARP/hostname/vendor lookup and return device records."""
    network = ipaddress.ip_network(subnet, strict=False) if subnet else _default_subnet()
    if network is None:
        return []

    hosts = [str(host) for host in network.hosts()][:max_hosts]
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="lan-ping") as pool:
        futures = [pool.submit(_ping_host, host) for host in hosts]
        for future in as_completed(futures):
            future.result()

    arp_table = _read_arp_table()
    devices: list[dict[str, Any]] = []

    for ip, mac in sorted(arp_table.items()):
        try:
            if ipaddress.ip_address(ip) not in network:
                continue
        except ValueError:
            continue

        oui = normalize_mac(mac)[:8]
        vendor = VENDOR_BY_OUI.get(oui, "Unknown")
        hostname = _resolve_hostname(ip)
        devices.append(
            {
                "ip": ip,
                "mac": normalize_mac(mac),
                "hostname": hostname,
                "vendor": vendor,
                "device_type": _guess_device_type(hostname, vendor),
            }
        )

    return devices


def collect_outbound_flows(registry: DeviceRegistry) -> list[OutboundFlow]:
    """Collect active outbound flows that originate from discovered local devices."""
    local_ip_index = {str(device.get("ip", "")) for device in registry.devices}
    flows: list[OutboundFlow] = []

    for conn in psutil.net_connections(kind="inet"):
        if conn.status != "ESTABLISHED" or not conn.laddr or not conn.raddr:
            continue

        local_ip = str(getattr(conn.laddr, "ip", ""))
        local_port = int(getattr(conn.laddr, "port", 0) or 0)
        remote_ip = str(getattr(conn.raddr, "ip", ""))
        remote_port = int(getattr(conn.raddr, "port", 0) or 0)
        if local_ip not in local_ip_index or is_local_or_private_ip(remote_ip):
            continue

        process_name = "Unknown"
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                process_name = "Unknown"

        flows.append(
            OutboundFlow(
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol="tcp",
                process_name=process_name,
            )
        )
    return flows


def correlate_iot_outbound_anomalies(registry: DeviceRegistry) -> list[dict[str, Any]]:
    """Detect suspicious outbound flows for local IoT-class devices."""
    device_by_ip = {str(device.get("ip", "")): device for device in registry.devices}
    anomalies: list[dict[str, Any]] = []

    for flow in collect_outbound_flows(registry):
        device = device_by_ip.get(flow.local_ip)
        if not device or str(device.get("device_type", "")).lower() != "iot":
            continue

        intel = get_ip_intel(flow.remote_ip)
        country = str(intel.get("country") or "Unknown")
        provider = str(intel.get("provider") or "Unknown")

        anomaly = evaluate_iot_anomaly(device=device, flow=flow, remote_intel=intel)
        if not anomaly and provider and provider not in device.get("allowed_providers", []):
            device.setdefault("allowed_providers", []).append(provider)
        if not anomaly:
            continue

        anomalies.append(
            {
                "device_ip": flow.local_ip,
                "device_mac": str(device.get("mac", "")),
                "device_hostname": str(device.get("hostname", "Unknown")),
                "device_vendor": str(device.get("vendor", "Unknown")),
                "remote_ip": flow.remote_ip,
                "remote_port": flow.remote_port,
                "country": country,
                "provider": provider,
                "process_name": flow.process_name,
                "risk": anomaly.get("risk", "average"),
                "reason": anomaly.get("reason", "unexpected outbound destination"),
            }
        )

    return anomalies
