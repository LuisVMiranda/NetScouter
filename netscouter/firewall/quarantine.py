"""Platform-specific quarantine NAT/redirect command builders."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class QuarantinePlan:
    """Command plan required to quarantine an offending source IP."""

    platform: str
    source_ip: str
    sinkhole_host: str
    sinkhole_port: int
    commands: list[list[str]]
    notes: str


def build_quarantine_plan(
    *,
    platform: str,
    source_ip: str,
    sinkhole_host: str,
    sinkhole_port: int,
) -> QuarantinePlan:
    """Build platform-specific redirect/NAT commands for a quarantined source."""
    if platform == "windows":
        commands = [
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=NetScouter Quarantine {source_ip} Inbound",
                "dir=in",
                "action=block",
                f"remoteip={source_ip}",
            ],
            [
                "netsh",
                "interface",
                "portproxy",
                "add",
                "v4tov4",
                f"listenport={sinkhole_port}",
                f"listenaddress={sinkhole_host}",
                f"connectport={sinkhole_port}",
                f"connectaddress={sinkhole_host}",
            ],
        ]
        return QuarantinePlan(
            platform=platform,
            source_ip=source_ip,
            sinkhole_host=sinkhole_host,
            sinkhole_port=sinkhole_port,
            commands=commands,
            notes="Windows quarantine adds an inbound block and local sinkhole portproxy mapping.",
        )

    if platform == "linux":
        commands = [
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-s",
                source_ip,
                "-p",
                "tcp",
                "-j",
                "REDIRECT",
                "--to-ports",
                str(sinkhole_port),
            ],
            [
                "iptables",
                "-A",
                "INPUT",
                "-s",
                source_ip,
                "-p",
                "tcp",
                "--dport",
                str(sinkhole_port),
                "-j",
                "ACCEPT",
            ],
        ]
        return QuarantinePlan(
            platform=platform,
            source_ip=source_ip,
            sinkhole_host=sinkhole_host,
            sinkhole_port=sinkhole_port,
            commands=commands,
            notes="Linux quarantine redirects quarantined source traffic into local sinkhole port.",
        )

    if platform == "macos":
        commands = [
            [
                "pfctl",
                "-a",
                "com.netscouter.quarantine",
                "-f",
                "-",
            ]
        ]
        return QuarantinePlan(
            platform=platform,
            source_ip=source_ip,
            sinkhole_host=sinkhole_host,
            sinkhole_port=sinkhole_port,
            commands=commands,
            notes=(
                "macOS quarantine requires loading a pf anchor rule like: "
                f"rdr pass inet proto tcp from {source_ip} to any -> {sinkhole_host} port {sinkhole_port}"
            ),
        )

    return QuarantinePlan(
        platform=platform,
        source_ip=source_ip,
        sinkhole_host=sinkhole_host,
        sinkhole_port=sinkhole_port,
        commands=[],
        notes="Unsupported platform for quarantine NAT/redirect rule plan.",
    )

