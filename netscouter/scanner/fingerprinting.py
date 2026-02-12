"""Service fingerprinting helpers for open TCP ports."""

from __future__ import annotations

from dataclasses import dataclass
import re
import socket
from typing import Callable


@dataclass(slots=True)
class ServiceFingerprint:
    service: str = "unknown"
    software: str = "unknown"
    version: str = ""
    banner: str = ""
    confidence: str = "low"


def _recv_banner(sock: socket.socket, limit: int = 256) -> str:
    try:
        payload = sock.recv(limit)
    except (TimeoutError, OSError):
        return ""
    return payload.decode("utf-8", errors="ignore").strip()


def _extract_version(pattern: str, banner: str) -> str:
    match = re.search(pattern, banner, flags=re.IGNORECASE)
    if not match:
        return ""
    if match.groups():
        return str(match.group(1)).strip()
    return ""


def _probe_http(sock: socket.socket) -> str:
    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
    return _recv_banner(sock)


def _probe_smtp(sock: socket.socket) -> str:
    greeting = _recv_banner(sock)
    sock.sendall(b"EHLO netscouter.local\r\n")
    return "\n".join(filter(None, [greeting, _recv_banner(sock)]))


def _probe_ssh(sock: socket.socket) -> str:
    greeting = _recv_banner(sock)
    sock.sendall(b"SSH-2.0-NetScouterProbe\r\n")
    return greeting


def _probe_ftp(sock: socket.socket) -> str:
    greeting = _recv_banner(sock)
    sock.sendall(b"SYST\r\n")
    return "\n".join(filter(None, [greeting, _recv_banner(sock)]))


def _probe_mysql(sock: socket.socket) -> str:
    greeting = _recv_banner(sock)
    return greeting


def _probe_generic(sock: socket.socket) -> str:
    sock.sendall(b"\r\n")
    return _recv_banner(sock)


def _signature_from_banner(port: int, banner: str) -> ServiceFingerprint:
    lowered = banner.lower()

    if "ssh-" in lowered:
        return ServiceFingerprint(
            service="ssh",
            software="openssh" if "openssh" in lowered else "ssh",
            version=_extract_version(r"openssh[_-]([0-9][^\s]+)", banner),
            banner=banner,
            confidence="high",
        )
    if "server:" in lowered or "http/" in lowered:
        software = "nginx" if "nginx" in lowered else "apache" if "apache" in lowered else "http-server"
        version = _extract_version(r"(?:nginx|apache)/([0-9][^\s\r\n;]+)", banner) or _extract_version(
            r"http/[0-9.]+\s+[0-9]+\s+[^\r\n]+", banner
        )
        return ServiceFingerprint(service="http", software=software, version=version, banner=banner, confidence="high")
    if "smtp" in lowered or "esmtp" in lowered:
        return ServiceFingerprint(
            service="smtp",
            software="postfix" if "postfix" in lowered else "exim" if "exim" in lowered else "smtp-server",
            version=_extract_version(r"(?:postfix|exim)[/\s-]?([0-9][^\s\r\n]+)", banner),
            banner=banner,
            confidence="medium",
        )
    if "ftp" in lowered:
        return ServiceFingerprint(
            service="ftp",
            software="vsftpd" if "vsftpd" in lowered else "proftpd" if "proftpd" in lowered else "ftp-server",
            version=_extract_version(r"(?:vsftpd|proftpd)[\s-]?([0-9][^\s\r\n]+)", banner),
            banner=banner,
            confidence="medium",
        )
    if "mysql" in lowered or port == 3306:
        return ServiceFingerprint(service="mysql", software="mysql", version=_extract_version(r"([0-9]+\.[0-9]+\.[0-9]+)", banner), banner=banner, confidence="medium")
    return ServiceFingerprint(service=f"tcp/{port}", software="unknown", version="", banner=banner, confidence="low")


def fingerprint_service(host: str, port: int, timeout: float = 0.7) -> ServiceFingerprint:
    """Best-effort banner grabbing + protocol specific probes for open ports."""
    probes: dict[int, Callable[[socket.socket], str]] = {
        21: _probe_ftp,
        22: _probe_ssh,
        25: _probe_smtp,
        80: _probe_http,
        443: _probe_http,
        587: _probe_smtp,
        3306: _probe_mysql,
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, int(port)))
            probe = probes.get(int(port), _probe_generic)
            banner = probe(sock)
            return _signature_from_banner(int(port), banner)
    except OSError:
        return ServiceFingerprint(service=f"tcp/{port}", software="unknown", version="", banner="", confidence="low")
