"""Live packet capture service built on top of Scapy."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import ipaddress
import socket
import threading
import time
from typing import Any

import psutil

try:
    from scapy.all import AsyncSniffer  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    AsyncSniffer = None  # type: ignore[assignment]


class PacketCaptureService:
    """Capture packets for a selected remote host using a bounded ring buffer."""

    def __init__(self, max_packets: int = 500, interface: str | None = None) -> None:
        self.max_packets = max_packets
        self.interface = interface
        self._packets: deque[dict[str, Any]] = deque(maxlen=max_packets)
        self._lock = threading.Lock()
        self._sniffer: Any | None = None
        self._stop_requested = threading.Event()
        self._stopped = threading.Event()
        self._running = False
        self._remote_ip: str | None = None
        self._network_cidr: str | None = None
        self._port: int | None = None
        self._mode = "remote"
        self._capture_filter = ""
        self._capture_interface = "default"
        self._conn_index: dict[tuple[str, int], dict[str, Any]] = {}
        self._conn_index_refreshed_at = 0.0

    @property
    def remote_ip(self) -> str | None:
        return self._remote_ip

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def capture_filter(self) -> str:
        return self._capture_filter

    @property
    def capture_interface(self) -> str:
        return self._capture_interface

    @property
    def stop_event(self) -> threading.Event:
        """Set once stop is requested; useful for GUI shutdown coordination."""
        return self._stop_requested

    @property
    def stopped_event(self) -> threading.Event:
        """Set once capture has fully stopped and resources are released."""
        return self._stopped

    def start(
        self,
        remote_ip: str,
        port: int | None = None,
        *,
        network_cidr: str | None = None,
        mode: str = "remote",
    ) -> None:
        """Start live capture for remote IP or local-network scope."""
        global AsyncSniffer
        if AsyncSniffer is None:
            try:
                from scapy.all import AsyncSniffer as runtime_sniffer  # type: ignore[import-not-found]

                AsyncSniffer = runtime_sniffer
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError("Scapy is unavailable. Install scapy and rerun.") from exc
        if AsyncSniffer is None:
            raise RuntimeError("Scapy is unavailable. Install scapy and rerun.")

        self.stop(timeout=0.5)

        self._remote_ip = remote_ip
        self._network_cidr = network_cidr
        self._port = port
        self._mode = mode
        self._stop_requested.clear()
        self._stopped.clear()
        with self._lock:
            self._packets.clear()

        capture_iface = self.interface or self._resolve_capture_interface(remote_ip)
        self._capture_interface = capture_iface or "default"

        if mode == "local_network":
            bpf = ""
            if network_cidr:
                bpf = f"net {network_cidr}"
            lfilter = None
        else:
            bpf = ""
            lfilter = self._build_remote_lfilter(remote_ip, port)

        self._capture_filter = bpf or "python-lfilter"

        sniffer_kwargs: dict[str, Any] = {
            "iface": capture_iface,
            "store": False,
            "prn": self._on_packet,
        }
        if bpf:
            sniffer_kwargs["filter"] = bpf
        if lfilter is not None:
            sniffer_kwargs["lfilter"] = lfilter

        self._sniffer = AsyncSniffer(**sniffer_kwargs)
        self._running = True
        self._sniffer.start()


    def _resolve_capture_interface(self, remote_ip: str) -> str | None:
        target_ip = self._detect_local_ipv4() if self._mode == "local_network" else self._detect_route_local_ip(remote_ip)
        if target_ip:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if getattr(addr, "family", None) == socket.AF_INET and getattr(addr, "address", "") == target_ip:
                        return iface
        return None

    def _detect_route_local_ip(self, remote_ip: str) -> str | None:
        fallback = "8.8.8.8"
        candidate = remote_ip if remote_ip and ":" not in remote_ip else fallback
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((candidate, 80))
                return sock.getsockname()[0]
        except OSError:
            return self._detect_local_ipv4()

    def _detect_local_ipv4(self) -> str | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
        except OSError:
            return None

    def _build_remote_lfilter(self, remote_ip: str, port: int | None) -> Any:
        def _accept(pkt: Any) -> bool:
            try:
                if not pkt.haslayer("IP"):
                    return False
                ip_layer = pkt.getlayer("IP")
                src = str(getattr(ip_layer, "src", ""))
                dst = str(getattr(ip_layer, "dst", ""))
                if remote_ip and remote_ip not in {src, dst}:
                    return False
                if port is None:
                    return True
                if pkt.haslayer("TCP"):
                    layer = pkt.getlayer("TCP")
                    return int(getattr(layer, "sport", -1)) == port or int(getattr(layer, "dport", -1)) == port
                if pkt.haslayer("UDP"):
                    layer = pkt.getlayer("UDP")
                    return int(getattr(layer, "sport", -1)) == port or int(getattr(layer, "dport", -1)) == port
                return False
            except Exception:
                return False

        return _accept

    def stop(self, timeout: float = 1.5) -> bool:
        """Stop capture thread and return True when stopped within timeout."""
        self._stop_requested.set()
        sniffer = self._sniffer
        if not sniffer:
            self._running = False
            self._stopped.set()
            return True

        try:
            sniffer.stop(join=True)
        except Exception:  # noqa: BLE001
            pass

        self._sniffer = None
        self._running = False
        self._mode = "remote"
        self._capture_filter = ""
        self._capture_interface = "default"
        self._stopped.set()
        return self._stopped.wait(timeout)

    def get_packets(self, *, remote_ip: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._packets)

        if remote_ip:
            items = [item for item in items if item.get("src") == remote_ip or item.get("dst") == remote_ip]
        if limit is not None and limit > 0:
            items = items[-limit:]
        return items

    def clear_packets(self) -> None:
        with self._lock:
            self._packets.clear()

    def export_packets(self, path: str, *, remote_ip: str | None = None, limit: int | None = None) -> int:
        import json

        payload = self.get_packets(remote_ip=remote_ip, limit=limit)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        return len(payload)

    def _on_packet(self, packet: Any) -> None:
        parsed = self._normalize_packet(packet)
        with self._lock:
            self._packets.append(parsed)

    def _normalize_packet(self, packet: Any) -> dict[str, Any]:
        summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src": None,
            "dst": None,
            "proto": "Unknown",
            "tcp_flags": "",
            "packet_length": None,
            "malformed": False,
            "parse_error": "",
            "raw": {
                "ip_ttl": None,
                "ip_id": None,
                "src_port": None,
                "dst_port": None,
                "seq": None,
                "ack": None,
            },
            "pid": None,
            "process_name": "",
        }

        try:
            if packet is None:
                raise ValueError("Empty packet")

            summary["packet_length"] = int(len(packet))

            if packet.haslayer("IP"):
                ip_layer = packet.getlayer("IP")
                summary["src"] = getattr(ip_layer, "src", None)
                summary["dst"] = getattr(ip_layer, "dst", None)
                summary["raw"]["ip_ttl"] = getattr(ip_layer, "ttl", None)
                summary["raw"]["ip_id"] = getattr(ip_layer, "id", None)

            if packet.haslayer("TCP"):
                tcp = packet.getlayer("TCP")
                summary["proto"] = "TCP"
                summary["tcp_flags"] = str(getattr(tcp, "flags", ""))
                summary["raw"]["src_port"] = getattr(tcp, "sport", None)
                summary["raw"]["dst_port"] = getattr(tcp, "dport", None)
                summary["raw"]["seq"] = getattr(tcp, "seq", None)
                summary["raw"]["ack"] = getattr(tcp, "ack", None)
            elif packet.haslayer("UDP"):
                udp = packet.getlayer("UDP")
                summary["proto"] = "UDP"
                summary["raw"]["src_port"] = getattr(udp, "sport", None)
                summary["raw"]["dst_port"] = getattr(udp, "dport", None)
            elif packet.haslayer("ICMP"):
                summary["proto"] = "ICMP"

            summary.update(self._resolve_process_meta(summary))
        except Exception as exc:  # noqa: BLE001
            summary["malformed"] = True
            summary["parse_error"] = str(exc)

        return summary

    def _refresh_connection_index(self) -> None:
        now = time.monotonic()
        if now - self._conn_index_refreshed_at < 2.0:
            return
        cache: dict[tuple[str, int], dict[str, Any]] = {}
        for conn in psutil.net_connections(kind="inet"):
            if not conn.laddr:
                continue
            laddr = conn.laddr
            key = (str(getattr(laddr, "ip", "")), int(getattr(laddr, "port", 0)))
            if key[1] <= 0:
                continue
            pid = int(conn.pid) if conn.pid else None
            process_name = ""
            if pid:
                try:
                    process_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    process_name = ""
            cache[key] = {"pid": pid, "process_name": process_name}
        self._conn_index = cache
        self._conn_index_refreshed_at = now

    def _resolve_process_meta(self, packet_summary: dict[str, Any]) -> dict[str, Any]:
        self._refresh_connection_index()
        src = str(packet_summary.get("src") or "")
        dst = str(packet_summary.get("dst") or "")
        src_port = packet_summary.get("raw", {}).get("src_port")
        dst_port = packet_summary.get("raw", {}).get("dst_port")

        candidates: list[tuple[str, int]] = []
        if isinstance(src_port, int):
            candidates.append((src, src_port))
            candidates.append(("0.0.0.0", src_port))
            candidates.append(("::", src_port))
        if isinstance(dst_port, int):
            candidates.append((dst, dst_port))
            candidates.append(("0.0.0.0", dst_port))
            candidates.append(("::", dst_port))

        for key in candidates:
            meta = self._conn_index.get(key)
            if meta:
                return {
                    "pid": meta.get("pid"),
                    "process_name": meta.get("process_name", ""),
                }
        return {"pid": None, "process_name": ""}


def derive_lan_cidr(ipv4: str) -> str | None:
    """Best-effort /24 LAN block derivation from local IPv4."""
    try:
        network = ipaddress.ip_network(f"{ipv4}/24", strict=False)
    except ValueError:
        return None
    return str(network)
