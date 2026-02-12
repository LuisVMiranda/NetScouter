"""Live packet capture service built on top of Scapy."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import threading
from typing import Any

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
        self._port: int | None = None

    @property
    def remote_ip(self) -> str | None:
        return self._remote_ip

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stop_event(self) -> threading.Event:
        """Set once stop is requested; useful for GUI shutdown coordination."""
        return self._stop_requested

    @property
    def stopped_event(self) -> threading.Event:
        """Set once capture has fully stopped and resources are released."""
        return self._stopped

    def start(self, remote_ip: str, port: int | None = None) -> None:
        """Start live capture for a remote IP (and optional port)."""
        if AsyncSniffer is None:
            raise RuntimeError("Scapy is unavailable. Install scapy and rerun.")

        self.stop(timeout=0.5)

        self._remote_ip = remote_ip
        self._port = port
        self._stop_requested.clear()
        self._stopped.clear()
        with self._lock:
            self._packets.clear()

        bpf = f"host {remote_ip}"
        if port is not None:
            bpf = f"{bpf} and port {port}"

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=bpf,
            store=False,
            prn=self._on_packet,
        )
        self._running = True
        self._sniffer.start()

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
        except Exception as exc:  # noqa: BLE001
            summary["malformed"] = True
            summary["parse_error"] = str(exc)

        return summary
