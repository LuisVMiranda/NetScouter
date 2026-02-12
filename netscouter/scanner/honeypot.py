"""Lightweight local honeypot listener for quarantine observation logs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import socket
import threading
import time
from typing import Any


class LocalHoneypot:
    """Simple TCP listener that records inbound connection observations."""

    def __init__(self, host: str = "127.0.0.1", port: int = 25252) -> None:
        self.host = host
        self.port = int(port)
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._logs: list[dict[str, Any]] = []

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> bool:
        if self.is_running:
            return True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True, name="netscouter-honeypot")
        self._thread.start()
        deadline = time.time() + 1.2
        while time.time() < deadline:
            if self.healthy(timeout=0.2):
                return True
            time.sleep(0.05)
        return False

    def stop(self, timeout: float = 1.2) -> bool:
        self._stop_event.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=timeout)
        return not self.is_running

    def healthy(self, timeout: float = 0.6) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                return sock.connect_ex((self.host, self.port)) == 0
        except OSError:
            return False

    def recent_logs(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._logs[-limit:])

    def export_logs(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        rows = self.recent_logs(limit=10_000)
        lines = [
            f"{row['timestamp']} | {row['source_ip']}:{row['source_port']} -> {row['dest_ip']}:{row['dest_port']}"
            for row in rows
        ]
        target.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return target

    def _serve(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server = server
        try:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(64)
            server.settimeout(0.4)
            while not self._stop_event.is_set():
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with conn:
                    self._record(addr)
        except OSError:
            pass
        finally:
            try:
                server.close()
            except OSError:
                pass
            self._server = None

    def _record(self, addr: tuple[str, int]) -> None:
        source_ip, source_port = addr[0], int(addr[1])
        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "source_port": source_port,
            "dest_ip": self.host,
            "dest_port": self.port,
            "kind": "quarantine_interaction",
        }
        with self._lock:
            self._logs.append(row)
