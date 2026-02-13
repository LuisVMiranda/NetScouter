"""Threaded scan engine and connection collectors."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import queue
import random
import socket
import threading
import time
from typing import Callable, Iterable, Sequence

import psutil

from .ip_utils import is_local_or_private


@dataclass(slots=True)
class ScanResult:
    """Single probe result produced by the scanner engine."""

    host: str
    port: int
    is_open: bool
    source: str = "probe"
    error: str | None = None
    local_port: int | None = None
    pid: int | None = None
    process_name: str | None = None
    exe_path: str | None = None
    cmdline: str | None = None


@dataclass(slots=True)
class ScanJob:
    """Async scan handle returned by :func:`scan_targets`."""

    _worker: threading.Thread
    _callback_worker: threading.Thread
    _stop_event: threading.Event

    def cancel(self) -> None:
        """Ask the scan to stop early."""
        self._stop_event.set()

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for workers to finish; returns ``True`` when both are done."""
        self._worker.join(timeout)
        self._callback_worker.join(timeout)
        return not self._worker.is_alive() and not self._callback_worker.is_alive()


def _probe_tcp_port(host: str, port: int, timeout: float) -> ScanResult:
    """Attempt a TCP connect and return open/closed state."""
    if port < 0 or port > 65535:
        return ScanResult(host=host, port=port, is_open=False, error="invalid-port")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            is_open = sock.connect_ex((host, port)) == 0
        return ScanResult(host=host, port=port, is_open=is_open)
    except OSError as exc:
        return ScanResult(host=host, port=port, is_open=False, error=str(exc))


def _normalize_host_port(address: object | None) -> tuple[str | None, int | None]:
    if not address:
        return None, None

    if isinstance(address, tuple):
        if len(address) >= 2:
            return str(address[0]), int(address[1])
        return None, None

    return getattr(address, "ip", None), getattr(address, "port", None)


def _safe_process_details(pid: int | None) -> dict[str, str | int | None]:
    details: dict[str, str | int | None] = {
        "pid": pid,
        "process_name": "Unknown",
        "exe_path": "",
        "cmdline": "",
    }
    if not pid:
        return details

    try:
        process = psutil.Process(pid)
        details["process_name"] = process.name()
        details["exe_path"] = process.exe() or ""
        details["cmdline"] = " ".join(process.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return details


def collect_established_connections() -> tuple[list[tuple[str, int]], dict[str, dict[str, str | int | None]]]:
    """Collect remote endpoints from established inet connections plus process context."""
    endpoints: list[tuple[str, int]] = []
    ip_to_process: dict[str, dict[str, str | int | None]] = {}
    local_port_to_process: dict[int, dict[str, str | int | None]] = {}

    for conn in psutil.net_connections(kind="inet"):
        _, local_port = _normalize_host_port(conn.laddr)
        if local_port and local_port not in local_port_to_process:
            local_port_to_process[local_port] = _safe_process_details(conn.pid)

        if conn.status != "ESTABLISHED" or not conn.raddr:
            continue

        remote_ip, remote_port = _normalize_host_port(conn.raddr)

        if remote_ip and remote_port:
            endpoints.append((remote_ip, int(remote_port)))
            process_details = local_port_to_process.get(int(local_port or 0)) or _safe_process_details(conn.pid)
            ip_to_process.setdefault(remote_ip, process_details)

    return endpoints, ip_to_process


def _callback_consumer(
    result_queue: queue.Queue[ScanResult | None],
    on_result: Callable[[ScanResult], None],
    on_complete: Callable[[], None] | None = None,
) -> None:
    """Consume queue entries and run callbacks outside scanner threads."""
    while True:
        result = result_queue.get()
        if result is None:
            result_queue.task_done()
            if on_complete:
                on_complete()
            break

        try:
            on_result(result)
        finally:
            result_queue.task_done()


def scan_targets(
    targets: Sequence[str],
    ports: Sequence[int],
    on_result: Callable[[ScanResult], None],
    *,
    on_complete: Callable[[], None] | None = None,
    max_workers: int = 128,
    timeout: float = 0.6,
    target_process_map: dict[str, dict[str, str | int | None]] | None = None,
) -> ScanJob:
    """Scan host/port combinations asynchronously and stream results via callback."""

    result_queue: queue.Queue[ScanResult | None] = queue.Queue()
    stop_event = threading.Event()

    callback_worker = threading.Thread(
        target=_callback_consumer,
        args=(result_queue, on_result, on_complete),
        daemon=True,
        name="scan-callback-consumer",
    )

    def worker() -> None:
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan-probe") as pool:
            futures = []

            for target in targets:
                if stop_event.is_set():
                    break

                if not is_local_or_private(target):
                    time.sleep(random.uniform(0.1, 0.5))

                for port in ports:
                    if stop_event.is_set():
                        break

                    future = pool.submit(_probe_tcp_port, target, int(port), timeout)
                    def _queue_result(fut, target_host: str = target, port_value: int = int(port)) -> None:  # type: ignore[no-untyped-def]
                        if stop_event.is_set():
                            return
                        try:
                            result = fut.result()
                        except Exception as exc:  # noqa: BLE001
                            result = ScanResult(host=target_host, port=port_value, is_open=False, error=str(exc))
                        if target_process_map:
                            process_meta = target_process_map.get(target_host, {})
                            result.pid = int(process_meta.get("pid")) if process_meta.get("pid") else None
                            result.process_name = str(process_meta.get("process_name", "Unknown"))
                            result.exe_path = str(process_meta.get("exe_path", ""))
                            result.cmdline = str(process_meta.get("cmdline", ""))
                        result_queue.put(result)

                    future.add_done_callback(_queue_result)
                    futures.append(future)

            for future in futures:
                if stop_event.is_set():
                    future.cancel()
                    continue
                try:
                    future.result()
                except Exception:
                    continue

        result_queue.put(None)

    scan_worker = threading.Thread(target=worker, daemon=True, name="scan-submit-worker")
    callback_worker.start()
    scan_worker.start()

    return ScanJob(_worker=scan_worker, _callback_worker=callback_worker, _stop_event=stop_event)


def scan_established_connections(
    ports: Iterable[int],
    on_result: Callable[[ScanResult], None],
    *,
    on_complete: Callable[[], None] | None = None,
    max_workers: int = 128,
    timeout: float = 0.6,
) -> ScanJob:
    """Convenience wrapper: scan remotes discovered from ESTABLISHED sockets."""
    endpoints, process_map = collect_established_connections()
    targets = sorted({ip for ip, _ in endpoints})
    return scan_targets(
        targets=targets,
        ports=list(ports),
        on_result=on_result,
        on_complete=on_complete,
        max_workers=max_workers,
        timeout=timeout,
        target_process_map=process_map,
    )
