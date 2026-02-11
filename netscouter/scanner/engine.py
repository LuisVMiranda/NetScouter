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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            is_open = sock.connect_ex((host, port)) == 0
        return ScanResult(host=host, port=port, is_open=is_open)
    except OSError as exc:
        return ScanResult(host=host, port=port, is_open=False, error=str(exc))


def collect_established_connections() -> list[tuple[str, int]]:
    """Collect remote endpoints from established inet connections."""
    endpoints: list[tuple[str, int]] = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != "ESTABLISHED" or not conn.raddr:
            continue

        remote_ip: str | None = None
        remote_port: int | None = None
        if isinstance(conn.raddr, tuple):
            if len(conn.raddr) >= 2:
                remote_ip = conn.raddr[0]
                remote_port = conn.raddr[1]
        else:
            remote_ip = getattr(conn.raddr, "ip", None)
            remote_port = getattr(conn.raddr, "port", None)

        if remote_ip and remote_port:
            endpoints.append((remote_ip, int(remote_port)))

    return endpoints


def _callback_consumer(
    result_queue: queue.Queue[ScanResult | None],
    on_result: Callable[[ScanResult], None],
) -> None:
    """Consume queue entries and run callbacks outside scanner threads."""
    while True:
        result = result_queue.get()
        if result is None:
            result_queue.task_done()
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
    max_workers: int = 128,
    timeout: float = 0.6,
) -> ScanJob:
    """Scan host/port combinations asynchronously and stream results via callback."""

    result_queue: queue.Queue[ScanResult | None] = queue.Queue()
    stop_event = threading.Event()

    callback_worker = threading.Thread(
        target=_callback_consumer,
        args=(result_queue, on_result),
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
                    future.add_done_callback(
                        lambda fut: result_queue.put(fut.result()) if not stop_event.is_set() else None
                    )
                    futures.append(future)

            for future in futures:
                if stop_event.is_set():
                    future.cancel()
                    continue
                future.result()

        result_queue.put(None)

    scan_worker = threading.Thread(target=worker, daemon=True, name="scan-submit-worker")
    callback_worker.start()
    scan_worker.start()

    return ScanJob(_worker=scan_worker, _callback_worker=callback_worker, _stop_event=stop_event)


def scan_established_connections(
    ports: Iterable[int],
    on_result: Callable[[ScanResult], None],
    *,
    max_workers: int = 128,
    timeout: float = 0.6,
) -> ScanJob:
    """Convenience wrapper: scan remotes discovered from ESTABLISHED sockets."""
    targets = sorted({ip for ip, _ in collect_established_connections()})
    return scan_targets(targets=targets, ports=list(ports), on_result=on_result, max_workers=max_workers, timeout=timeout)
