"""Heuristics for packet-level alerting."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def evaluate_packet_signals(remote_ip: str, packets: list[dict[str, Any]]) -> list[str]:
    """Return human-readable alerts for malformed and heartbeat-like traffic."""
    if not packets:
        return []

    alerts: list[str] = []
    malformed_count = sum(1 for packet in packets if packet.get("malformed"))
    if malformed_count >= 3:
        alerts.append(f"{remote_ip}: malformed packets detected ({malformed_count} in current slice)")

    heartbeat_msg = _detect_heartbeat(remote_ip, packets)
    if heartbeat_msg:
        alerts.append(heartbeat_msg)

    return alerts


def _detect_heartbeat(remote_ip: str, packets: list[dict[str, Any]]) -> str | None:
    aligned = [packet for packet in packets if not packet.get("malformed")]
    if len(aligned) < 6:
        return None

    recent = aligned[-10:]
    lengths = [int(packet.get("packet_length") or 0) for packet in recent]
    small_packets = sum(1 for length in lengths if 1 <= length <= 96)
    dominant_length = max(set(lengths), key=lengths.count)

    timestamps = [packet.get("timestamp") for packet in recent]
    parsed = []
    for value in timestamps:
        if not value:
            continue
        try:
            parsed.append(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
        except ValueError:
            continue

    if len(parsed) < 6:
        return None

    intervals = []
    for index in range(1, len(parsed)):
        interval = (parsed[index] - parsed[index - 1]).total_seconds()
        if interval > 0:
            intervals.append(interval)

    if len(intervals) < 5:
        return None

    avg_interval = sum(intervals) / len(intervals)
    jitter = sum(abs(interval - avg_interval) for interval in intervals) / len(intervals)
    if small_packets >= 6 and lengths.count(dominant_length) >= 6 and jitter <= 1.2 and avg_interval <= 10:
        return (
            f"{remote_ip}: heartbeat-like stream observed "
            f"(len={dominant_length}, avg interval={avg_interval:.2f}s, jitter={jitter:.2f}s)"
        )
    return None
