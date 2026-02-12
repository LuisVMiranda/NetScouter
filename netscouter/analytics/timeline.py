"""Timeline aggregations for charting and exports."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if not text:
        return None

    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def normalize_timeline_rows(
    events: list[dict[str, Any]],
    *,
    schedule_overlays: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Normalize scan events into timeline-friendly row objects."""
    overlays_by_scan: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for overlay in schedule_overlays or []:
        scan_key = str(overlay.get("scan_id") or "")
        if scan_key:
            overlays_by_scan[scan_key].append(overlay)

    rows: list[dict[str, Any]] = []
    for event in events:
        timestamp = _parse_timestamp(event.get("timestamp"))
        if timestamp is None:
            continue

        scan_id = str(event.get("scan_id") or "")
        overlays = overlays_by_scan.get(scan_id, [])
        rows.append(
            {
                "timestamp": timestamp,
                "timestamp_iso": timestamp.isoformat(),
                "status": str(event.get("status") or "Unknown"),
                "risk": str(event.get("risk") or "Average"),
                "risk_level": str(event.get("risk_level") or str(event.get("risk") or "average")).lower(),
                "source_ip": str(event.get("remote_ip") or event.get("ip") or ""),
                "port": event.get("port", ""),
                "scan_id": scan_id,
                "schedule_job_ids": ",".join(
                    sorted({str(item.get('job_id') or '') for item in overlays if item.get('job_id')})
                ),
                "scheduled_windows": ",".join(
                    sorted({str(item.get('scheduled_for') or '') for item in overlays if item.get('scheduled_for')})
                ),
                "trigger_sources": ",".join(
                    sorted({str(item.get('source') or '') for item in overlays if item.get('source')})
                ),
            }
        )
    return rows


def filter_timeline_events(
    rows: list[dict[str, Any]],
    *,
    status: str = "All Status",
    risk: str = "All Risk",
    source_ip: str = "",
) -> list[dict[str, Any]]:
    """Filter normalized timeline rows by status, risk, and source IP."""
    source_filter = source_ip.strip().lower()
    filtered: list[dict[str, Any]] = []
    for row in rows:
        row_status = str(row.get("status", "")).lower()
        row_risk = str(row.get("risk", "")).lower()
        row_source = str(row.get("source_ip", "")).lower()

        if status != "All Status" and row_status != status.lower():
            continue
        if risk != "All Risk" and row_risk != risk.lower():
            continue
        if source_filter and source_filter not in row_source:
            continue
        filtered.append(row)
    return filtered


def bucket_events_by_time(rows: list[dict[str, Any]], *, bucket: str = "hour") -> list[dict[str, Any]]:
    """Bucket rows by hour/day and risk level."""
    if bucket not in {"hour", "day"}:
        raise ValueError("bucket must be 'hour' or 'day'")

    grouped: dict[datetime, dict[str, int]] = defaultdict(lambda: {"low": 0, "average": 0, "high": 0, "total": 0})

    for row in rows:
        timestamp = _parse_timestamp(row.get("timestamp") or row.get("timestamp_iso"))
        if timestamp is None:
            continue
        key = timestamp.replace(minute=0, second=0, microsecond=0) if bucket == "hour" else timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
        risk_level = str(row.get("risk_level") or row.get("risk") or "average").lower()
        if risk_level not in {"low", "average", "high"}:
            risk_level = "average"
        grouped[key][risk_level] += 1
        grouped[key]["total"] += 1

    return [
        {
            "bucket": key,
            "bucket_label": key.strftime("%Y-%m-%d %H:00") if bucket == "hour" else key.strftime("%Y-%m-%d"),
            "low": counts["low"],
            "average": counts["average"],
            "high": counts["high"],
            "total": counts["total"],
        }
        for key, counts in sorted(grouped.items(), key=lambda item: item[0])
    ]


def build_heatmap_matrix(rows: list[dict[str, Any]]) -> tuple[list[list[int]], list[str], list[str]]:
    """Build a weekday/hour matrix for recurring attack windows."""
    matrix = [[0 for _ in range(24)] for _ in range(7)]
    for row in rows:
        timestamp = _parse_timestamp(row.get("timestamp") or row.get("timestamp_iso"))
        if timestamp is None:
            continue
        matrix[timestamp.weekday()][timestamp.hour] += 1

    weekdays = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    hours = [f"{hour:02d}" for hour in range(24)]
    return matrix, weekdays, hours
