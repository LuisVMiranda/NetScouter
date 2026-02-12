"""Export helpers for IoT map inventory and anomaly findings."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .writers import export_json_document


def export_iot_map(
    devices: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
    output_path: str | Path,
) -> Path:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "device_count": len(devices),
        "anomaly_count": len(anomalies),
        "devices": devices,
        "anomalies": anomalies,
    }
    return export_json_document(output_path, payload)
