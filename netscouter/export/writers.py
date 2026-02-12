"""Export writer stubs for JSON, text, and XLSX outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def append_json_log(path: str | Path, record: dict[str, Any]) -> None:
    """Append one JSON object per line."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def export_json_document(path: str | Path, payload: dict[str, Any]) -> Path:
    """Write a formatted JSON document and return the destination path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target
