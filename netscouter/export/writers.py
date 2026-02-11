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
