"""Timeline dataset export helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import pandas as pd


def export_timeline_to_csv(rows: Iterable[dict[str, Any]], output_path: str | Path) -> Path:
    """Export normalized timeline rows to CSV."""
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    dataframe = pd.DataFrame(list(rows))
    dataframe.to_csv(target, index=False)
    return target


def export_timeline_to_xlsx(rows: Iterable[dict[str, Any]], output_path: str | Path) -> Path:
    """Export normalized timeline rows to XLSX."""
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    dataframe = pd.DataFrame(list(rows))
    with pd.ExcelWriter(target) as writer:
        dataframe.to_excel(writer, sheet_name="timeline", index=False)
    return target
