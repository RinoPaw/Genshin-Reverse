from __future__ import annotations

import csv
import json
from pathlib import Path


def parse_parameter_types(value: str) -> list[str]:
    value = (value or "").strip()
    if not value:
        return []
    parsed = json.loads(value)
    if not isinstance(parsed, list):
        raise ValueError("parameter_types must be a JSON array")
    return [str(item) for item in parsed]


def load_methods(methods_csv: Path) -> list[dict[str, object]]:
    """Load a methods CSV and decode its parameter_types arrays."""

    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        rows: list[dict[str, object]] = []
        for raw in csv.DictReader(f):
            row: dict[str, object] = dict(raw)
            row["parameter_types"] = parse_parameter_types(raw.get("parameter_types", ""))
            rows.append(row)
        return rows
