from __future__ import annotations

import csv
import json
from pathlib import Path


def _parse_params(value: str) -> list[str]:
    value = (value or "").strip()
    if not value:
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    except json.JSONDecodeError:
        pass
    return [part.strip() for part in value.split("|") if part.strip()]


def load_methods(methods_csv: Path) -> list[dict[str, object]]:
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        rows = []
        for raw in csv.DictReader(f):
            row: dict[str, object] = dict(raw)
            row["parameter_types"] = _parse_params(raw.get("parameter_types", ""))
            rows.append(row)
        return rows


def build_type_methods(methods_csv: Path, output_json: Path) -> dict[str, list[dict[str, object]]]:
    index: dict[str, list[dict[str, object]]] = {}
    for row in load_methods(methods_csv):
        type_name = str(row.get("type_name", ""))
        type_index = str(row.get("type_definition_index", ""))
        for key in {type_name, type_index} - {""}:
            index.setdefault(key, []).append(row)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return index


def query_methods(
    methods_csv: Path,
    type_name: str | None = None,
    parameter_type: str | None = None,
    method_name: str | None = None,
) -> list[dict[str, object]]:
    rows = load_methods(methods_csv)
    result = []
    for row in rows:
        if type_name and type_name.casefold() not in str(row.get("type_name", "")).casefold():
            continue
        if method_name and method_name.casefold() not in str(row.get("method_name", "")).casefold():
            continue
        if parameter_type:
            params = [str(item).casefold() for item in row.get("parameter_types", [])]
            if parameter_type.casefold() not in params:
                continue
        result.append(row)
    return result
