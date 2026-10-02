from __future__ import annotations

import csv
import json
from collections import defaultdict
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


def build_type_methods(methods_csv: Path, output_json: Path) -> dict[str, dict[str, list[int]]]:
    """Build a compact type -> method-index lookup.

    The methods CSV remains the source of method details. Repeating complete method
    rows inside JSON made the 7.1 index hundreds of megabytes and duplicated data
    already present in methods.csv. The canonical index stores only method indices,
    separated by semantic type name and numeric type-definition index.
    """

    by_name: dict[str, list[int]] = defaultdict(list)
    by_index: dict[str, list[int]] = defaultdict(list)
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fields = set(reader.fieldnames or ())
        required = {"method_index", "type_definition_index", "type_name"}
        missing = sorted(required - fields)
        if missing:
            raise ValueError(
                f"{methods_csv} missing columns required for type-method index: {', '.join(missing)}"
            )
        for row in reader:
            text = str(row.get("method_index", "")).strip()
            if not text:
                continue
            try:
                method_index = int(text, 0)
            except ValueError as exc:
                raise ValueError(f"bad method_index {text!r} in {methods_csv}") from exc

            type_name = str(row.get("type_name", "")).strip()
            type_definition_index = str(row.get("type_definition_index", "")).strip()
            if type_name:
                by_name[type_name].append(method_index)
            if type_definition_index:
                by_index[type_definition_index].append(method_index)

    index = {
        "by_type_name": dict(by_name),
        "by_type_definition_index": dict(by_index),
    }
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(index, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
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
