from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path


def build_type_methods(methods_csv: Path, output_json: Path) -> dict[str, dict[str, list[int]]]:
    """Build the compact type -> method-index artifact used by publication."""

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
        for line_no, row in enumerate(reader, start=2):
            text = str(row.get("method_index", "")).strip()
            if not text:
                raise ValueError(f"{methods_csv}:{line_no}: missing method_index")
            try:
                method_index = int(text, 0)
            except ValueError as exc:
                raise ValueError(
                    f"{methods_csv}:{line_no}: bad method_index {text!r}"
                ) from exc

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
