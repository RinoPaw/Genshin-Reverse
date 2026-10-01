from __future__ import annotations

import csv
import json
from pathlib import Path

from .metadata import load_methods


def _norm_address(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    return f"0x{int(value, 0):X}"


def _load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def verify_metadata_anchors(metadata_dir: Path, anchors_json: Path) -> dict[str, object]:
    anchors = json.loads(anchors_json.read_text(encoding="utf-8"))
    type_rows = _load_csv(metadata_dir / "types.csv")
    field_rows = _load_csv(metadata_dir / "fields.csv") if (metadata_dir / "fields.csv").exists() else []
    method_rows = load_methods(metadata_dir / "methods.csv")

    checks: list[dict[str, object]] = []

    for anchor in anchors.get("types", []):
        matches = []
        for row in type_rows:
            if anchor.get("type_name") and row.get("type_name") != anchor.get("type_name"):
                continue
            expected_index = str(anchor.get("type_definition_index", ""))
            if expected_index and row.get("type_definition_index") != expected_index:
                continue
            expected_cache = _norm_address(str(anchor.get("type_cache_rva", "")))
            if expected_cache and _norm_address(row.get("type_cache_rva", "")) != expected_cache:
                continue
            expected_field_start = str(anchor.get("field_start", ""))
            if expected_field_start and row.get("field_start") != expected_field_start:
                continue
            expected_field_count = str(anchor.get("field_count", ""))
            if expected_field_count and row.get("field_count") != expected_field_count:
                continue
            expected_method_start = str(anchor.get("method_start", ""))
            if expected_method_start and row.get("method_start") != expected_method_start:
                continue
            expected_method_count = str(anchor.get("method_count", ""))
            if expected_method_count and row.get("method_count") != expected_method_count:
                continue
            matches.append(row)
        checks.append({"kind": "type", "anchor": anchor, "passed": bool(matches), "match_count": len(matches)})

    for anchor in anchors.get("fields", []):
        matches = []
        for row in field_rows:
            expected_index = str(anchor.get("field_index", ""))
            if expected_index and row.get("field_index") != expected_index:
                continue
            expected_owner = str(anchor.get("type_definition_index", ""))
            if expected_owner and row.get("type_definition_index") != expected_owner:
                continue
            if anchor.get("type_name") and row.get("type_name") != anchor.get("type_name"):
                continue
            if anchor.get("field_name") and row.get("field_name") != anchor.get("field_name"):
                continue
            if anchor.get("field_type") and row.get("field_type") != anchor.get("field_type"):
                continue
            expected_type_index = str(anchor.get("field_type_index", ""))
            if expected_type_index and row.get("field_type_index") != expected_type_index:
                continue
            matches.append(row)
        checks.append({"kind": "field", "anchor": anchor, "passed": bool(matches), "match_count": len(matches)})

    for anchor in anchors.get("methods", []):
        matches = []
        expected_rva = _norm_address(str(anchor.get("rva", "")))
        expected_params = [str(value) for value in anchor.get("parameter_types", [])]
        expected_index = str(anchor.get("method_index", ""))
        for row in method_rows:
            if expected_index and str(row.get("method_index", "")) != expected_index:
                continue
            expected_owner = str(anchor.get("type_definition_index", ""))
            if expected_owner and str(row.get("type_definition_index", "")) != expected_owner:
                continue
            if anchor.get("type_name") and row.get("type_name") != anchor.get("type_name"):
                continue
            if anchor.get("method_name") and row.get("method_name") != anchor.get("method_name"):
                continue
            if expected_rva and _norm_address(str(row.get("rva", ""))) != expected_rva:
                continue
            expected_parameter_start = str(anchor.get("parameter_start", ""))
            if expected_parameter_start and str(row.get("parameter_start", "")) != expected_parameter_start:
                continue
            expected_parameter_count = str(anchor.get("parameter_count", ""))
            if expected_parameter_count and str(row.get("parameter_count", "")) != expected_parameter_count:
                continue
            params = [str(value) for value in row.get("parameter_types", [])]
            if expected_params and not all(value in params for value in expected_params):
                continue
            matches.append(row)
        checks.append({"kind": "method", "anchor": anchor, "passed": bool(matches), "match_count": len(matches)})

    failed = [check for check in checks if not check["passed"]]
    return {
        "passed": not failed,
        "check_count": len(checks),
        "failed_count": len(failed),
        "checks": checks,
    }
