from __future__ import annotations

import csv
import json
from pathlib import Path

from .metadatacsv import parse_parameter_types


def _norm_address(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    return f"0x{int(value, 0):X}"


def _type_matches(row: dict[str, str], anchor: dict[str, object]) -> bool:
    if anchor.get("type_name") and row.get("type_name") != anchor.get("type_name"):
        return False
    expected_index = str(anchor.get("type_definition_index", ""))
    if expected_index and row.get("type_definition_index") != expected_index:
        return False
    for key in ("field_start", "field_count", "method_start", "method_count"):
        expected = str(anchor.get(key, ""))
        if expected and row.get(key) != expected:
            return False
    return True


def _field_matches(row: dict[str, str], anchor: dict[str, object]) -> bool:
    for key in ("field_index", "type_definition_index", "field_type_index"):
        expected = str(anchor.get(key, ""))
        if expected and row.get(key) != expected:
            return False
    for key in ("type_name", "field_name", "field_type"):
        expected = str(anchor.get(key, ""))
        if expected and row.get(key) != expected:
            return False
    return True


def _method_matches(row: dict[str, str], anchor: dict[str, object]) -> bool:
    expected_index = str(anchor.get("method_index", ""))
    if expected_index and str(row.get("method_index", "")) != expected_index:
        return False
    expected_owner = str(anchor.get("type_definition_index", ""))
    if expected_owner and str(row.get("type_definition_index", "")) != expected_owner:
        return False
    if anchor.get("type_name") and row.get("type_name") != anchor.get("type_name"):
        return False
    if anchor.get("method_name") and row.get("method_name") != anchor.get("method_name"):
        return False

    expected_rva = _norm_address(str(anchor.get("rva", "")))
    if expected_rva and _norm_address(str(row.get("rva", ""))) != expected_rva:
        return False

    for key in ("parameter_start", "parameter_count"):
        expected = str(anchor.get(key, ""))
        if expected and str(row.get(key, "")) != expected:
            return False

    expected_params = [str(value) for value in anchor.get("parameter_types", [])]
    if expected_params:
        params = parse_parameter_types(row.get("parameter_types", ""))
        if not all(value in params for value in expected_params):
            return False
    return True


def _count_matches(
    path: Path,
    anchors: list[dict[str, object]],
    matcher,
) -> list[int]:
    counts = [0] * len(anchors)
    if not anchors:
        return counts
    if not path.is_file():
        raise ValueError(f"required metadata anchor table is missing: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            for index, anchor in enumerate(anchors):
                if matcher(row, anchor):
                    counts[index] += 1
    return counts


def _checks(
    kind: str,
    anchors: list[dict[str, object]],
    counts: list[int],
) -> list[dict[str, object]]:
    return [
        {
            "kind": kind,
            "anchor": anchor,
            "passed": count > 0,
            "match_count": count,
        }
        for anchor, count in zip(anchors, counts, strict=True)
    ]


def verify_metadata_anchors(metadata_dir: Path, anchors_json: Path) -> dict[str, object]:
    anchors = json.loads(anchors_json.read_text(encoding="utf-8"))
    if not isinstance(anchors, dict):
        raise ValueError("metadata anchors root must be an object")
    type_anchors = list(anchors.get("types", []))
    field_anchors = list(anchors.get("fields", []))
    method_anchors = list(anchors.get("methods", []))

    checks: list[dict[str, object]] = []
    checks.extend(
        _checks(
            "type",
            type_anchors,
            _count_matches(metadata_dir / "types.csv", type_anchors, _type_matches),
        )
    )
    checks.extend(
        _checks(
            "field",
            field_anchors,
            _count_matches(metadata_dir / "fields.csv", field_anchors, _field_matches),
        )
    )
    checks.extend(
        _checks(
            "method",
            method_anchors,
            _count_matches(metadata_dir / "methods.csv", method_anchors, _method_matches),
        )
    )

    failed = [check for check in checks if not check["passed"]]
    return {
        "passed": not failed,
        "check_count": len(checks),
        "failed_count": len(failed),
        "checks": checks,
    }
