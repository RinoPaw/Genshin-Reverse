from __future__ import annotations

import csv
from pathlib import Path

EXPECTED_REGISTRY_ROW_COUNT = 4_896

CANONICAL_REGISTRY_COLUMNS = (
    "index",
    "cmd_id",
    "type_name",
    "type_definition_index",
    "direction",
    "direction_status",
    "semantic_name",
    "type_slot_rva",
    "get_cmd_id_rva",
    "get_cmd_id_method",
    "load_rva",
    "store_rva",
    "xref_count",
    "xref_method_count",
    "status",
    "evidence",
)

ALLOWED_STATUS = {
    "",
    "CONFIRMED",
    "HIGH_CONFIDENCE",
    "CANDIDATE",
    "REJECTED",
    "UNRESOLVED",
    "runtime-verified",
    "static-verified",
    "static-verified-identity",
    "cross-project-supported",
    "observed-unresolved",
    "mapped-not-observed",
    "historical-only",
    "hypothesis",
}


def _row_int_equals(row: dict[str, str], key: str, expected: int | None) -> bool:
    if expected is None:
        return True
    text = str(row.get(key, "")).strip()
    if not text:
        return False
    try:
        return int(text, 0) == expected
    except ValueError:
        return False


def query_registry(
    path: Path,
    cmd_id: int | None = None,
    type_name: str | None = None,
    type_definition_index: int | None = None,
    registry_index: int | None = None,
) -> list[dict[str, str]]:
    """Stream-filter a canonical registry CSV using one or more identity fields."""

    if not any(
        (
            cmd_id is not None,
            type_name,
            type_definition_index is not None,
            registry_index is not None,
        )
    ):
        raise ValueError("provide at least one registry query filter")

    needle = type_name.casefold() if type_name else None
    result: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if not _row_int_equals(row, "cmd_id", cmd_id):
                continue
            if needle and needle not in str(row.get("type_name", "")).casefold():
                continue
            if not _row_int_equals(row, "type_definition_index", type_definition_index):
                continue
            if not _row_int_equals(row, "index", registry_index):
                continue
            result.append(dict(row))
    return result
