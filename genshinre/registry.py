from __future__ import annotations

import csv
from pathlib import Path

from .contracts import ANALYSIS_STATUSES
from .nativeprofile import PROFILE_71
from .rowutil import int_matches

EXPECTED_REGISTRY_ROW_COUNT = PROFILE_71.registry_row_count

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

ALLOWED_STATUS = {""} | ANALYSIS_STATUSES | {
    "runtime-verified",
    "static-verified",
    "static-verified-identity",
    "cross-project-supported",
    "observed-unresolved",
    "mapped-not-observed",
    "historical-only",
    "hypothesis",
}


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
            if not int_matches(row.get("cmd_id"), cmd_id):
                continue
            if needle and needle not in str(row.get("type_name", "")).casefold():
                continue
            if not int_matches(row.get("type_definition_index"), type_definition_index):
                continue
            if not int_matches(row.get("index"), registry_index):
                continue
            result.append(dict(row))
    return result
