from __future__ import annotations

import csv
import re
from pathlib import Path

from .metadatacsv import parse_parameter_types
from .rowutil import int_matches


def _type_token_pattern(type_name: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?<![A-Za-z0-9_]){re.escape(type_name)}(?![A-Za-z0-9_])",
        flags=re.IGNORECASE,
    )


def load_methods(methods_csv: Path) -> list[dict[str, object]]:
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        rows = []
        for raw in csv.DictReader(f):
            row: dict[str, object] = dict(raw)
            row["parameter_types"] = parse_parameter_types(raw.get("parameter_types", ""))
            rows.append(row)
        return rows


def query_methods(
    methods_csv: Path,
    type_name: str | None = None,
    parameter_type: str | None = None,
    method_name: str | None = None,
    type_definition_index: int | None = None,
    rva: int | None = None,
) -> list[dict[str, object]]:
    """Stream-filter a methods CSV without materializing the full metadata table."""

    type_needle = type_name.casefold() if type_name else None
    parameter_needle = parameter_type.casefold() if parameter_type else None
    method_needle = method_name.casefold() if method_name else None

    result: list[dict[str, object]] = []
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for raw in csv.DictReader(f):
            if type_needle and type_needle not in str(raw.get("type_name", "")).casefold():
                continue
            if not int_matches(raw.get("type_definition_index"), type_definition_index):
                continue
            if not int_matches(raw.get("rva"), rva):
                continue
            if method_needle and method_needle not in str(raw.get("method_name", "")).casefold():
                continue

            params = parse_parameter_types(raw.get("parameter_types", ""))
            if parameter_needle and not any(
                item.casefold() == parameter_needle for item in params
            ):
                continue

            row: dict[str, object] = dict(raw)
            row["parameter_types"] = params
            result.append(row)
    return result


def query_method_references(
    methods_csv: Path,
    referenced_type: str,
    *,
    external_only: bool = False,
) -> list[dict[str, object]]:
    """Stream methods whose decoded signature references an exact metadata type."""

    referenced_type = referenced_type.strip()
    if not referenced_type:
        raise ValueError("referenced_type must not be empty")

    referenced_fold = referenced_type.casefold()
    return_pattern = _type_token_pattern(referenced_type)

    result: list[dict[str, object]] = []
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for raw in csv.DictReader(f):
            declaring_type = str(raw.get("type_name", "")).strip()
            is_self = declaring_type.casefold() == referenced_fold
            if external_only and is_self:
                continue

            params = parse_parameter_types(raw.get("parameter_types", ""))
            parameter_positions = [
                index
                for index, item in enumerate(params)
                if item.casefold() == referenced_fold
            ]
            return_type = str(raw.get("return_type", ""))
            match_return = (
                return_type.casefold() == referenced_fold
                or return_pattern.search(return_type) is not None
            )
            if not parameter_positions and not match_return:
                continue

            row: dict[str, object] = dict(raw)
            row["parameter_types"] = params
            row["referenced_type"] = referenced_type
            row["self_type"] = is_self
            row["match_parameter"] = bool(parameter_positions)
            row["parameter_positions"] = parameter_positions
            row["match_return"] = match_return
            result.append(row)
    return result


def query_fields(
    fields_csv: Path,
    type_name: str | None = None,
    field_name: str | None = None,
    field_type: str | None = None,
    type_definition_index: int | None = None,
    field_type_index: int | None = None,
) -> list[dict[str, str]]:
    """Stream-filter a canonical metadata fields CSV."""

    type_needle = type_name.casefold() if type_name else None
    field_name_needle = field_name.casefold() if field_name else None
    field_type_needle = field_type.casefold() if field_type else None

    result: list[dict[str, str]] = []
    with fields_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if type_needle and type_needle not in str(row.get("type_name", "")).casefold():
                continue
            if not int_matches(row.get("type_definition_index"), type_definition_index):
                continue
            if field_name_needle and field_name_needle not in str(row.get("field_name", "")).casefold():
                continue
            if field_type_needle and field_type_needle != str(row.get("field_type", "")).casefold():
                continue
            if not int_matches(row.get("field_type_index"), field_type_index):
                continue
            result.append(dict(row))
    return result
