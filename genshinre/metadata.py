from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from .metadataindex import build_type_methods
from .rowutil import int_matches


def _parse_params(value: str) -> list[str]:
    value = (value or "").strip()
    if not value:
        return []
    parsed = json.loads(value)
    if not isinstance(parsed, list):
        raise ValueError("parameter_types must be a JSON array")
    return [str(item) for item in parsed]


def _type_token_matches(value: object, type_name: str) -> bool:
    text = str(value or "")
    if not text:
        return False
    if text.casefold() == type_name.casefold():
        return True
    pattern = rf"(?<![A-Za-z0-9_]){re.escape(type_name)}(?![A-Za-z0-9_])"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def load_methods(methods_csv: Path) -> list[dict[str, object]]:
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        rows = []
        for raw in csv.DictReader(f):
            row: dict[str, object] = dict(raw)
            row["parameter_types"] = _parse_params(raw.get("parameter_types", ""))
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

    result: list[dict[str, object]] = []
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for raw in csv.DictReader(f):
            if type_name and type_name.casefold() not in str(raw.get("type_name", "")).casefold():
                continue
            if not int_matches(raw.get("type_definition_index"), type_definition_index):
                continue
            if not int_matches(raw.get("rva"), rva):
                continue
            if method_name and method_name.casefold() not in str(raw.get("method_name", "")).casefold():
                continue

            params = _parse_params(raw.get("parameter_types", ""))
            if parameter_type and parameter_type.casefold() not in {item.casefold() for item in params}:
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
    """Stream methods whose decoded signature references an exact metadata type.

    Parameter types use exact case-insensitive equality. Return types also allow
    a delimited occurrence so generic/rendered signatures can retain the target
    type without permitting ordinary identifier-substring false positives.
    """

    referenced_type = referenced_type.strip()
    if not referenced_type:
        raise ValueError("referenced_type must not be empty")

    result: list[dict[str, object]] = []
    with methods_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for raw in csv.DictReader(f):
            declaring_type = str(raw.get("type_name", "")).strip()
            is_self = declaring_type.casefold() == referenced_type.casefold()
            if external_only and is_self:
                continue

            params = _parse_params(raw.get("parameter_types", ""))
            parameter_positions = [
                index
                for index, item in enumerate(params)
                if item.casefold() == referenced_type.casefold()
            ]
            return_type = str(raw.get("return_type", ""))
            match_return = _type_token_matches(return_type, referenced_type)
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

    result: list[dict[str, str]] = []
    with fields_csv.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if type_name and type_name.casefold() not in str(row.get("type_name", "")).casefold():
                continue
            if not int_matches(row.get("type_definition_index"), type_definition_index):
                continue
            if field_name and field_name.casefold() not in str(row.get("field_name", "")).casefold():
                continue
            if field_type and field_type.casefold() != str(row.get("field_type", "")).casefold():
                continue
            if not int_matches(row.get("field_type_index"), field_type_index):
                continue
            result.append(dict(row))
    return result
