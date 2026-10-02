from __future__ import annotations

import csv
import re
from pathlib import Path

from .registry import ALLOWED_STATUS

HEXADDR = re.compile(r"^0x[0-9A-Fa-f]+$")
DIRECTIONS = {"", "C2S", "S2C", "unknown"}

XREF_TABLE_CONTRACTS: dict[str, dict[str, object]] = {
    "message-handlers.csv": {
        "columns": (
            "cmd_id",
            "type_name",
            "direction",
            "handler_type",
            "handler_method",
            "handler_rva",
            "status",
            "evidence",
            "context",
        ),
        "rva": "handler_rva",
        "direction": "direction",
    },
    "message-senders.csv": {
        "columns": (
            "cmd_id",
            "type_name",
            "sender_type",
            "sender_method",
            "sender_rva",
            "context",
            "status",
            "evidence",
        ),
        "rva": "sender_rva",
    },
    "message-constructors.csv": {
        "columns": (
            "cmd_id",
            "type_name",
            "constructor_rva",
            "context",
            "status",
            "evidence",
        ),
        "rva": "constructor_rva",
    },
}


def validate_xref_table(path: Path) -> list[str]:
    """Validate one maintained message-xref CSV without requiring resolved names."""

    errors: list[str] = []
    contract = XREF_TABLE_CONTRACTS.get(path.name)
    if contract is None:
        return [f"{path.name}: no maintained xref-table contract"]

    expected_columns = tuple(contract["columns"])
    rva_column = str(contract["rva"])
    direction_column = contract.get("direction")

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            actual_columns = tuple(reader.fieldnames or ())
            if actual_columns != expected_columns:
                errors.append(
                    f"{path.name}: header mismatch; expected {','.join(expected_columns)}; "
                    f"got {','.join(actual_columns)}"
                )
                return errors

            for line_no, row in enumerate(reader, start=2):
                prefix = f"{path.name}:{line_no}"
                try:
                    cmd_id = int(str(row.get("cmd_id", "")).strip(), 0)
                except ValueError:
                    errors.append(f"{prefix}: bad cmd_id {row.get('cmd_id', '')}")
                else:
                    if not 0 <= cmd_id <= 65535:
                        errors.append(f"{prefix}: cmd_id out of range {cmd_id}")

                rva = str(row.get(rva_column, "")).strip()
                if not rva or not HEXADDR.fullmatch(rva):
                    errors.append(f"{prefix}: bad {rva_column} {rva}")

                if direction_column is not None:
                    direction = str(row.get(str(direction_column), "")).strip()
                    if direction not in DIRECTIONS:
                        errors.append(f"{prefix}: bad direction {direction}")

                status = str(row.get("status", "")).strip()
                if status not in ALLOWED_STATUS:
                    errors.append(f"{prefix}: bad status {status}")

                for column in ("evidence", "context"):
                    value = str(row.get(column, "")).strip()
                    if not value:
                        errors.append(f"{prefix}: {column} must be non-empty")
    except Exception as exc:
        errors.append(f"{path.name}: {exc}")

    return errors


def validate_xref_directory(path: Path) -> list[str]:
    """Validate the currently maintained message handler/sender/constructor tables."""

    errors: list[str] = []
    for filename in XREF_TABLE_CONTRACTS:
        table = path / filename
        if not table.is_file():
            errors.append(f"missing {filename}")
            continue
        errors.extend(validate_xref_table(table))
    return errors
