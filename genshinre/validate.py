from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from .registry import ALLOWED_STATUS

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
HEXADDR = re.compile(r"^0x[0-9A-Fa-f]+$")

REGISTRY_REQUIRED_COLUMNS = (
    "cmd_id",
    "type_name",
    "type_definition_index",
    "direction",
    "get_cmd_id_rva",
    "semantic_name",
    "status",
    "evidence",
)
REGISTRY_SLOT_COLUMNS = ("type_cache_rva", "type_slot_rva")


def validate_version(path: Path, allow_partial: bool = False) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    hashes_path = path / "hashes.json"
    if not hashes_path.exists():
        errors.append("missing hashes.json")
    else:
        try:
            hashes = json.loads(hashes_path.read_text(encoding="utf-8"))
            for name, sample in hashes.get("samples", {}).items():
                sha = sample.get("sha256", "")
                if sha and not HEX64.fullmatch(sha):
                    errors.append(f"{name}: invalid sha256")
        except Exception as exc:
            errors.append(f"hashes.json: {exc}")

    registry_path = path / "registry" / "registry.csv"
    if registry_path.exists():
        try:
            with registry_path.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                fields = tuple(reader.fieldnames or ())
                missing = [column for column in REGISTRY_REQUIRED_COLUMNS if column not in fields]
                if missing:
                    errors.append(f"registry.csv missing columns: {', '.join(missing)}")

                slot_column = next((column for column in REGISTRY_SLOT_COLUMNS if column in fields), None)
                if slot_column is None:
                    errors.append(
                        "registry.csv missing type slot column: type_cache_rva or type_slot_rva"
                    )

                seen: set[int] = set()
                for line_no, row in enumerate(reader, start=2):
                    cmd = int(row["cmd_id"])
                    if not 0 <= cmd <= 65535:
                        errors.append(f"registry.csv:{line_no}: cmd_id out of range")
                    if cmd in seen:
                        errors.append(f"registry.csv:{line_no}: duplicate cmd_id {cmd}")
                    seen.add(cmd)
                    direction = row.get("direction", "")
                    if direction not in {"", "C2S", "S2C", "unknown"}:
                        errors.append(f"registry.csv:{line_no}: bad direction {direction}")
                    status = row.get("status", "")
                    if status not in ALLOWED_STATUS:
                        errors.append(f"registry.csv:{line_no}: bad status {status}")
                    address_columns = ["get_cmd_id_rva"]
                    if slot_column is not None:
                        address_columns.insert(0, slot_column)
                    for column in address_columns:
                        value = row.get(column, "")
                        if value and not HEXADDR.fullmatch(value):
                            errors.append(f"registry.csv:{line_no}: bad {column} {value}")
        except Exception as exc:
            errors.append(f"registry.csv: {exc}")
    elif allow_partial:
        warnings.append("registry/registry.csv is not generated yet")
    else:
        errors.append("missing registry/registry.csv")

    known_path = path / "proto" / "known-opcodes.csv"
    if not known_path.exists():
        (warnings if allow_partial else errors).append("missing proto/known-opcodes.csv")

    shapes_path = path / "proto" / "message-shapes.json"
    if shapes_path.exists():
        try:
            shapes = json.loads(shapes_path.read_text(encoding="utf-8"))
            if not isinstance(shapes, dict):
                errors.append("message-shapes.json must be an object")
        except Exception as exc:
            errors.append(f"message-shapes.json: {exc}")
    elif allow_partial:
        warnings.append("proto/message-shapes.json is not generated yet")
    else:
        errors.append("missing proto/message-shapes.json")

    for rel in ("metadata/types.csv", "metadata/methods.csv", "metadata/fields.csv", "xrefs/message-handlers.csv", "xrefs/message-senders.csv"):
        if not (path / rel).exists():
            warnings.append(f"pending high-value artifact: {rel}")

    return errors, warnings
