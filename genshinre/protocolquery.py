from __future__ import annotations

import csv
import json
from pathlib import Path

from .metadata import query_fields, query_methods
from .registry import query_registry

_XREF_FILES = {
    "handlers": "message-handlers.csv",
    "senders": "message-senders.csv",
    "constructors": "message-constructors.csv",
}


def _row_int(row: dict[str, object], key: str) -> int | None:
    text = str(row.get(key, "")).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _matching_csv_rows(path: Path, cmd_id: int, type_name: str) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    result: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            row_cmd = _row_int(row, "cmd_id")
            row_type = str(row.get("type_name", "")).strip()
            if row_cmd == cmd_id or (row_type and row_type == type_name):
                result.append(dict(row))
    return result


def _known_opcode_rows(path: Path, cmd_id: int) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    result: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if _row_int(row, "cmd_id") == cmd_id:
                result.append(dict(row))
    return result


def _message_shapes(path: Path, cmd_id: int) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []
    result: list[dict[str, object]] = []
    for semantic_name, shape in data.items():
        if not isinstance(shape, dict) or shape.get("cmd_id") != cmd_id:
            continue
        result.append({"semantic_name": semantic_name, **shape})
    return result


def query_protocol(
    version_dir: Path,
    *,
    cmd_id: int | None = None,
    type_name: str | None = None,
    type_definition_index: int | None = None,
    registry_index: int | None = None,
) -> dict[str, object]:
    """Join published protocol evidence around one or more registry identities.

    This is an evidence aggregator only. It intentionally does not infer semantic
    names, parser roles, field meanings, or packet direction beyond what published
    artifacts already state.
    """

    registry_path = version_dir / "registry" / "registry.csv"
    registry_rows = query_registry(
        registry_path,
        cmd_id=cmd_id,
        type_name=type_name,
        type_definition_index=type_definition_index,
        registry_index=registry_index,
    )

    results: list[dict[str, object]] = []
    for registry in registry_rows:
        identity_cmd = _row_int(registry, "cmd_id")
        identity_tdef = _row_int(registry, "type_definition_index")
        identity_type = str(registry.get("type_name", "")).strip()
        if identity_cmd is None:
            continue

        methods_path = version_dir / "metadata" / "methods.csv"
        fields_path = version_dir / "metadata" / "fields.csv"
        methods = (
            query_methods(methods_path, type_definition_index=identity_tdef)
            if methods_path.is_file() and identity_tdef is not None
            else []
        )
        fields = (
            query_fields(fields_path, type_definition_index=identity_tdef)
            if fields_path.is_file() and identity_tdef is not None
            else []
        )

        xrefs = {
            label: _matching_csv_rows(version_dir / "xrefs" / filename, identity_cmd, identity_type)
            for label, filename in _XREF_FILES.items()
        }
        observations = _matching_csv_rows(
            version_dir / "cmdids" / "observations.csv",
            identity_cmd,
            identity_type,
        )
        known_opcodes = _known_opcode_rows(
            version_dir / "proto" / "known-opcodes.csv",
            identity_cmd,
        )
        shapes = _message_shapes(version_dir / "proto" / "message-shapes.json", identity_cmd)

        results.append(
            {
                "registry": registry,
                "metadata": {
                    "fields": fields,
                    "methods": methods,
                },
                "xrefs": xrefs,
                "runtime_observations": observations,
                "known_opcodes": known_opcodes,
                "message_shapes": shapes,
                "counts": {
                    "fields": len(fields),
                    "methods": len(methods),
                    "handlers": len(xrefs["handlers"]),
                    "senders": len(xrefs["senders"]),
                    "constructors": len(xrefs["constructors"]),
                    "runtime_observations": len(observations),
                    "known_opcodes": len(known_opcodes),
                    "message_shapes": len(shapes),
                },
            }
        )

    return {
        "version_dir": str(version_dir),
        "query": {
            "cmd_id": cmd_id,
            "type_name": type_name,
            "type_definition_index": type_definition_index,
            "registry_index": registry_index,
        },
        "result_count": len(results),
        "results": results,
    }
