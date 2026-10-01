from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

CANONICAL_COLUMNS = (
    "cmd_id",
    "type_name",
    "type_definition_index",
    "type_cache_rva",
    "direction",
    "get_cmd_id_rva",
    "semantic_name",
    "status",
    "evidence",
    "notes",
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
    "cross-project-supported",
    "observed-unresolved",
    "mapped-not-observed",
    "historical-only",
    "hypothesis",
}

ALIASES = {
    "cmdid": "cmd_id",
    "cmd": "cmd_id",
    "type": "type_name",
    "typedef": "type_definition_index",
    "type_definition": "type_definition_index",
    "type_cache": "type_cache_rva",
    "get_cmd_id": "get_cmd_id_rva",
    "name": "semantic_name",
    "confidence": "status",
}


def _normalize_address(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    number = int(value, 0)
    if number < 0:
        raise ValueError(f"negative address: {value}")
    return f"0x{number:X}"


def _normalize_direction(value: str, direction_map: dict[str, str]) -> str:
    value = value.strip()
    mapped = direction_map.get(value, value)
    upper = mapped.upper()
    if upper in {"C2S", "S2C"}:
        return upper
    if mapped.lower() in {"unknown", ""}:
        return "unknown" if mapped else ""
    raise ValueError(f"unsupported direction: {value}")


def normalize_registry(
    input_csv: Path,
    output_dir: Path,
    direction_map: dict[str, str] | None = None,
    provenance: dict[str, object] | None = None,
) -> dict[str, object]:
    direction_map = direction_map or {}
    output_dir.mkdir(parents=True, exist_ok=True)

    with input_csv.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError("registry CSV has no header")
        rows = []
        for raw in reader:
            canonical: dict[str, str] = {key: "" for key in CANONICAL_COLUMNS}
            for key, value in raw.items():
                if key is None:
                    continue
                target = ALIASES.get(key.strip().lower(), key.strip().lower())
                if target in canonical:
                    canonical[target] = (value or "").strip()

            if not canonical["cmd_id"]:
                raise ValueError("registry row is missing cmd_id")
            cmd_id = int(canonical["cmd_id"], 0)
            if not 0 <= cmd_id <= 65535:
                raise ValueError(f"cmd_id out of range: {cmd_id}")
            canonical["cmd_id"] = str(cmd_id)

            if canonical["type_definition_index"]:
                canonical["type_definition_index"] = str(int(canonical["type_definition_index"], 0))
            canonical["type_cache_rva"] = _normalize_address(canonical["type_cache_rva"])
            canonical["get_cmd_id_rva"] = _normalize_address(canonical["get_cmd_id_rva"])
            canonical["direction"] = _normalize_direction(canonical["direction"], direction_map)
            if canonical["status"] not in ALLOWED_STATUS:
                raise ValueError(f"unsupported status: {canonical['status']}")
            rows.append(canonical)

    ids = [int(row["cmd_id"]) for row in rows]
    duplicates = sorted(cmd for cmd, count in Counter(ids).items() if count > 1)
    if duplicates:
        raise ValueError(f"duplicate cmd_id values: {duplicates[:20]}")

    rows.sort(key=lambda row: int(row["cmd_id"]))
    csv_path = output_dir / "registry.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CANONICAL_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    (output_dir / "registry.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    summary: dict[str, object] = {
        "row_count": len(rows),
        "unique_cmd_ids": len(ids),
        "cmd_id_min": min(ids) if ids else None,
        "cmd_id_max": max(ids) if ids else None,
        "direction_counts": dict(Counter(row["direction"] or "blank" for row in rows)),
        "status_counts": dict(Counter(row["status"] or "blank" for row in rows)),
        "missing_type_name": sum(not row["type_name"] for row in rows),
        "missing_type_definition_index": sum(not row["type_definition_index"] for row in rows),
        "missing_get_cmd_id_rva": sum(not row["get_cmd_id_rva"] for row in rows),
    }
    if provenance:
        summary["provenance"] = provenance
    (output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return summary


def query_registry(path: Path, cmd_id: int | None = None, type_name: str | None = None) -> list[dict[str, str]]:
    if (cmd_id is None) == (type_name is None):
        raise ValueError("provide exactly one of cmd_id or type_name")
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if cmd_id is not None:
        return [row for row in rows if row.get("cmd_id") == str(cmd_id)]
    needle = (type_name or "").casefold()
    return [row for row in rows if needle in row.get("type_name", "").casefold()]
