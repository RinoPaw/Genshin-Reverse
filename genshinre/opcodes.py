from __future__ import annotations

import csv
import json
import re
from pathlib import Path

OPCODE_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+)\s*;")


def import_java_opcodes(java_file: Path, output_csv: Path) -> int:
    rows = []
    seen: set[int] = set()
    text = java_file.read_text(encoding="utf-8", errors="replace")
    for name, raw_value in OPCODE_RE.findall(text):
        value = int(raw_value)
        if value <= 0 or value > 65535 or value in seen:
            continue
        seen.add(value)
        rows.append(
            {
                "semantic_name": name,
                "cmd_id": str(value),
                "direction": "",
                "status": "mapped-not-observed",
                "evidence": java_file.name,
                "notes": "imported control-set mapping; target-client verification still required",
            }
        )
    rows.sort(key=lambda row: int(row["cmd_id"]))
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=("semantic_name", "cmd_id", "direction", "status", "evidence", "notes"))
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def crosscheck_registry(registry_csv: Path, known_opcodes_csv: Path) -> dict[str, object]:
    with registry_csv.open("r", encoding="utf-8-sig", newline="") as f:
        registry_rows = list(csv.DictReader(f))
    with known_opcodes_csv.open("r", encoding="utf-8-sig", newline="") as f:
        known_rows = list(csv.DictReader(f))
    registry_ids = {int(row["cmd_id"]) for row in registry_rows if row.get("cmd_id")}
    known_ids = {int(row["cmd_id"]) for row in known_rows if row.get("cmd_id") and int(row["cmd_id"]) > 0}
    missing = sorted(known_ids - registry_ids)
    return {
        "registry_unique_cmd_ids": len(registry_ids),
        "control_set_unique_cmd_ids": len(known_ids),
        "matched": len(known_ids) - len(missing),
        "missing_count": len(missing),
        "missing_cmd_ids": missing,
        "all_control_ids_present": not missing,
    }


def write_crosscheck(result: dict[str, object], output_json: Path) -> None:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
