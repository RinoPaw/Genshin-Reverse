from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
META = ROOT / "versions/7.1.0-global/windows-x64/metadata"
OUT = ROOT / "quest351-target-types.json"

# 61791 dominates current 7.1 methods that directly accept QuestProxy and is
# therefore the strongest QuestModule-shaped candidate. 64147 owns the in-level
# return-button refresh path. 71905 is the named UserLocalDataItem containing
# trackingMainQuestIDList and navigation state, useful for finding the local
# persistence side of ResetTrackingLocalData.
TARGETS = {
    20622,
    37197,
    61791,
    64147,
    67347,
    67518,
    62829,
    71905,
    73130,
    74397,
    83901,
}


def main() -> None:
    types: dict[int, dict[str, object]] = {}
    with (META / "types.csv").open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            idx = int(row["type_definition_index"])
            if idx in TARGETS:
                types[idx] = dict(row)

    fields: dict[int, list[dict[str, object]]] = {idx: [] for idx in TARGETS}
    with (META / "fields.csv").open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            raw = row.get("type_definition_index", "")
            if not raw:
                continue
            idx = int(raw)
            if idx not in TARGETS:
                continue
            fields[idx].append(
                {
                    "field_index": int(row["field_index"]),
                    "field_name": row.get("field_name", ""),
                    "field_type": row.get("field_type", ""),
                    "field_type_index": int(row["field_type_index"]) if row.get("field_type_index") else -1,
                    "offset": row.get("offset", ""),
                }
            )

    methods: dict[int, list[dict[str, object]]] = {idx: [] for idx in TARGETS}
    with (META / "methods.csv").open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            raw = row.get("type_definition_index", "")
            if not raw:
                continue
            idx = int(raw)
            if idx not in TARGETS:
                continue
            methods[idx].append(
                {
                    "method_index": int(row["method_index"]),
                    "method_name": row.get("method_name", ""),
                    "rva": row.get("rva", ""),
                    "parameter_count": int(row.get("parameter_count") or 0),
                    "parameter_types": json.loads(row.get("parameter_types") or "[]"),
                    "parameter_type_indices": json.loads(row.get("parameter_type_indices") or "[]"),
                }
            )

    payload = {
        str(idx): {
            "type": types.get(idx),
            "fields": fields.get(idx, []),
            "methods": methods.get(idx, []),
        }
        for idx in sorted(TARGETS)
    }
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    for idx in sorted(TARGETS):
        t = types.get(idx, {})
        print(f"=== type {idx} {t.get('type_name')} fields={t.get('field_count')} methods={t.get('method_count')} ===")
        print("FIELDS")
        for field in fields.get(idx, []):
            print(json.dumps(field, ensure_ascii=False, separators=(",", ":")))
        print("METHODS")
        for method in methods.get(idx, []):
            print(json.dumps(method, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
