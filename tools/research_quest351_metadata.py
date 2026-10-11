from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
META = ROOT / "versions/7.1.0-global/windows-x64/metadata"
TYPES = META / "types.csv"
FIELDS = META / "fields.csv"
METHODS = META / "methods.csv"
OUT = ROOT / "quest351-metadata-candidates.json"

# Historical QuestModule (WorldReverse) has 55 declared fields.  The generic
# instances are intentionally unresolved by the canonical 7.1 decoder and show
# up as kind_0x15, but the primitive/constant slots remain a useful structural
# fingerprint.
HISTORICAL_FIELD_COUNT = 55
EXPECTED_PRIMITIVE_POSITIONS = {
    1: "bool",
    8: "int32",
    11: "bool",
    12: "bool",
    16: "int32",
    17: "int32",
    26: "bool",
    29: "bool",
    32: "string",
    33: "string",
    34: "string",
    35: "string",
    47: "bool",
    50: "bool",
    53: "uint32",
}
EXPECTED_COUNTS = {
    "bool": 7,
    "int32": 3,
    "string": 4,
    "uint32": 1,
}


def as_int(value: str) -> int:
    return int(value, 0) if value else 0


def load_types() -> dict[int, dict[str, str]]:
    result: dict[int, dict[str, str]] = {}
    with TYPES.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            idx = int(row["type_definition_index"])
            fc = int(row["field_count"])
            if 48 <= fc <= 62:
                result[idx] = dict(row)
    return result


def collect_fields(candidate_ids: set[int]) -> dict[int, list[dict[str, str]]]:
    result: dict[int, list[dict[str, str]]] = defaultdict(list)
    with FIELDS.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            raw = row.get("type_definition_index", "")
            if not raw:
                continue
            owner = int(raw)
            if owner in candidate_ids:
                result[owner].append(dict(row))
    return result


def score_fields(rows: list[dict[str, str]], declared_count: int) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if declared_count == HISTORICAL_FIELD_COUNT:
        score += 50
        reasons.append("field_count=55")
    else:
        score += max(0, 20 - abs(declared_count - HISTORICAL_FIELD_COUNT) * 4)

    field_types = [r.get("field_type", "") for r in rows]
    counts = Counter(field_types)
    for kind, expected in EXPECTED_COUNTS.items():
        delta = abs(counts.get(kind, 0) - expected)
        gain = max(0, 12 - delta * 4)
        score += gain
        if delta == 0:
            reasons.append(f"{kind}_count={expected}")

    positional_hits = 0
    for pos, expected in EXPECTED_PRIMITIVE_POSITIONS.items():
        if pos < len(field_types) and field_types[pos] == expected:
            positional_hits += 1
            score += 4 if expected == "string" else 2
    if positional_hits:
        reasons.append(f"primitive_position_hits={positional_hits}/{len(EXPECTED_PRIMITIVE_POSITIONS)}")

    for i in range(max(0, len(field_types) - 3)):
        if field_types[i : i + 4] == ["string"] * 4:
            score += 20
            reasons.append(f"four_consecutive_strings@{i}")
            break

    # Historical QuestModule has a dense generic-heavy layout.
    genericish = sum(1 for t in field_types if t.startswith("kind_0x"))
    if genericish >= 30:
        score += min(15, genericish - 29)
        reasons.append(f"genericish={genericish}")
    return score, reasons


def collect_methods(candidate_ids: set[int]) -> dict[int, list[dict[str, object]]]:
    result: dict[int, list[dict[str, object]]] = defaultdict(list)
    with METHODS.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            raw = row.get("type_definition_index", "")
            if not raw:
                continue
            owner = int(raw)
            if owner not in candidate_ids:
                continue
            params = json.loads(row.get("parameter_types") or "[]")
            result[owner].append(
                {
                    "method_index": int(row["method_index"]),
                    "method_name": row.get("method_name", ""),
                    "rva": row.get("rva", ""),
                    "parameter_count": int(row.get("parameter_count") or 0),
                    "parameter_types": params,
                    "parameter_type_indices": json.loads(row.get("parameter_type_indices") or "[]"),
                }
            )
    return result


def main() -> None:
    types = load_types()
    fields = collect_fields(set(types))
    ranked: list[dict[str, object]] = []
    for idx, type_row in types.items():
        rows = fields.get(idx, [])
        score, reasons = score_fields(rows, int(type_row["field_count"]))
        ranked.append(
            {
                "score": score,
                "type_definition_index": idx,
                "namespace": type_row.get("namespace", ""),
                "type_name": type_row.get("type_name", ""),
                "field_count": int(type_row["field_count"]),
                "method_count": int(type_row["method_count"]),
                "field_start": int(type_row["field_start"]),
                "method_start": int(type_row["method_start"]),
                "reasons": reasons,
                "fields": [
                    {
                        "field_index": int(r["field_index"]),
                        "field_name": r.get("field_name", ""),
                        "field_type": r.get("field_type", ""),
                        "field_type_index": as_int(r.get("field_type_index", "")),
                    }
                    for r in rows
                ],
            }
        )

    ranked.sort(key=lambda item: (-int(item["score"]), abs(int(item["field_count"]) - 55), int(item["type_definition_index"])))
    top = ranked[:20]
    methods = collect_methods({int(item["type_definition_index"]) for item in top[:8]})
    for item in top[:8]:
        item["methods"] = methods.get(int(item["type_definition_index"]), [])

    payload = {
        "historical_fingerprint": {
            "field_count": HISTORICAL_FIELD_COUNT,
            "expected_counts": EXPECTED_COUNTS,
            "primitive_positions_zero_based": EXPECTED_PRIMITIVE_POSITIONS,
        },
        "candidates": top,
    }
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("QuestModule structural candidates")
    for item in top[:12]:
        print(
            f"score={item['score']:3} type={item['type_definition_index']:5} "
            f"name={item['type_name']:<24} fields={item['field_count']:2} "
            f"methods={item['method_count']:3} reasons={';'.join(item['reasons'])}"
        )
        print("  field types:", ",".join(str(f["field_type"]) for f in item["fields"]))
        if "methods" in item:
            one_arg = [m for m in item["methods"] if int(m["parameter_count"]) == 1]
            print("  one-arg methods:")
            for method in one_arg[:40]:
                print(
                    f"    {method['method_index']} {method['method_name']} {method['rva']} "
                    f"params={method['parameter_types']} typeidx={method['parameter_type_indices']}"
                )


if __name__ == "__main__":
    main()
