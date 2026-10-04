from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
META = ROOT / "versions/7.1.0-global/windows-x64/metadata"
OUT = ROOT / "quest351-keyword-sweep.json"

KEYWORDS = (
    "quest",
    "rewind",
    "tracking",
    "navigation",
    "navigate",
    "servercond",
    "born",
    "transmit",
    "backbutton",
    "paimon",
)


def hit(text: str) -> list[str]:
    folded = text.casefold()
    return [word for word in KEYWORDS if word in folded]


def main() -> None:
    type_hits: list[dict[str, object]] = []
    interesting_type_ids: set[int] = set()
    with (META / "types.csv").open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            hay = f"{row.get('namespace','')} {row.get('type_name','')}"
            words = hit(hay)
            if not words:
                continue
            idx = int(row["type_definition_index"])
            interesting_type_ids.add(idx)
            type_hits.append({
                "keywords": words,
                "type_definition_index": idx,
                "namespace": row.get("namespace", ""),
                "type_name": row.get("type_name", ""),
                "field_count": int(row.get("field_count") or 0),
                "method_count": int(row.get("method_count") or 0),
                "method_start": int(row.get("method_start") or -1),
            })

    method_hits: list[dict[str, object]] = []
    methods_by_interesting_type: dict[int, list[dict[str, object]]] = defaultdict(list)
    parameter_type_hits: list[dict[str, object]] = []
    with (META / "methods.csv").open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            owner_raw = row.get("type_definition_index", "")
            owner = int(owner_raw) if owner_raw else -1
            name = row.get("method_name", "")
            words = hit(name)
            params = json.loads(row.get("parameter_types") or "[]")
            param_words = sorted({w for p in params for w in hit(str(p))})
            item = {
                "method_index": int(row["method_index"]),
                "type_definition_index": owner,
                "type_name": row.get("type_name", ""),
                "method_name": name,
                "rva": row.get("rva", ""),
                "parameter_count": int(row.get("parameter_count") or 0),
                "parameter_types": params,
                "parameter_type_indices": json.loads(row.get("parameter_type_indices") or "[]"),
            }
            if words:
                item["keywords"] = words
                method_hits.append(item)
            if param_words:
                p = dict(item)
                p["keywords"] = param_words
                parameter_type_hits.append(p)
            if owner in interesting_type_ids:
                methods_by_interesting_type[owner].append(item)

    field_hits: list[dict[str, object]] = []
    with (META / "fields.csv").open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            words = sorted(set(hit(row.get("field_name", "")) + hit(row.get("field_type", ""))))
            if not words:
                continue
            field_hits.append({
                "keywords": words,
                "field_index": int(row["field_index"]),
                "type_definition_index": int(row["type_definition_index"]) if row.get("type_definition_index") else -1,
                "type_name": row.get("type_name", ""),
                "field_name": row.get("field_name", ""),
                "field_type": row.get("field_type", ""),
                "field_type_index": int(row["field_type_index"]) if row.get("field_type_index") else -1,
            })

    payload = {
        "keywords": KEYWORDS,
        "type_hits": type_hits,
        "method_name_hits": method_hits,
        "parameter_type_hits": parameter_type_hits,
        "field_hits": field_hits,
        "methods_for_semantic_type_hits": methods_by_interesting_type,
    }
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"type_hits={len(type_hits)} method_name_hits={len(method_hits)} parameter_type_hits={len(parameter_type_hits)} field_hits={len(field_hits)}")
    print("\nMETHOD NAME HITS")
    for row in method_hits[:400]:
        print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
    print("\nPARAMETER TYPE HITS")
    for row in parameter_type_hits[:300]:
        print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
    print("\nTYPE HITS")
    for row in type_hits[:300]:
        print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
    print("\nFIELD HITS")
    for row in field_hits[:300]:
        print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
