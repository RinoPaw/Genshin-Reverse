#!/usr/bin/env python3
"""Bounded 7.1 IL2CPP *type-neighborhood* inventory near scene table managers.

Method/type metadata adjacency is a low-confidence search heuristic.
The SceneTag/SceneExcel concrete record classes and virtual slot +0xF0
are not inferred until a type pointer or exact object/read path links
them. This emits reproducible original metadata only, not player data.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

MANAGERS = {
    "SceneTag": {"index": 84296, "type": "EJCNENCJADF",
                 "loaderMethod": 696653},
    "SceneExcel": {"index": 35441, "type": "HPNMCGDJOJL",
                   "loaderMethod": 279989},
}
RADIUS = 25
READER_NAME = "GMENPOPMKAA"
READER_PARAM = "FNIAHJGHFAK"


def inspect(types: Path, methods: Path, fields: Path, *, radius: int=RADIUS) -> dict:
    if not 1 <= radius <= 50:
        raise ValueError("bounded metadata neighborhood radius required")
    target_indices = set()
    for item in MANAGERS.values():
        target_indices.update(range(item["index"]-radius, item["index"]+radius+1))
    found = {}
    with types.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            index = int(row["type_definition_index"])
            if index in target_indices:
                found[index] = {
                    "index": index,
                    "name": row["type_name"],
                    "parent": row.get("parent_type"),
                    "fieldCount": int(row["field_count"]),
                    "methodCount": int(row["method_count"]),
                    "fieldStart": int(row["field_start"]),
                    "methodStart": int(row["method_start"]),
                    "fields": [],
                    "methods": [],
                }
    for label, m in MANAGERS.items():
        if m["index"] not in found or found[m["index"]]["name"] != m["type"]:
            raise ValueError(f"{label} original type identity changed")
    with methods.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            index = int(row["type_definition_index"])
            if index in found:
                found[index]["methods"].append({
                    "methodIndex": int(row["method_index"]),
                    "name": row["method_name"],
                    "rva": row["rva"],
                    "parameters": row.get("parameter_types", ""),
                    "parameterCount": int(row.get("parameter_count") or 0),
                })
    with fields.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            index = int(row["type_definition_index"])
            if index in found:
                found[index]["fields"].append({
                    "name": row["field_name"],
                    "type": row.get("field_type"),
                    "offset": row.get("offset"),
                })
    result = {}
    for label, m in MANAGERS.items():
        center = m["index"]
        span = [found[i] for i in range(center-radius, center+radius+1)
                if i in found]
        candidate_methods = []
        for typ in span:
            for method in typ["methods"]:
                if method["name"] != READER_NAME:
                    continue
                # Exact JSON-encoded type list is used as a *filter* only.
                if method["parameters"] != json.dumps([READER_PARAM]):
                    continue
                candidate_methods.append({
                    "typeIndex": typ["index"],
                    "typeName": typ["name"],
                    "distanceFromManagerType": typ["index"]-center,
                    "fieldCount": typ["fieldCount"],
                    "methodCount": typ["methodCount"],
                    **method,
                })
        result[label] = {
            "managerIndex": center,
            "managerType": m["type"],
            "metadataNeighborhoodRadius": radius,
            "typesObserved": len(span),
            "sameMethodAndInputSignatureCandidates": candidate_methods,
            "neighborTypes": span,
        }
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_SCENE_MANAGER_TYPE_NEIGHBORS__VIRTUAL_ROW_CLASS_UNVERIFIED",
        "radius": radius,
        "tables": result,
        "limitations": [
            "Metadata adjacency is a search heuristic; it does not prove SceneTag or SceneExcel record class identity.",
            "The obfuscated GMENPOPMKAA method name and FNIAHJGHFAK parameter signature are common in the original client.",
            "A nearby type with a candidate method does not link its address to the class-static pointer at 0x57EA618/0x58113D0.",
            "Vtable slot +0xF0 has not been mapped to a concrete row reader, and original field schemas and record boundaries remain unverified.",
            "Client scene table names and metadata do not authenticate official server chest drop_tag or reward probabilities.",
        ],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--types", type=Path, required=True)
    p.add_argument("--methods", type=Path, required=True)
    p.add_argument("--fields", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    obj = inspect(args.types, args.methods, args.fields)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(obj, ensure_ascii=False, indent=2)+"\n",
                           encoding="utf-8")
    print(json.dumps({
        "status": obj["status"],
        "candidates": {
            name: [
                {k: c[k] for k in ("typeIndex", "typeName", "distanceFromManagerType",
                                    "fieldCount", "methodCount", "methodIndex", "rva")}
                for c in item["sameMethodAndInputSignatureCandidates"]
            ] for name, item in obj["tables"].items()
        },
    }, indent=2))


if __name__ == "__main__":
    main()
