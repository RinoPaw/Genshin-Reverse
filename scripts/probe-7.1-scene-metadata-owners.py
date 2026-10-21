#!/usr/bin/env python3
"""Narrow original 7.1 metadata inventory for SceneTag/SceneExcel row readers.

This reports metadata owner/type/field candidates, with no inferred source
field names. Native loader method indexes are established by original
opcode/row-header matches. Virtual call slot +0xF0 is indirect; selecting
which metadata method implements it requires further runtime/vtable
evidence and an exact row-payload consumption test.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

LOADERS = {
    "SceneTag": {"methodIndex": 696653, "rva": "0x14015460",
                 "nativeKeyFieldOffset": "0x28", "virtualDispatchByteOffset": "0xF0"},
    "SceneExcel": {"methodIndex": 279989, "rva": "0xA6C7000",
                   "nativeKeyFieldOffset": "0x50", "virtualDispatchByteOffset": "0xF0"},
}


def records(path: Path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        yield from csv.DictReader(f)


def inspect(types: Path, methods: Path, fields: Path) -> dict:
    owner_methods = {}
    owned_names = set()
    loader_rows = {}
    possible_readers = []
    # Native loader method metadata belongs to the table-owner type.
    for m in records(methods):
        if m["method_index"] in {"696653", "279989"}:
            label = "SceneTag" if m["method_index"] == "696653" else "SceneExcel"
            loader_rows[label] = dict(m)
            owned_names.add(m["type_name"])
        if m["method_name"] == "GMENPOPMKAA" and m["rva"]:
            possible_readers.append({
                "methodIndex": m["method_index"], "typeName": m["type_name"],
                "typeIndex": m["type_definition_index"], "rva": m["rva"],
                "parameterTypes": m.get("parameter_types", ""),
            })
    if set(loader_rows) != set(LOADERS):
        raise ValueError("Global 7.1 native Scene table loader metadata missing")
    for label, info in LOADERS.items():
        m = loader_rows[label]
        if int(m["rva"], 0) != int(info["rva"], 0):
            raise ValueError(f"{label} loader native RVA changed")
    for t in records(types):
        if t["type_name"] in owned_names:
            owner_methods[t["type_name"]] = {
                "typeIndex": t["type_definition_index"],
                "parentType": t.get("parent_type"),
                "fieldCount": t.get("field_count"),
                "methodCount": t.get("method_count"),
                "fieldStart": t.get("field_start"),
                "methodStart": t.get("method_start"),
                "namespace": t.get("namespace"),
            }
    owner_field_rows = defaultdict(list)
    for f in records(fields):
        if f["type_name"] in owned_names:
            owner_field_rows[f["type_name"]].append({
                "fieldName": f["field_name"], "fieldType": f.get("field_type"),
                "offset": f.get("offset"),
            })

    # Metadata-only candidate broadening is deliberately limited to a count
    # histogram. A method name or object key offset alone is not a vtable link.
    reader_types = Counter(x["typeName"] for x in possible_readers)
    loader_context = {}
    for label, m in loader_rows.items():
        owner = m["type_name"]
        loader_context[label] = {
            "loaderMetadata": m,
            "ownerType": owner_methods.get(owner),
            "ownerFields": owner_field_rows.get(owner, []),
            "virtualReaderMethodNameCandidate": "GMENPOPMKAA",
            "virtualReaderFieldOwnerUnverified": True,
        }
    return {
        "schemaVersion": 1,
        "status": "PINNED_7_1_SCENE_TABLE_OWNER_METADATA__VIRTUAL_ROW_READER_UNRESOLVED",
        "loaders": LOADERS,
        "loaderContext": loader_context,
        "sameObfuscatedMethodNameCount": len(possible_readers),
        "differentOwnersWithSameName": len(reader_types),
        "sameNameOwners": dict(sorted(reader_types.items())),
        "limits": [
            "All method and field names are recovered obfuscated original Global 7.1 metadata tokens.",
            "Manager class fields and methods are metadata identities only and do not establish table row type.",
            "Virtual call +0xF0 dispatches through the row object; manager owner and similar method names are not proof of the target.",
            "Runtime class pointer mapping or table-entry row-consumption confirmation is necessary before assigning SceneTag/SceneExcel field semantics.",
            "No original Scene Lua instance, chest drop_tag or server reward evidence is included.",
        ],
    }


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--types",required=True,type=Path)
    p.add_argument("--methods",required=True,type=Path)
    p.add_argument("--fields",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    args=p.parse_args()
    report=inspect(args.types,args.methods,args.fields)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({
        "status":report["status"],
        "ownerClasses":list(report["loaderContext"]),
        "readerNameMatches":report["sameObfuscatedMethodNameCount"],
        "distinctReaderOwners":report["differentOwnersWithSameName"],
        "loaderOwners":{name:x["loaderMetadata"]["type_name"]
                        for name,x in report["loaderContext"].items()},
    },indent=2))


if __name__=="__main__":
    main()
