#!/usr/bin/env python3
"""Trace original 7.1 SceneTag/SceneExcel manager generic field type pointers.

The exact original Global 7.1 IL2CPP metadata has two manager fields:
a kind_0x15 (genericinst) and a bool. The generic argument type may reveal
the *concrete* SceneTag / SceneExcel row type. This script does not assume
that a type-array data pointer is file-backed: it records the pointer,
attempts the standard IL2CPP generic-class/generic-inst layout only when
the expected pointer chain is readable, and explicitly preserves unknowns.

This is a candidate type-identity lead. No server Lua chest drop_tag or
reward table is inferred from the client manager's generic Dictionary.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256
from genshinre.typearray import decode_type_entry, ENTRY_SIZE

OWNERS = {
    "SceneTagConfigData": (84296, "EJCNENCJADF"),
    "SceneExcelConfigData": (35441, "HPNMCGDJOJL"),
}
FIELD_NAMES = ("PAAGPEHCJFI", "PBLMHNBIAJL")
MAX_ARGS = 4
MAX_READ = 0x50


def owner_fields(fields: Path) -> dict[str, list[dict]]:
    source = {}
    by_index = {str(index): name for name, (index, _) in OWNERS.items()}
    with fields.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            source_name = by_index.get(row.get("type_definition_index", ""))
            if source_name:
                source.setdefault(source_name, []).append(dict(row))
    for name, (_, original_owner) in OWNERS.items():
        rows = source.get(name, [])
        if len(rows) != 2 or {r["field_name"] for r in rows} != set(FIELD_NAMES):
            raise ValueError(f"unexpected exact 7.1 manager field identity {name}")
        if any(r["type_name"] != original_owner for r in rows):
            raise ValueError(f"unexpected exact 7.1 manager type owner {name}")
        generic = next(r for r in rows if r["field_name"] == FIELD_NAMES[0])
        if generic["field_type"] != "kind_0x15":
            raise ValueError(f"unexpected original generic manager field {name}")
    return source


def read_backed(pe: PEImage, va: int, count: int) -> bytes:
    if not (pe.image_base <= va and 0 < count <= MAX_READ):
        return b""
    data = pe.read_rva(va - pe.image_base, count)
    return data if len(data) == count else b""


def trace_pointer_chain(pe: PEImage, entry: bytes) -> dict:
    pointer_va = int.from_bytes(entry[:8], "little")
    out = {
        "rawTypeArrayEntryHex": entry.hex(),
        "genericClassDataVaCandidate": f"0x{pointer_va:X}",
        "genericClassDataFileBacked": False,
        "classContextFileBacked": False,
        "classGenericArgsFileBacked": False,
        "genericArgumentTypeIndexMapping": "UNVERIFIED",
        "genericArgumentTypes": [],
    }
    generic_class = read_backed(pe, pointer_va, 0x20)
    if not generic_class:
        return out
    out["genericClassDataFileBacked"] = True
    type_va = int.from_bytes(generic_class[0:8], "little")
    class_inst_va = int.from_bytes(generic_class[8:16], "little")
    out["genericClassTypeVaCandidate"] = f"0x{type_va:X}"
    out["classGenericInstVaCandidate"] = f"0x{class_inst_va:X}"
    context = read_backed(pe, class_inst_va, 0x10)
    if not context:
        return out
    out["classContextFileBacked"] = True
    count = int.from_bytes(context[:4], "little")
    arg_array_va = int.from_bytes(context[8:16], "little")
    out["classGenericArgCountCandidate"] = count
    out["classGenericArgPointerArrayVaCandidate"] = f"0x{arg_array_va:X}"
    if not 0 < count <= MAX_ARGS:
        return out
    args = read_backed(pe, arg_array_va, count*8)
    if not args:
        return out
    out["classGenericArgsFileBacked"] = True
    for pos in range(count):
        arg_type_va = int.from_bytes(args[pos*8:(pos+1)*8], "little")
        arg_entry = read_backed(pe, arg_type_va, ENTRY_SIZE)
        val = {
            "ordinal": pos, "typeVaCandidate": f"0x{arg_type_va:X}",
            "typeEntryFileBacked": bool(arg_entry),
        }
        if arg_entry:
            decoded = decode_type_entry(arg_entry)
            val["kind"] = f"0x{int(decoded['kind']):02X}"
            val["kindName"] = decoded["kind_name"]
            val["typeDataU32Candidate"] = decoded["data_u32"]
            val["rawTypeEntryHex"] = arg_entry.hex()
            if decoded["kind"] in (0x11, 0x12) and 0 <= int(decoded["data_u32"]) < PROFILE_71.type_definition_count:
                val["typeDefinitionIndexCandidate"] = decoded["data_u32"]
        out["genericArgumentTypes"].append(val)
    return out


def investigate(exe: Path, fields: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="exact Global 7.1 executable")
    original_fields = owner_fields(fields)
    with PEImage(exe) as pe:
        type_pointer = pe.read_rva(PROFILE_71.type_array_pointer_rva, 8)
        if len(type_pointer) != 8:
            raise ValueError("truncated original 7.1 runtime type-array pointer")
        type_array_va = int.from_bytes(type_pointer, "little")
        if not pe.rva_to_offset(type_array_va - pe.image_base):
            raise ValueError("original 7.1 runtime type-array pointer is not file backed")
        result = {}
        for name, (_, owner) in OWNERS.items():
            rows = original_fields[name]
            typed = []
            for row in rows:
                idx = int(row["field_type_index"], 0)
                if not 0 <= idx < PROFILE_71.runtime_type_count:
                    raise ValueError(f"{name} field type index outside exact 7.1 type array")
                entry = read_backed(pe, type_array_va + idx*ENTRY_SIZE, ENTRY_SIZE)
                if not entry:
                    raise ValueError(f"{name} runtime field Il2CppType entry not file backed")
                decoded = decode_type_entry(entry)
                typed.append({
                    "fieldName": row["field_name"],
                    "fieldTypeIndex": idx,
                    "metadataKind": row["field_type"],
                    "actualNativeKind": decoded["kind_name"],
                    "rawNativeTypeEntry": entry.hex(),
                    "genericClassPointerProbe": (
                        trace_pointer_chain(pe, entry) if decoded["kind"] == 0x15 else None
                    ),
                })
            gen = next(r for r in typed if r["fieldName"] == FIELD_NAMES[0])
            if gen["actualNativeKind"] != "genericinst":
                raise ValueError(f"{name} field type changed from genericinst")
            result[name] = {"ownerType": owner, "ownerTypeDefinitionIndex": OWNERS[name][0],
                            "fields": typed}
    return {
        "schemaVersion": 1,
        "status": "ORIGINAL_7_1_SCENE_MANAGER_GENERICINST_POINTER_CHAIN_CANDIDATES__VIRTUAL_ROW_UNVERIFIED",
        "exeSha256": PROFILE_71.exe_sha256,
        "source": "SHA-256-pinned exact 7.1 Global native Il2CppType array and metadata fields.csv",
        "managers": result,
        "limitations": [
            "The manager's genericinst field is a native metadata fact. Pointers in its raw Il2CppType entry may be unavailable in file-backed PE sections.",
            "Generic-class / generic-inst layout traversal is a hypothesis until a known-positive instance and original runtime type registration establish the structure.",
            "A readable generic argument candidate is not alone proof of a concrete virtual row reader at +0xF0.",
            "No scene placement, Scene Lua chest drop_tag, payout root or probability is authenticated.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fields", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = investigate(args.exe, args.fields)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n",
                           encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "managers": {name: [
            {"field": r["fieldName"], "typeIndex": r["fieldTypeIndex"],
             "kind": r["actualNativeKind"],
             "pointerProbe": r["genericClassPointerProbe"]}
            for r in m["fields"] if r["actualNativeKind"] == "genericinst"
        ] for name, m in report["managers"].items()},
    }, indent=2))


if __name__ == "__main__":
    main()
