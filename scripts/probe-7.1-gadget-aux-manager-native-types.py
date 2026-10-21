#!/usr/bin/env python3
"""Original Global 7.1 Gadget auxiliary manager field and type-array evidence.

Inspect ONLY the exact pinned EXE and repository's original IL2CPP metadata.
The owner type metadata and their field types may reveal a generic manager
index or a direct native row-class identity. A genericinst low-32 datum is
not automatically a TypeDefinitionIndex, VA, or concrete virtual method.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256
from genshinre.typearray import ENTRY_SIZE, decode_type_entry, is_valid_type_entry

MANAGER_TYPES = {
    "GadgetPropExcelConfigData": (28984, "CLOHJDMMODM"),
    "GadgetInteractExcelConfigData": (28382, "GAMAJLKMDJO"),
}
METHODS_GIT_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
MAX_FIELDS_PER_MANAGER = 128
STATIC_SLOTS = {"GadgetPropExcelConfigData": 0x57DAF50,
                "GadgetInteractExcelConfigData": 0x57FA548}


def git_blob(path: Path) -> str:
    h = hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1048576), b""):
            h.update(part)
    return h.hexdigest()


def get_manager_fields(path: Path) -> dict[str, list[dict]]:
    index = {str(spec[0]): name for name, spec in MANAGER_TYPES.items()}
    rows = {name: [] for name in MANAGER_TYPES}
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for field in csv.DictReader(stream):
            name = index.get(field.get("type_definition_index"))
            if name is None:
                continue
            if field["type_name"] != MANAGER_TYPES[name][1]:
                raise ValueError(f"{name}: original owner type label changed")
            rows[name].append({
                "fieldIndex": int(field["field_index"]),
                "fieldName": field["field_name"],
                "fieldTypeIndex": int(field["field_type_index"], 0),
                "metadataKindName": field["field_type"],
            })
            if len(rows[name]) > MAX_FIELDS_PER_MANAGER:
                raise ValueError(f"{name}: unbounded original manager fields")
    if any(not fields for fields in rows.values()):
        raise ValueError("original Gadget auxiliary manager has no field records")
    for fields in rows.values():
        if len({x["fieldIndex"] for x in fields}) != len(fields):
            raise ValueError("duplicate original manager field index")
    return rows


def decode_original_types(pe: PEImage, manager_fields: dict) -> dict:
    orig = pe.read_rva(PROFILE_71.type_array_pointer_rva, 8)
    if len(orig) != 8:
        raise ValueError("original IL2CPP type-array pointer missing")
    base = int.from_bytes(orig, "little")
    if base < pe.image_base:
        raise ValueError("original IL2CPP type-array VA invalid")
    type_array_rva = base - pe.image_base
    anchor = pe.read_rva(type_array_rva + PROFILE_71.runtime_type_anchor.type_index * ENTRY_SIZE, ENTRY_SIZE)
    if not is_valid_type_entry(anchor) or (
        decode_type_entry(anchor)["data_u32"] != PROFILE_71.runtime_type_anchor.type_definition_index
        or decode_type_entry(anchor)["kind"] != PROFILE_71.runtime_type_anchor.kind):
        raise ValueError("original 7.1 native type-array identity anchor mismatch")
    result = {}
    for name, fields in manager_fields.items():
        typed = []
        for row in fields:
            typ = row["fieldTypeIndex"]
            if not 0 <= typ < PROFILE_71.runtime_type_count:
                raise ValueError(f"{name}: field type index out of native array")
            entry = pe.read_rva(type_array_rva + typ*ENTRY_SIZE, ENTRY_SIZE)
            if not is_valid_type_entry(entry):
                raise ValueError(f"{name}: invalid original native field Il2CppType entry")
            decoded = decode_type_entry(entry)
            data = int(decoded["data_u32"])
            type_def = data if decoded["kind"] in (0x11, 0x12) else None
            typed.append({
                **row,
                "nativeTypeEntry": entry.hex(),
                "nativeTypeKind": f"0x{decoded['kind']:02X}",
                "nativeTypeKindName": decoded["kind_name"],
                "nativeTypeDataLow32": f"0x{data:X}",
                "classOrValueTypeDefinitionIndex": type_def,
                "genericArgumentsResolved": False,
            })
        slot = STATIC_SLOTS[name]
        raw = pe.read_rva(slot, 8)
        result[name] = {
            "managerTypeDefinitionIndex": MANAGER_TYPES[name][0],
            "managerOriginalTypeName": MANAGER_TYPES[name][1],
            "nativeFieldCount": len(typed),
            "nativeFields": typed,
            "originalRowTypeInfoSlotRva": f"0x{slot:X}",
            "originalClassSlotEightBytesFileBacked": len(raw) == 8,
            "originalClassSlotFileBytesHex": raw.hex() if len(raw) == 8 else None,
            "runtimeRowClassResolved": False,
        }
    return result


def investigate(exe: Path, fields: Path, methods: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="Global 7.1 original EXE")
    if git_blob(methods) != METHODS_GIT_BLOB:
        raise ValueError("Global 7.1 native methods.csv Git blob changed")
    rows = get_manager_fields(fields)
    with PEImage(exe) as pe:
        decoded = decode_original_types(pe, rows)
    return {
        "schemaVersion": 1,
        "status": "ORIGINAL_7_1_GADGET_AUX_MANAGER_NATIVE_FIELDS__ROW_VTABLE_UNRESOLVED",
        "exeSha256": PROFILE_71.exe_sha256,
        "methodsGitBlob": METHODS_GIT_BLOB,
        "originalIl2CppTypeArrayRva": f"0x{PROFILE_71.type_array_pointer_rva:X}",
        "tables": decoded,
        "limitations": [
            "Native Il2CppType.kind is verified from exact original client bytes; genericinst raw payloads have no confirmed pointer/index mapping.",
            "The class static slot can be runtime-initialized; file-backed bytes alone cannot prove the runtime class or virtual function.",
            "Manager field generic arguments cannot be assigned the concrete row type without a verified metadata registration mapping.",
            "No loot selector type, chest grade, scene level, server reward or probabilities are inferred.",
        ],
    }


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe",type=Path,required=True)
    p.add_argument("--fields",type=Path,required=True)
    p.add_argument("--methods",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    value=investigate(a.exe,a.fields,a.methods)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(value,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps(value,indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
