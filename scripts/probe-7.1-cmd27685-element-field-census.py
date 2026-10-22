#!/usr/bin/env python3
"""Enumerate exact Global 7.1 obfuscated scene-entity packet element schema leads.

Both canonical metadata CSVs are derived from the SHA-256-pinned original
IL2CPP sample. The native reader window is independently checked against
the same original executable. A comparison immediate is a *candidate* wire
key until its enclosing branch and reader invocation have been verified.
No semantic fields are imported from an emulator or community .proto.
"""
from __future__ import annotations
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

METHODS_GIT_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
FIELDS_GIT_BLOB = "ae01d117f4d884e891a95d529a15302a68715b04"
TYPES = {
    85506: ("KFOLLNPEMHH", 27, 17),
    65670: ("KIIKIELOHOG", 4, 14),
    51277: ("CEOGMKOJDBL", 1, None),
}
NATIVE_READER_RVA = 0xB43A2A0
NATIVE_READER_SIZE = 0xCD0
KNOWN_TAG_CMP_RVA = 0xB43A328
KNOWN_TAG_CMP = ("cmp", "eax, 0x10")
KNOWN_VALUE_CALL_RVA = 0xB43A33D
KNOWN_VALUE_CALL = ("call", "0x1499a23f0")
KNOWN_FIELD_WRITE_RVA = 0xB43A342
KNOWN_FIELD_WRITE = ("mov", "dword ptr [r12 + 0x98], eax")


def git_blob(path: Path) -> str:
    h = hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as source:
        for part in iter(lambda: source.read(1 << 20), b""):
            h.update(part)
    return h.hexdigest()


def recover_members(methods: Path, fields: Path) -> dict:
    if git_blob(methods) != METHODS_GIT_BLOB or git_blob(fields) != FIELDS_GIT_BLOB:
        raise ValueError("not the exact original Global 7.1 generated metadata source")
    by_index = {index: {"owner": name, "fields": [], "methods": []}
                for index, (name, _, _) in TYPES.items()}
    with fields.open(encoding="utf-8-sig", newline="") as stream:
        for raw in csv.DictReader(stream):
            index = int(raw["type_definition_index"])
            if index not in by_index:
                continue
            result = by_index[index]
            if raw["type_name"] != result["owner"]:
                raise ValueError("native field owner changed")
            result["fields"].append({
                "originalFieldIndex": int(raw["field_index"]),
                "originalObfuscatedToken": raw["field_name"],
                "originalType": raw["field_type"],
                "originalRuntimeTypeIndex": int(raw["field_type_index"]),
            })
    with methods.open(encoding="utf-8-sig", newline="") as stream:
        for raw in csv.DictReader(stream):
            index = int(raw["type_definition_index"])
            if index not in by_index:
                continue
            result = by_index[index]
            if raw["type_name"] != result["owner"]:
                raise ValueError("native method owner changed")
            result["methods"].append({
                "originalMethodIndex": int(raw["method_index"]),
                "originalName": raw["method_name"],
                "originalRva": raw["rva"],
                "originalParameterTypes": raw.get("parameter_types", ""),
            })
    for index, (_, expected_fields, expected_methods) in TYPES.items():
        result = by_index[index]
        if len(result["fields"]) != expected_fields:
            raise ValueError(f"native {result['owner']} field count drift")
        if expected_methods is not None and len(result["methods"]) != expected_methods:
            raise ValueError(f"native {result['owner']} method count drift")
    if not any(m["originalMethodIndex"] == 705939
               and m["originalRva"].upper() == f"0X{NATIVE_READER_RVA:X}"
               and m["originalName"] == "NLGBJEEJDLG"
               for m in by_index[85506]["methods"]):
        raise ValueError("source-verified native element reader method missing")
    return by_index


def read_native(exe: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256,
                   label="original Global 7.1 client executable")
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    with PEImage(exe) as pe:
        src = pe.read_rva(NATIVE_READER_RVA, NATIVE_READER_SIZE)
        if len(src) != NATIVE_READER_SIZE:
            raise ValueError("native reader window not fully backed")
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoded = [
            {"rva": f"0x{ins.address - pe.image_base:X}",
             "mnemonic": ins.mnemonic, "operands": ins.op_str,
             "opcode": bytes(ins.bytes).hex()}
            for ins in decoder.disasm(src, pe.image_base + NATIVE_READER_RVA)
        ]
    lookup = {int(row["rva"], 16): row for row in decoded}
    if len(decoded) < 50 or len(lookup) != len(decoded):
        raise ValueError("insufficient original native decoder instructions")
    for rva, (mnemonic, operands) in (
        (KNOWN_TAG_CMP_RVA, KNOWN_TAG_CMP),
        (KNOWN_VALUE_CALL_RVA, KNOWN_VALUE_CALL),
        (KNOWN_FIELD_WRITE_RVA, KNOWN_FIELD_WRITE)
    ):
        row = lookup.get(rva)
        if row is None or (row["mnemonic"], row["operands"]) != (mnemonic, operands):
            raise ValueError(f"original reader scalar proof drift at RVA {rva:X}")
    candidates = []
    for i, row in enumerate(decoded):
        if row["mnemonic"] != "cmp":
            continue
        match = re.fullmatch(r"(?:eax|ecx|edx|ebx), (0x[0-9a-f]+|[0-9]+)",
                             row["operands"])
        if not match:
            continue
        value = int(match.group(1), 0)
        if not (0 < value <= 0xFFFFFFFF):
            continue
        entries = decoded[max(0, i-2):i+4]
        candidates.append({
            "rva": row["rva"],
            "immediate": value,
            "wireFieldNumberIfKey": value >> 3,
            "wireTypeIfKey": value & 7,
            "originalOpcode": row["opcode"],
            "context": entries,
            "provenOriginalWireKey": int(row["rva"], 16) == KNOWN_TAG_CMP_RVA,
        })
    return {
        "readerRva": f"0x{NATIVE_READER_RVA:X}",
        "readerMethodIndex": 705939,
        "readerWindowBytes": NATIVE_READER_SIZE,
        "readerWindowSha256": hashlib.sha256(src).hexdigest(),
        "disassembledInstructions": len(decoded),
        "verifiedNativeField2": {
            "protobufWireKey": "0x10",
            "fieldNumber": 2,
            "wireType": 0,
            "objectOffset": "0x98",
            "comparisonRva": f"0x{KNOWN_TAG_CMP_RVA:X}",
            "readerCallRva": f"0x{KNOWN_VALUE_CALL_RVA:X}",
            "storeRva": f"0x{KNOWN_FIELD_WRITE_RVA:X}",
            "nativeSemanticName": None,
        },
        "scalarComparisonCandidates": candidates,
    }


def investigate(exe: Path, methods: Path, fields: Path) -> dict:
    members = recover_members(methods, fields)
    native = read_native(exe)
    return {
        "schemaVersion": 1,
        "status": "ORIGINAL_GLOBAL_7_1_CMD27685_ELEMENT_NATIVE_FIELDS_AND_READER_COMPARISONS__PLACEMENT_OWNER_UNRESOLVED",
        "originalClient": PROFILE_71.identity,
        "originalExeSha256": PROFILE_71.exe_sha256,
        "originalMetadataSha256": PROFILE_71.metadata_sha256,
        "canonicalFieldsGitBlob": FIELDS_GIT_BLOB,
        "canonicalMethodsGitBlob": METHODS_GIT_BLOB,
        "elementTypeDefinitionIndex": 85506,
        "elementTypeObfuscatedName": "KFOLLNPEMHH",
        "metadata": {
            "elementFields": members[85506]["fields"],
            "elementMethods": members[85506]["methods"],
            "messageFields": members[65670]["fields"],
            "containerFields": members[51277]["fields"],
            "elementOriginalTypeHistogram":
                dict(sorted(Counter(x["originalType"]
                                    for x in members[85506]["fields"]).items())),
        },
        "originalNativeReader": native,
        "originalSceneChestPlacementSourceProven": False,
        "originalSceneLevelProven": False,
        "originalPacketDirectionProven": False,
        "limitations": [
            "All listed obfuscated field tokens and type labels derive from original Global 7.1 metadata; semantic names remain unresolved.",
            "Only native reader tag comparison 0x10, matched scalar call and field +0x98 store have independently verified protobuf semantics.",
            "All other native scalar comparisons are candidates. Some may be flags, lengths, other value checks or unrelated branches.",
            "A network message containing entity fields does not establish that static scene placements are absent from local client assets.",
            "No AstaPS Lua, public proto, LootCSS, community JSON or reward field was used to label the source.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", required=True, type=Path)
    p.add_argument("--methods", required=True, type=Path)
    p.add_argument("--fields", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    result = investigate(a.exe, a.methods, a.fields)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("ORIGINAL_CMD27685_ELEMENT_FIELDS_BEGIN")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("ORIGINAL_CMD27685_ELEMENT_FIELDS_END")


if __name__ == "__main__":
    main()
