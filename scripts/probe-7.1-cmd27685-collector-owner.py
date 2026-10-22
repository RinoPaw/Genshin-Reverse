#!/usr/bin/env python3
"""Exact original 7.1 provenance for JLDCJCKHJEM's +0x28 keyed container.

The original OnAccept call passes RCX = [rdi+0x28] and EDX = the
KFOLLNPEMHH field2 value; an original native call target behaves as
a hash-map insertion. Resolve the declaring class fields/constructors
from the pinned original metadata, and inspect what initializes +0x28.
Native source provenance is mandatory; any gameplay-level label is unproven.
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

METHODS_SHA = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
FIELDS_SHA = "ae01d117f4d884e891a95d529a15302a68715b04"
ORIGINAL_TYPE = "JLDCJCKHJEM"
KNOWN_ONACCEPT = (190174, 0xFCDF5D0)
MAX_MEMBERS = 130
MAX_SOURCE_BYTES = 0x600
MATCHES_LIMIT = 50


def git_blob(path: Path) -> str:
    h = hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(methods: Path, fields: Path) -> dict:
    if git_blob(methods) != METHODS_SHA or git_blob(fields) != FIELDS_SHA:
        raise ValueError("original source metadata identity drift")
    members = {"methods": [], "fields": []}
    with methods.open(encoding="utf-8-sig", newline="") as source:
        for m in csv.DictReader(source):
            if m["type_name"] != ORIGINAL_TYPE:
                continue
            members["methods"].append({
                "methodIndex": int(m["method_index"]),
                "nativeMethodRva": m["rva"],
                "originalMethodName": m["method_name"],
                "typeDefinitionIndex": int(m["type_definition_index"]),
                "originalParameterTypes": m.get("parameter_types",""),
            })
            if len(members["methods"]) > MAX_MEMBERS:
                raise ValueError("too many owner methods")
    with fields.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            if row["type_name"] != ORIGINAL_TYPE:
                continue
            members["fields"].append({
                "fieldIndex": int(row["field_index"]),
                "originalFieldName": row["field_name"],
                "fieldTypeName": row["field_type"],
                "fieldRuntimeTypeIndex": int(row["field_type_index"]),
                "typeDefinitionIndex": int(row["type_definition_index"]),
            })
            if len(members["fields"]) > MAX_MEMBERS:
                raise ValueError("too many owner fields")
    known = [m for m in members["methods"] if m["methodIndex"] == KNOWN_ONACCEPT[0]]
    if len(known) != 1 or int(known[0]["nativeMethodRva"], 16) != KNOWN_ONACCEPT[1]:
        raise ValueError("original OnAccept class owner not pinned")
    type_indices = {m["typeDefinitionIndex"] for m in members["methods"]}
    if len(type_indices) != 1:
        raise ValueError("original OnAccept owner type definition index mismatch")
    if any(f["typeDefinitionIndex"] not in type_indices for f in members["fields"]):
        raise ValueError("original OnAccept declared field owner mismatch")
    members["ownerTypeDefinitionIndex"] = type_indices.pop()
    return members


def disasm_ctor(exe: Path, methods: list[dict]) -> dict:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    chosen = [m for m in methods if m["originalMethodName"] in (".ctor", ".cctor", "Handle")]
    if len(chosen) > 12:
        raise ValueError("too many original constructor candidates")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    result = {}
    with PEImage(exe) as pe:
        for m in chosen:
            rva = int(m["nativeMethodRva"] or "0", 16)
            if rva <= 0:
                continue
            window = 0x180 if m["originalMethodName"] == "Handle" else 0x220
            data = pe.read_rva(rva, window)
            if len(data) != window:
                raise ValueError("cannot read original constructor method bytes")
            lines = []
            for ins in md.disasm(data, pe.image_base + rva):
                lines.append({
                    "rva": f"0x{ins.address - pe.image_base:X}",
                    "mnemonic": ins.mnemonic,
                    "operands": ins.op_str,
                    "hex": bytes(ins.bytes).hex(),
                })
                if len(lines) >= 280:
                    break
            writes = [row for row in lines if "+ 0x28]" in row["operands"]]
            calls = [row for row in lines if row["mnemonic"] == "call"]
            result[str(m["methodIndex"])] = {
                "originalCtorName": m["originalMethodName"],
                "originalMethodRva": f"0x{rva:X}",
                "boundedBytesSha256": hashlib.sha256(data).hexdigest(),
                "instructionsDecoded": len(lines),
                "completeConstructorControlFlowProven": False,\n                "fullBoundedWindowDecodedAfterEarlyRet": True,
                "objectOffset28InstructionSamples": writes[:MATCHES_LIMIT],
                "directOrVirtualCalls": calls[:MATCHES_LIMIT],
                "firstInstructions": lines[:35],
            }
    return result


def inspect(exe: Path, methods: Path, fields: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="original 7.1 EXE")
    owner = collect(methods, fields)
    return {
        "schemaVersion": 1,
        "status": "EXACT_71_CMD27685_COLLECTOR_OWNER_AND_CTOR__FIELD2_GAMEPLAY_SEMANTICS_UNPROVEN",
        "originalExeSha256": PROFILE_71.exe_sha256,
        "originalMethodsGitBlob": METHODS_SHA,
        "originalFieldsGitBlob": FIELDS_SHA,
        "onAcceptOwner": owner,
        "nativeConstructors": disasm_ctor(exe, owner["methods"]),
        "previousVerifiedNativeCall": {
            "from": "0xFCDF6BE", "to": "0x184EE960",
            "firstArgSource": "JLDCJCKHJEM instance +0x28",
            "secondArgSource": "KFOLLNPEMHH instance +0x98, protobuf field2",
            "thirdAndFourthNativeArgValues": [0, 1],
        },
        "limitations": [
            "Original class field metadata supplies type identities; without independently recovered offsets it does not map any arbitrary named field to object +0x28.",
            "Bounded native constructor disassemblies and helper code cannot name a container's generic arguments without a registration proof.",
            "A hash key in this original path is not a verified entity ID, chest level, scene level or reward grade.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, required=True)
    p.add_argument("--methods", type=Path, required=True)
    p.add_argument("--fields", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    obj = inspect(a.exe, a.methods, a.fields)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": obj["status"],
        "ownerFields": obj["onAcceptOwner"]["fields"],
        "ownerMethods": obj["onAcceptOwner"]["methods"],
        "constructorEvidence": obj["nativeConstructors"],
    }, indent=2))


if __name__ == "__main__":
    main()
