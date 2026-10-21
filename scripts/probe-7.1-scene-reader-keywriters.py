#!/usr/bin/env python3
"""Search exact Global 7.1 row methods by *native key-write behavior*.

SceneTag and SceneExcel table loaders read each row's wrapped lookup key
at in-object offsets 0x28 and 0x50, respectively. Their unknown virtual
row reader likely invokes the confirmed native 0xBB16020 uint32 writer.
Filter all source-pinned direct calls by original method signature and
inspect *aligned post-call instructions* for a same-function field store.
A hit is a candidate, not vtable proof. An absent hit does not exclude
an indirect writer or a getter inherited from another row class.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from genshinre.callxref import scan_direct_call_xrefs
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

METHODS_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
WRITER = 0xBB16020
READER_PARAM = '["FNIAHJGHFAK"]'
ROW_METHOD_NAME = "GMENPOPMKAA"
KEY_OFFSETS = {"SceneTag": 0x28, "SceneExcel": 0x50}
MATCH = re.compile(r"^dword ptr \[(?:r(?:[a-z0-9]+))(?: \+ 0x([0-9a-f]+))?\], eax$")


def git_blob(path: Path) -> str:
    sha = hashlib.sha1()
    sha.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as inp:
        for block in iter(lambda: inp.read(1048576), b""):
            sha.update(block)
    return sha.hexdigest()


def classify_post_call(instructions: list[dict]) -> list[int]:
    offsets = []
    for ins in instructions:
        if ins["mnemonic"] != "mov":
            continue
        match = MATCH.fullmatch(ins["op_str"])
        if match:
            offsets.append(int(match.group(1) or "0", 16))
    return offsets


def run(exe: Path, methods: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="exact Global 7.1 EXE")
    if git_blob(methods) != METHODS_BLOB:
        raise ValueError("exact original 7.1 method metadata Git blob mismatch")
    calls = scan_direct_call_xrefs(
        exe, [WRITER], methods_csv=methods, window=0,
        max_method_body=0x10000)
    call_rows = calls["matches"][f"0x{WRITER:X}"]
    origin_control = 0
    possible = {}
    filtered_count = 0
    with PEImage(exe) as pe:
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        for hit in call_rows:
            owners = hit.get("caller_methods", [])
            if any(owner.get("method_index") == "395933"
                   for owner in owners):
                origin_control += 1
            selected = [owner for owner in owners
                        if owner.get("method_name") == ROW_METHOD_NAME
                        and owner.get("parameter_types") == READER_PARAM]
            if not selected:
                continue
            filtered_count += 1
            site = int(hit["instruction_rva"], 16)
            code = pe.read_rva(site + 5, 64)
            ins = [
                {"rva": f"0x{entry.address - pe.image_base:X}",
                 "mnemonic": entry.mnemonic, "op_str": entry.op_str}
                for entry in decoder.disasm(code, pe.image_base + site + 5)
            ]
            offsets = classify_post_call(ins)
            for owner in selected:
                idx = owner["method_index"]
                row = possible.setdefault(idx, {
                    "methodIndex": int(idx),
                    "typeName": owner["type_name"],
                    "typeDefinitionIndex": int(owner["type_definition_index"]),
                    "methodRva": owner["rva"],
                    "nativeCallSites": [],
                    "keyWriteOffsetsAfterWrapper": [],
                })
                row["nativeCallSites"].append({
                    "callRva": hit["instruction_rva"],
                    "followingInstructions": ins[:12],
                    "observedStoresToEaxFields": offsets,
                })
                row["keyWriteOffsetsAfterWrapper"].extend(offsets)
    if origin_control < 1:
        raise ValueError("pinned native inherited Gadget writer positive control missing")
    groups = {name: [] for name in KEY_OFFSETS}
    for row in possible.values():
        row["keyWriteOffsetsAfterWrapper"] = sorted(
            set(row["keyWriteOffsetsAfterWrapper"]))
        for name, key in KEY_OFFSETS.items():
            if key in row["keyWriteOffsetsAfterWrapper"]:
                groups[name].append(row)
    for rows in groups.values():
        rows.sort(key=lambda entry: entry["methodIndex"])
    if any(len(rows) > 1000 for rows in groups.values()):
        raise ValueError("unbounded native row key-writer candidate group")
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_ROW_KEY_WRAPPER_CALLSITE_CANDIDATES__VIRTUAL_DISPATCH_UNVERIFIED",
        "exeSha256": PROFILE_71.exe_sha256,
        "methodsGitBlob": METHODS_BLOB,
        "wrappedUint32WriterRva": f"0x{WRITER:X}",
        "directNativeWriterCalls": len(call_rows),
        "knownInheritedGadgetMethodCalls": origin_control,
        "sameReaderNameAndArgumentCalls": filtered_count,
        "sameSignatureMethodsWithWriterCalls": len(possible),
        "keyOffsetCandidates": {name: {
            "memoryOffset": f"0x{offset:X}",
            "methods": groups[name],
            "methodCount": len(groups[name]),
        } for name, offset in KEY_OFFSETS.items()},
        "limitations": [
            "Only exact E8 rel32 calls to the original u32 writer are considered; indirect or inlined conversions remain outside this probe.",
            "The method name and argument type are common; a post-call field store is an alignment-checked native clue, not verified ownership of class TypeInfo.",
            "Up to 64 post-call instruction bytes are inspected, which may include later branches; candidates require complete method disassembly.",
            "The exact class-global pointer slot to virtual row class/vtable+0xF0 is not yet linked to any candidate method.",
            "Historical SceneTag JSON names, scene group Lua drop_tag and server reward tables are not used to assign identities.",
        ],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, required=True)
    p.add_argument("--methods", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = run(a.exe, a.methods)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n",
                        encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "directNativeWriterCalls": result["directNativeWriterCalls"],
        "sameSignatureMethodsWithWriterCalls": result["sameSignatureMethodsWithWriterCalls"],
        "keyCandidateCounts": {
            k: v["methodCount"] for k,v in result["keyOffsetCandidates"].items()
        },
        "candidates": {
            k: [{"methodIndex": m["methodIndex"], "type": m["typeName"],
                 "rva": m["methodRva"]} for m in v["methods"][:35]]
            for k,v in result["keyOffsetCandidates"].items()
        },
    }, indent=2))


if __name__ == "__main__":
    main()
