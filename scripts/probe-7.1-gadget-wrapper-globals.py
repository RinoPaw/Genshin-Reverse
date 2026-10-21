#!/usr/bin/env python3
"""Locate source-pinned native Gadget u32 wrapper globals and their code xrefs.

Exact Global 7.1 executable, no runtime modification. The 64-bit pointer
at 0x57831E8 indexes IL2CPP statics at +0xF560, so its file-backed value is
NOT the dynamically allocated 8-page substitution table. Raw global words
are observational only and may differ after runtime initialization.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from genshinre.callxref import attach_caller_methods
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256
from genshinre.xrefs import scan_rip_xrefs

GLOBALS = {"staticOwnerPointer": 0x57831E8, "xorWord": 0x578B100}


def audit(exe: Path, methods_csv: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="exact 7.1 EXE")
    with PEImage(exe) as pe:
        globals_on_disk = {
            name: {
                "rva": f"0x{rva:X}",
                "fileSectionValueHex": pe.read_rva(rva, 8 if name == "staticOwnerPointer" else 4).hex()
            } for name, rva in GLOBALS.items()
        }
    result = scan_rip_xrefs(exe, list(GLOBALS.values()), window=0,
                            methods_csv=None)
    hits = {}
    counts = {}
    writes = {}
    for name, rva in GLOBALS.items():
        rows = result["matches"].get(f"0x{rva:X}", [])
        counts[name] = len(rows)
        # This IL2CPP statics pointer has many references. Count exhaustively
        # but retain bounded samples and all possible write sites up to cap.
        write_rows = [row for row in rows if row["access"] == "write"]
        writes[name] = len(write_rows)
        anchors = {0xBB16026, 0xBB15F56, 0xBB160A3, 0xBB15F6D}
        selected = list(write_rows[:128])
        selected += [r for r in rows if int(r["instruction_rva"], 0) in anchors]
        if name == "xorWord":
            selected += rows[:128]
        selected += rows[:12]
        chosen = list({int(row["instruction_rva"], 0): row for row in selected}.values())
        chosen.sort(key=lambda r: int(r["instruction_rva"]))
        annotations = attach_caller_methods(
            [int(row["instruction_rva"], 0) for row in chosen],
            methods_csv, max_method_body=0x10000)
        hits[name] = [
            {
                "instructionRva": f"0x{int(row['instruction_rva']):X}",
                "access": row["access"],
                "mnemonic": row["mnemonic"],
                "hex": row["instruction_hex"],
                "candidateOwners": [
                    {
                        "methodIndex": owner.get("method_index"),
                        "methodName": owner.get("method_name"),
                        "typeName": owner.get("type_name"),
                        "methodRva": owner.get("rva"),
                    } for owner in annotations.get(int(row["instruction_rva"], 0), [])[:4]
                ],
            } for row in chosen
        ]
    return {
        "schemaVersion": 1,
        "status": "PINNED_NATIVE_WRAPPER_STATIC_GLOBAL_XREFS__DYNAMIC_TABLE_UNRESOLVED",
        "sample": PROFILE_71.identity,
        "exeSha256": PROFILE_71.exe_sha256,
        "globallyReferencedLocations": globals_on_disk,
        "totalXrefsByGlobal": counts,
        "totalCandidateWritesByGlobal": writes,
        "boundedXrefSamples": hits,
        "limitations": [
            "RIP-relative byte pattern hits require aligned disassembly review before attributing global writes.",
            "The +0xF560 instance pointer and its 2048-byte lookup are runtime allocated, not proven by reading the on-disk static owner slot.",
            "Static XOR-word contents are on-disk observations only; runtime mutations must be traced.",
            "Caller attribution uses nearest preceding metadata method RVA, not a full control-flow reconstruction.",
            "No scene gadget tag or server payout data follows from these globals.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--methods", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = audit(args.exe, args.methods)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "globalLocations": report["globallyReferencedLocations"],
        "xrefs": report["totalXrefsByGlobal"],
        "writes": report["totalCandidateWritesByGlobal"],
    }, indent=2))


if __name__ == "__main__":
    main()
