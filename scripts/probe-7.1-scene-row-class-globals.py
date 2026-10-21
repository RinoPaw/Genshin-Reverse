#!/usr/bin/env python3
"""Trace exact Global 7.1 SceneTag/SceneExcel allocation-class pointer slots.

Both original table loaders call allocator RVA 0x140529A10 first for the map
and then for each row; the preceding MOV RCX,[RIP+disp32] is a class/static
pointer, *not* a file-backed type-definition identity. This scan can locate
additional native references to each pointer but cannot recover its runtime
Il2CppClass contents or virtual method target by itself.

The source EXE SHA-256, four exact original loading instructions, and the
native method-owner attribution are independently checked.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256
from genshinre.xrefs import scan_rip_xrefs

# table -> scope -> (pinned native RIP-relative MOV instruction, global slot)
SITES = {
    "SceneTagConfigData": {
        "mapAllocationTypeSlot": (0x140154B6, 0x57EA610),
        "rowAllocationTypeSlot": (0x14015504, 0x57EA618),
    },
    "SceneExcelConfigData": {
        "mapAllocationTypeSlot": (0xA6C7056, 0x58113C8),
        "rowAllocationTypeSlot": (0xA6C70A4, 0x58113D0),
    },
}
MAX_SITES = 512


def _same_native_anchor(row: dict, site: int) -> bool:
    return int(row["instruction_rva"], 16) == site and (
        row["mnemonic"], row["access"]) == ("mov", "read")


def investigate(exe: Path, methods_csv: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="exact Global 7.1 executable")
    rvas = sorted({rva for by_type in SITES.values() for _,rva in by_type.values()})
    xrefs = scan_rip_xrefs(exe, rvas, window=16, methods_csv=methods_csv)
    report = {}
    with PEImage(exe) as pe:
        for name, slots in SITES.items():
            items = {}
            for title, (instruction, target) in slots.items():
                candidates = xrefs["matches"][f"0x{target:X}"]
                anchors = [row for row in candidates if _same_native_anchor(row, instruction)]
                if len(anchors) != 1:
                    raise ValueError(f"source-pinned native {name} {title} loader anchor missing")
                if len(candidates) > MAX_SITES:
                    raise ValueError(f"unbounded pointer cross references at 0x{target:X}")
                if not anchors[0].get("caller_methods"):
                    raise ValueError(f"loader method-owner metadata missing at 0x{instruction:X}")
                items[title] = {
                    "nativeLoaderInstructionRva": f"0x{instruction:X}",
                    "sharedClassPointerGlobalRva": f"0x{target:X}",
                    "fileBackedBytesAtGlobalHex": pe.read_rva(target, 8).hex(),
                    "nativeLoaderInstructionBytes": anchors[0]["instruction_hex"],
                    "nativeMethodOwnerCandidates": anchors[0]["caller_methods"],
                    "totalMovLeaRIPCrossReferences": len(candidates),
                    "referenceMethods": [
                        {
                            "nativeInstructionRva": row["instruction_rva"],
                            "access": row["access"],
                            "nativeMethodCandidates": [
                                {
                                    "typeName": m.get("type_name"),
                                    "methodName": m.get("method_name"),
                                    "methodIndex": m.get("method_index"),
                                    "rva": m.get("rva"),
                                } for m in row.get("caller_methods", [])[:3]
                            ],
                        } for row in candidates
                    ],
                }
            if items["rowAllocationTypeSlot"]["sharedClassPointerGlobalRva"] == (
                    items["mapAllocationTypeSlot"]["sharedClassPointerGlobalRva"]):
                raise ValueError("native map and row allocation class globals accidentally aliased")
            report[name] = items
    return {
        "schemaVersion": 1,
        "status": "ORIGINAL_71_SCENE_ROW_ALLOCATION_CLASS_GLOBAL_XREFS__VIRTUAL_TARGET_UNKNOWN",
        "source": "exact Global 7.1 Windows x64 GenshinImpact.exe",
        "exeSha256": PROFILE_71.exe_sha256,
        "originalNativeLoaderClassSlots": report,
        "limits": [
            "The RIP globals are pointer storage slots passed to native object allocation; they do not identify managed class TypeDefinitionIndex without the runtime TypeInfo registration mapping.",
            "MOV/LEA byte-pattern matches are candidate references and not a full disassembly of arbitrary reference forms.",
            "Virtual call [row.vtable + 0xF0] still requires original class-instance/vtable mapping before it can be assigned to a concrete row decoder.",
            "SceneTagConfigData cannot be equated with server Scene Lua chest drop_tag using this client-side pointer evidence.",
            "No scene/group/config placement, chest payout root or reward quantity is confirmed.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--methods", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = investigate(args.exe, args.methods)
    if args.check:
        if report != json.loads(args.output.read_text(encoding="utf-8")):
            raise SystemExit("original 7.1 Scene row allocation xrefs diverged")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "counts": {source: {name: value["totalMovLeaRIPCrossReferences"]
                           for name, value in slots.items()}
                   for source, slots in report["originalNativeLoaderClassSlots"].items()},
    }, indent=2))


if __name__ == "__main__":
    main()
