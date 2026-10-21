#!/usr/bin/env python3
"""Find exact 7.1 metadata registration references to SceneTag/SceneExcel row class slots.

Both loader classes use runtime-initialized pointers to the concrete row
Il2CppClass, at 0x57EA618 and 0x58113D0. This source-pinned scanner
checks file-backed non-executable PE sections for exact 64-bit image VAs,
and a second *candidate-only* 32-bit RVA form. No runtime vtable target
is invented from a pointer-holder match.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.pointerxref import scan_pointer_holders
from genshinre.sampleidentity import require_sha256

SLOTS = {
    "SceneTag": {"rowClassRva": 0x57EA618, "otherAdjacentRva": 0x57EA610,
                 "nativeLoadInstructionRva": 0x14015504},
    "SceneExcel": {"rowClassRva": 0x58113D0, "otherAdjacentRva": 0x58113C8,
                   "nativeLoadInstructionRva": 0xA6C70A4},
}
MAX_HITS_PER_SLOT = 200
EXECUTABLE_SECTION = 0x20000000


def scan(exe: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="original Global 7.1 PE")
    results = {name: {
        "classSlotRva": f"0x{v['rowClassRva']:X}",
        "nativeLoaderInstructionRva": f"0x{v['nativeLoadInstructionRva']:X}",
        "fullVaQwordHolders": [],
        "rvaDwordCandidates": [],
        "adjacentFullVaHolders": [],
    } for name,v in SLOTS.items()}
    with PEImage(exe) as pe:
        for section in pe.sections:
            if section.characteristics & EXECUTABLE_SECTION or section.raw_size < 4:
                continue
            raw = pe.read_rva(section.virtual_address, section.raw_size)
            for name, info in SLOTS.items():
                record = results[name]
                key = info["rowClassRva"]
                # Exact 8-byte native-image absolute VA.
                holders = scan_pointer_holders(
                    raw, section_rva=section.virtual_address,
                    image_base=pe.image_base,
                    target_start_rva=key, target_end_rva=key+1,
                    alignment=8)
                record["fullVaQwordHolders"].extend({
                    "rva": f"0x{h['holder_rva']:X}",
                    "section": section.name,
                    "neighborBytesHex": pe.read_rva(max(0, h["holder_rva"]-16), 48).hex(),
                } for h in holders)
                adjacent = scan_pointer_holders(
                    raw, section_rva=section.virtual_address,
                    image_base=pe.image_base,
                    target_start_rva=info["otherAdjacentRva"],
                    target_end_rva=info["otherAdjacentRva"]+1, alignment=8)
                record["adjacentFullVaHolders"].extend({
                    "rva": f"0x{h['holder_rva']:X}",
                    "section": section.name,
                } for h in adjacent)
                # Alternative 32-bit RVAs may be relocation-free metadata-use
                # entries. They are untyped patterns and only leads.
                needle = key.to_bytes(4, "little")
                position = 0
                while (offset := raw.find(needle, position)) >= 0:
                    position = offset + 1
                    record["rvaDwordCandidates"].append({
                        "rva": f"0x{section.virtual_address+offset:X}",
                        "section": section.name,
                        "byteAligned4": ((section.virtual_address+offset) % 4 == 0),
                    })
            if any(any(len(results[n][field]) > MAX_HITS_PER_SLOT
                       for field in ("fullVaQwordHolders", "rvaDwordCandidates",
                                     "adjacentFullVaHolders")) for n in SLOTS):
                raise ValueError("unbounded 7.1 class registration pointer candidates")
        return {
            "schemaVersion": 1,
            "status": "EXACT_7_1_SCENE_ROW_CLASS_POINTER_REGISTRATION_PROBE__VTABLE_TARGET_UNRESOLVED",
            "exeSha256": PROFILE_71.exe_sha256,
            "imageBase": f"0x{pe.image_base:X}",
            "sourceNativeMethods": {
                "SceneTagLoaderRva": "0x14015460",
                "SceneExcelLoaderRva": "0xA6C7000",
                "objectAllocationRva": "0x140529A10",
                "virtualReaderSlotBytes": "0xF0",
            },
            "tables": results,
            "limitations": [
                "The class static slot RVAs are proven by exact original native loader MOV instructions.",
                "A file-backed image VA holder may be a type registration pointer or unrelated pointer consumer; identifying its array owner requires native code/metadata traversal.",
                "Four-byte RVA scans may match unaligned byte patterns or numeric values and are not proof of a pointer.",
                "Zero direct holders in file-backed data does not exclude runtime initialized class pointers or image relocation table encodings.",
                "No SceneTag row parser at vtable+0xF0, placement, original Lua drop_tag or server chest payout is authenticated.",
            ],
        }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--check", action="store_true",
                   help="Compare source-pinned report with the committed evidence")
    args = p.parse_args()
    result = scan(args.exe)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != result:
            raise SystemExit("pinned native row-class registration scan differs")
        print("PASS: source-pinned 7.1 scene class registration evidence")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n",
                               encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "hits": {k: {
            "fullVa": len(v["fullVaQwordHolders"]),
            "adjacentFullVa": len(v["adjacentFullVaHolders"]),
            "rvaDword": len(v["rvaDwordCandidates"]),
            "examples": v["fullVaQwordHolders"][:5],
        } for k,v in result["tables"].items()}
    }, indent=2))


if __name__ == "__main__":
    main()
