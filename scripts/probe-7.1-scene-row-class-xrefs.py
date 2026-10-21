#!/usr/bin/env python3
"""Find exact-7.1 scene row-constructor IL2CPP class pointers and their callers.

Global 7.1 SceneTag/SceneExcel loaders allocate each row via
  mov rcx,[RIP + disp32]; call 0x140529A10
with distinct global class-pointer slots. Find all static native code
references to those same slots. This is candidate class-ownership
evidence, NOT direct vtable+0xF0 resolution.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.sampleidentity import require_sha256
from genshinre.xrefs import scan_rip_xrefs

# Aligned native instructions from exact 7.1 loader disassemblies.
ANCHORS = {
    "SceneTag": {
        "loaderRva": 0x14015460,
        "rowClassLoadRva": 0x14015504,
        "rowClassRipDisplacement": -0xE82AEF3,
        "rowClassLoadInstructionBytes": "488b0d0d517df1",
        "rowObjectAllocCallRva": 0x1401550B,
        "rowReaderVirtualCallRva": 0x1401553C,
    },
    "SceneExcel": {
        "loaderRva": 0xA6C7000,
        "rowClassLoadRva": 0xA6C70A4,
        "rowClassRipDisplacement": -0x4EB5CDB,
        "rowClassLoadInstructionBytes": "488b0d25a314fb",
        "rowObjectAllocCallRva": 0xA6C70AB,
        "rowReaderVirtualCallRva": 0xA6C70DC,
    },
}


def class_pointer_rva(entry: dict) -> int:
    return (entry["rowClassLoadRva"] + len(bytes.fromhex(
        entry["rowClassLoadInstructionBytes"])) + entry["rowClassRipDisplacement"])


def summarize(xrefs: dict) -> dict:
    table = {}
    for name, anchor in ANCHORS.items():
        target = class_pointer_rva(anchor)
        rows = xrefs["matches"].get(f"0x{target:X}", [])
        if not any(row["instruction_rva"] == f"0x{anchor['rowClassLoadRva']:X}"
                   and row["instruction_hex"] == anchor["rowClassLoadInstructionBytes"]
                   for row in rows):
            raise ValueError(f"{name} exact row-class static pointer positive control missing")
        if len(rows) > 1024:
            raise ValueError(f"{name} class-pointer xref count unexpectedly broad")
        table[name] = {
            "loaderRva": f"0x{anchor['loaderRva']:X}",
            "rowClassStaticPointerRva": f"0x{target:X}",
            "rowClassLoadInstructionRva": f"0x{anchor['rowClassLoadRva']:X}",
            "rowObjectAllocCallRva": f"0x{anchor['rowObjectAllocCallRva']:X}",
            "rowReaderVirtualCallRva": f"0x{anchor['rowReaderVirtualCallRva']:X}",
            "referenceCount": len(rows),
            "referenceSites": [{
                "rva": row["instruction_rva"],
                "instructionBytes": row["instruction_hex"],
                "candidateAccess": row["access"],
                "metadataOwners": [{
                    "methodIndex": m.get("method_index"),
                    "type": m.get("type_name"),
                    "method": m.get("method_name"),
                    "rva": m.get("rva"),
                    "parameterTypes": m.get("parameter_types"),
                } for m in row.get("caller_methods", [])[:5]],
            } for row in rows],
        }
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_SCENE_ROW_CLASS_STATIC_XREF_CANDIDATES__VIRTUAL_TARGET_UNRESOLVED",
        "sample": PROFILE_71.identity,
        "exeSha256": PROFILE_71.exe_sha256,
        "sharedObjectAllocatorRva": "0x140529A10",
        "tables": table,
        "limitations": [
            "Both global pointer locations are traced from aligned original 7.1 native MOV instructions immediately preceding the object-allocation helper.",
            "References to a class pointer can lead to its concrete row type but are not themselves proof of the virtual method at +0xF0.",
            "Near-method attribution uses a bounded nearest metadata RVA; method-body overlap or thunk references require aligned disassembly.",
            "Runtime initialization of the class pointer, virtual slot mapping and original row field wire reader remain unresolved.",
            "The client SceneTag table cannot certify a historical server chest drop_tag or payout source.",
        ],
    }


def run(exe: Path, methods: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="exact Global 7.1 client")
    rvas = [class_pointer_rva(entry) for entry in ANCHORS.values()]
    return summarize(scan_rip_xrefs(
        exe, rvas, window=12, methods_csv=methods, max_method_body=0x10000))


def main() -> None:
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
        "classes": {name: {
            "rva": r["rowClassStaticPointerRva"],
            "references": r["referenceCount"],
            "candidateOwners": [
                {**ref["metadataOwners"][0], "site": ref["rva"]}
                for ref in r["referenceSites"] if ref["metadataOwners"]
            ][:25]
        } for name,r in result["tables"].items()},
    }, indent=2))


if __name__ == "__main__":
    main()
