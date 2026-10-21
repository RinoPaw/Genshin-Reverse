#!/usr/bin/env python3
"""Audit exact 7.1 SceneExcel / SceneTag native table loader instructions.

The original executable sample, disassembly file digests, original Sophon
SceneExcel/SceneTag payload hashes and exact instruction anchors are all
required. These are concrete decoded header/loop facts; row field readers
remain behind indirect virtual dispatch at vtable offset 0xF0.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.scenebin71 import SOURCES, decode_source_header

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-native-scene-table-loader-evidence.json")

NATIVE = {
    "SceneTagConfigData": {
        "name": "EJCNENCJADF.GMENPOPMKAA",
        "disassemblySha256": "7bf1d07589a75cc3a790728de46fc0c5c083bc8e11652e435222c25a074f26ba",
        "anchors": (
            ("0x140154A9", "mov", "edi, 0xf16a9d33"),
            ("0x140154AE", "xor", "edi, dword ptr [rax + rcx + 0x20]"),
            ("0x140154FC", "test", "edi, edi"),
            ("0x1401553C", "call", "qword ptr [rax + 0xf0]"),
            ("0x14015550", "mov", "eax, dword ptr [rbx + 0x28]"),
            ("0x1401555A", "call", "0x14bb15f50"),
            ("0x14015596", "dec", "edi"),
        ),
    },
    "SceneExcelConfigData": {
        "name": "HPNMCGDJOJL.GMENPOPMKAA",
        "disassemblySha256": "c629e084fcf9b5357de330d49ee681bb3c7d50181c404071a5b054fdafb93725",
        "anchors": (
            ("0xA6C7049", "mov", "edi, 0xb8b21ebc"),
            ("0xA6C704E", "add", "edi, dword ptr [rax + rcx + 0x20]"),
            ("0xA6C709C", "test", "edi, edi"),
            ("0xA6C70DC", "call", "qword ptr [rax + 0xf0]"),
            ("0xA6C70F0", "mov", "eax, dword ptr [rbx + 0x50]"),
            ("0xA6C70FA", "call", "0x14bb15f50"),
            ("0xA6C7136", "dec", "edi"),
        ),
    },
}


def verify_native(disassemblies: dict[str, bytes], original_raw: dict[str, bytes]) -> dict:
    report: dict[str, dict] = {}
    for name, spec in NATIVE.items():
        source = SOURCES[name]
        binary = disassemblies[name]
        digest = hashlib.sha256(binary).hexdigest()
        if digest != spec["disassemblySha256"]:
            raise ValueError(f"{name} pinned disassembly SHA-256 mismatch")
        parsed = json.loads(binary)
        if (parsed["exe_sha256"] != PROFILE_71.exe_sha256
                or int(parsed["start_rva"], 16) != source["loader_rva"]):
            raise ValueError(f"{name} original executable or method RVA mismatch")
        by_rva = {row["rva"]: row for row in parsed["instructions"]}
        if len(by_rva) != len(parsed["instructions"]):
            raise ValueError(f"{name} duplicate native instruction RVA")
        for rva, mnemonic, operands in spec["anchors"]:
            actual = by_rva.get(rva)
            if actual is None or (
                    actual["mnemonic"], actual["op_str"]) != (mnemonic, operands):
                raise ValueError(f"{name} original native instruction mismatch at {rva}")
        header = decode_source_header(original_raw[name], source=name)
        report[name] = {
            **header.summary(),
            "nativeLoaderOwner": spec["name"],
            "nativeMethodIndex": source["method_index"],
            "nativeLoaderRva": f"0x{source['loader_rva']:X}",
            "nativeDisassemblySha256": digest,
            "matchedInstructionAnchors": len(spec["anchors"]),
            "rowReaderDispatch": "virtual CALL [row.vtable + 0xF0]",
            "rowKeyMemoryOffset": f"0x{source['key_offset']:X}",
            "rowKeyGetterRva": "0xBB15F50",
            "headerAndLoopVerifiedFromOriginalClient": True,
        }
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_SCENE_EXCEL_AND_TAG_NATIVE_HEADER_LOOP_CONFIRMED__ROW_FIELDS_UNKNOWN",
        "sample": PROFILE_71.identity,
        "exeSha256": PROFILE_71.exe_sha256,
        "nativeTables": report,
        "limitations": [
            "Original table counts are confirmed by exact native instruction anchors and SHA-256-pinned original client source payloads, independent of historical JSON row counts.",
            "Both native table loaders iterate decoded counts, instantiate a row object and invoke a virtual row reader at vtable +0xF0.",
            "Native loader inserts rows keyed by a wrapper-read uint32 memory slot; the runtime substitution lookup relation remains unverified.",
            "The concrete virtual row class, serialized field mask and per-field read schema have not yet been resolved.",
            "SceneTagConfigData is an original client SceneTag table; there is no authenticated relationship to historical server Lua chest drop_tag or payout tables.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scene-tag-disasm", type=Path, required=True)
    parser.add_argument("--scene-excel-disasm", type=Path, required=True)
    parser.add_argument("--scene-tag-raw", type=Path, required=True)
    parser.add_argument("--scene-excel-raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = verify_native({
        "SceneTagConfigData": args.scene_tag_disasm.read_bytes(),
        "SceneExcelConfigData": args.scene_excel_disasm.read_bytes(),
    }, {
        "SceneTagConfigData": args.scene_tag_raw.read_bytes(),
        "SceneExcelConfigData": args.scene_excel_raw.read_bytes(),
    })
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != data:
            raise SystemExit("native scene row header evidence differs from pinned original")
        print("PASS: exact 7.1 native SceneTag and SceneExcel header readers")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
    print(json.dumps({
        "status": data["status"],
        "nativeCounts": {k: v["nativeRowCount"] for k, v in data["nativeTables"].items()},
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
