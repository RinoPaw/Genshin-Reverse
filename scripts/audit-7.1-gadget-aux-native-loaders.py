#!/usr/bin/env python3
"""Reproduce original Global 7.1 Gadget auxiliary loader evidence.

The original client EXE is verified via the disassembly producer; original
MiHoYoBinData raw source and metadata method blob are hash-checked again.
Native table counts/row allocation/indirect dispatch can be asserted without
inventing row schema or LootCSS semantics.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71

METHODS_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
SOURCE = {
  "GadgetPropExcelConfigData": {
    "rawName": "e37e8728.dat",
    "rawSha256": "8907f4b717cd450ce084bd3a1a6a73e4409b8280fb4c74605afa520efbbc6a54",
    "payloadSha256": "a12f433fe834576f84cbd5521c5715a27dc64eed0ee0137eb0cb24573d38d091",
    "rowCount": 326,
    "operation": "xor",
    "immediate": "0x5BD303D6",
    "loaderRva": "0x124F2CF0",
    "methodIndex": 225673,
    "ownerTypeName": "CLOHJDMMODM",
    "ownerTypeIndex": 28984,
    "keyOffset": "0x1C",
    "rowClassStaticSlot": "0x57DAF50",
    "anchors": {
      "0x124F2D39": [
        "mov",
        "edi, 0x5bd303d6"
      ],
      "0x124F2D3E": [
        "xor",
        "edi, dword ptr [rax + rcx + 0x20]"
      ],
      "0x124F2D94": [
        "mov",
        "rcx, qword ptr [rip - 0xcd17e4b]"
      ],
      "0x124F2D9B": [
        "call",
        "0x140529a10"
      ],
      "0x124F2DCC": [
        "call",
        "qword ptr [rax + 0xf0]"
      ],
      "0x124F2DE0": [
        "mov",
        "eax, dword ptr [rbx + 0x1c]"
      ],
      "0x124F2DEA": [
        "call",
        "0x14bb15f50"
      ],
      "0x124F2E26": [
        "dec",
        "edi"
      ]
    }
  },
  "GadgetInteractExcelConfigData": {
    "rawName": "c71a7ea9.dat",
    "rawSha256": "6481cd8b92185ffc13ffe8a12332eba8d53139077c75738aa40d15fc5bc8c24e",
    "payloadSha256": "ce9fcd3b2d7deb76c7e9f2a4ca2738f8d9e0e8500b7bb101768cd18be059fb11",
    "rowCount": 363,
    "operation": "add",
    "immediate": "0xDA262FFE",
    "loaderRva": "0x11072FA0",
    "methodIndex": 220154,
    "ownerTypeName": "GAMAJLKMDJO",
    "ownerTypeIndex": 28382,
    "keyOffset": "0x28",
    "rowClassStaticSlot": "0x57FA548",
    "anchors": {
      "0x11072FE9": [
        "mov",
        "edi, 0xda262ffe"
      ],
      "0x11072FEE": [
        "add",
        "edi, dword ptr [rax + rcx + 0x20]"
      ],
      "0x11073044": [
        "mov",
        "rcx, qword ptr [rip - 0xb878b03]"
      ],
      "0x1107304B": [
        "call",
        "0x140529a10"
      ],
      "0x1107307C": [
        "call",
        "qword ptr [rax + 0xf0]"
      ],
      "0x11073090": [
        "mov",
        "eax, dword ptr [rbx + 0x28]"
      ],
      "0x1107309A": [
        "call",
        "0x14bb15f50"
      ],
      "0x110730D6": [
        "dec",
        "edi"
      ]
    }
  }
}
OUTPUT = Path("versions/7.1.0-global/analyses/progression/economy/7.1-gadget-aux-native-table-loaders.json")


def hash_blob(path: Path) -> str:
    h = hashlib.sha1()
    h.update(("blob " + str(path.stat().st_size)).encode() + bytes([0]))
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def check_methods(path: Path) -> dict:
    if hash_blob(path) != METHODS_BLOB:
        raise ValueError("7.1 original methods.csv Git blob mismatch")
    indexed = {str(s["methodIndex"]): name for name, s in SOURCE.items()}
    found = {}
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for method in csv.DictReader(handle):
            name = indexed.get(method.get("method_index"))
            if name is None:
                continue
            s = SOURCE[name]
            if (method["rva"].upper() != s["loaderRva"].upper()
                or method["type_name"] != s["ownerTypeName"]
                or int(method["type_definition_index"]) != s["ownerTypeIndex"]):
                raise ValueError(f"{name}: original metadata manager mismatch")
            if name in found:
                raise ValueError(f"{name}: duplicate metadata method")
            found[name] = True
    if set(found) != set(SOURCE):
        raise ValueError("original 7.1 loader metadata owner missing")
    return found


def decode_header(raw: bytes, spec: dict) -> dict:
    if hashlib.sha256(raw).hexdigest() != spec["rawSha256"]:
        raise ValueError("original Raw SHA-256 mismatch")
    payload = unwrap_mihoyo_bin_data(raw)
    if hashlib.sha256(payload).hexdigest() != spec["payloadSha256"]:
        raise ValueError("original payload SHA-256 mismatch")
    if len(payload) < 4:
        raise ValueError("truncated original source table header")
    header = struct.unpack_from("<I", payload)[0]
    immediate = int(spec["immediate"], 16)
    count = ((header + immediate) & 0xFFFFFFFF
             if spec["operation"] == "add" else header ^ immediate)
    if count != spec["rowCount"]:
        raise ValueError("original header and loader native row count disagree")
    return {"rawSha256": spec["rawSha256"],
            "payloadSha256": spec["payloadSha256"],
            "payloadBytes": len(payload),
            "originalHeaderU32": f"0x{header:08X}",
            "nativeCountImmediate": spec["immediate"],
            "nativeCountOperation": spec["operation"],
            "nativeDecodedRowCount": count}


def verify(disassemblies: dict, original_raw: dict, methods_verified: dict) -> dict:
    out = {}
    for name, spec in SOURCE.items():
        d = disassemblies[name]
        if (d["exe_sha256"] != PROFILE_71.exe_sha256
                or d["start_rva"].upper() != spec["loaderRva"].upper()
                or int(d["size"]) != 0x320):
            raise ValueError(f"{name}: original EXE and loader RVA mismatch")
        instructions = {row["rva"].upper(): row for row in d["instructions"]}
        if len(instructions) != len(d["instructions"]):
            raise ValueError(f"{name}: duplicate original disassembly RVA")
        for rva, (mnemonic, operands) in spec["anchors"].items():
            actual = instructions.get(rva.upper())
            if actual is None or (actual["mnemonic"], actual["op_str"]) != (mnemonic, operands):
                raise ValueError(f"{name}: original instruction mismatch at {rva}")
        # Recover the static class-pointer RVA using the original instruction
        # encoding itself. This does not disclose the runtime row type.
        class_rva = next(key for key, value in spec["anchors"].items()
                         if value[1].startswith("rcx, qword ptr [rip"))
        blob = bytes.fromhex(instructions[class_rva]["bytes"])
        if len(blob) != 7 or blob[:3] != bytes.fromhex("488b0d"):
            raise ValueError(f"{name}: original class pointer instruction encoding drift")
        target = int(class_rva, 16) + len(blob) + struct.unpack_from("<i", blob, 3)[0]
        if target != int(spec["rowClassStaticSlot"], 16):
            raise ValueError(f"{name}: native class pointer static slot mismatch")
        if name not in methods_verified:
            raise ValueError(f"{name}: original method owner not verified")
        out[name] = {
            **decode_header(original_raw[name], spec),
            "methodIndex": spec["methodIndex"],
            "nativeManagerType": spec["ownerTypeName"],
            "nativeManagerTypeDefinitionIndex": spec["ownerTypeIndex"],
            "loaderRva": spec["loaderRva"],
            "verifiedNativeInstructions": len(spec["anchors"]),
            "rowClassStaticSlotRva": spec["rowClassStaticSlot"],
            "rowReaderDispatch": "virtual CALL [row.vtable + 0xF0]",
            "preGetterRowKeyMemoryOffset": spec["keyOffset"],
            "nativeWrappedKeyGetterRva": "0xBB15F50",
            "rowReaderOwnerConfirmed": False,
            "rowFieldsDecoded": False,
            "chestGradeProven": False,
            "sceneInstanceLevelProven": False,
        }
    return {"schemaVersion": 1,
            "status": "EXACT_7_1_AUX_GADGET_NATIVE_TABLE_LOADERS_CONFIRMED__ROW_READER_UNRESOLVED",
            "sample": PROFILE_71.identity,
            "exeSha256": PROFILE_71.exe_sha256,
            "methodsGitBlob": METHODS_BLOB,
            "tables": out,
            "limitations": [
                "Original native table counts, loop, row alloc and virtual slot are verified; concrete virtual row reader remains unknown.",
                "RIP-relative TypeInfo static slots are exact original instructions but not runtime class identities.",
                "Field offsets 0x1C/0x28 identify pre-getter wrapped row keys, not LootCSS grade, level or type.",
                "Source table identity is hash-checked; no official scene instance or reward field is inferred.",
            ]}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--prop-disasm", type=Path, required=True)
    p.add_argument("--interact-disasm", type=Path, required=True)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--methods", type=Path, required=True)
    p.add_argument("--output", type=Path, default=OUTPUT)
    p.add_argument("--check", action="store_true")
    a = p.parse_args()
    names = ["GadgetPropExcelConfigData", "GadgetInteractExcelConfigData"]
    d = {name: json.loads(f.read_text(encoding="utf-8"))
         for name, f in zip(names, (a.prop_disasm, a.interact_disasm))}
    raw = {name: (a.exports / SOURCE[name]["rawName"]).read_bytes() for name in names}
    report = verify(d, raw, check_methods(a.methods))
    if a.check:
        if json.loads(a.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("original 7.1 native Gadget auxiliary report drift")
    else:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
    print(json.dumps({"status": report["status"], "tables": {
        name: {"count": row["nativeDecodedRowCount"],
               "wrappedKeyOffset": row["preGetterRowKeyMemoryOffset"],
               "rowClassStaticSlotRva": row["rowClassStaticSlotRva"]}
        for name, row in report["tables"].items()}}, indent=2))


if __name__ == "__main__":
    main()
