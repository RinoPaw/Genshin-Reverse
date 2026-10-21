#!/usr/bin/env python3
"""Reject unsupported first-row reader attributions using exact 7.1 bytes.

These two neighboring metadata methods superficially look like SceneTag or
SceneExcel row readers: they read native presence masks, store a wrapped key,
and deserialize optional arrays. Calling either method as the row parser
directly after the authenticated 4-byte table header requires an impossible
array allocation in the *first* record.

The observation falsifies only the specified virtual-reader attribution
and entry cursor. It does not identify the actual row reader, disprove
other methods or recover any server chest drop_tag.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71

HERE = Path(__file__).resolve().parents[1]
REPORT = (HERE / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-scene-adjacent-reader-rejections.json")

SAMPLES = {
    "SceneTagConfigData": {
        "file": "b410089f.dat",
        "rawSha256": "f0cada8ea11c59fb32b72f0dd19e3aaf69af31382ed012573b9de92954567075",
        "payloadSha256": "9c043ecdbfba6a17c00243b37ae2bb3566ac9c09dcf800b648a76c3e113958ee",
        "metadataOwner": "BHENIHLFFDD",
        "methodIndex": 696555,
        "nativeRva": "0xAED2EF0",
        "disassemblyFile": "scenetag-adjacent-8field-reader.json",
        "headerMaskBytes": 2,
        "maskAdd": 0x7ABB,
        "maskXor": 0x8C53,
        "arrayPresentFlag": 0x01,
        "firstArrayCountOffset": 18,
        "arrayCountOp": "xor",
        "arrayCountConstant": 0xAD5BE444,
        "nativeAnchors": (
            ("0xAED2F41", "movzx", "esi, word ptr [rax + rcx + 0x20]"),
            ("0xAED2F4D", "add", "esi, 0x7abb"),
            ("0xAED2F53", "xor", "esi, 0x8c53"),
            ("0xAED3258", "test", "r15b, 1"),
            ("0xAED329B", "mov", "ebx, 0xad5be444"),
        ),
    },
    "SceneExcelConfigData": {
        "file": "fd805cfc.dat",
        "rawSha256": "970ffecdec5b1f9368b6db5c7c0129a9f0b9ba624f81d5289e3142572caebb8d",
        "payloadSha256": "588563f62149d62038c7ee3b179e50191ecc9a3cfc003353e18a831918d27f6a",
        "metadataOwner": "PDNKJGEJJAA",
        "methodIndex": 279984,
        "nativeRva": "0x118484D0",
        "disassemblyFile": "sceneexcel-adjacent-record-reader.json",
        "headerMaskBytes": 4,
        "maskAdd": 0,
        "maskXor": 0,
        "arrayPresentFlag": 0x100,
        "firstArrayCountOffset": 12,
        "arrayCountOp": "add",
        "arrayCountConstant": 0xADBFFFFB,
        "nativeAnchors": (
            ("0x11848521", "mov", "r14d, dword ptr [rax + rcx + 0x20]"),
            ("0x11848590", "test", "r14d, 0x100"),
            ("0x118485CE", "mov", "edx, 0xadbffffb"),
            ("0x118485D3", "add", "edx, dword ptr [rax + rcx + 0x20]"),
            ("0x118485ED", "call", "0x14050b230"),
        ),
    },
}


def inspect_first_row(name: str, raw: bytes, disassembly: dict) -> dict:
    spec = SAMPLES[name]
    if hashlib.sha256(raw).hexdigest() != spec["rawSha256"]:
        raise ValueError(f"{name}: raw original 7.1 SHA-256 mismatch")
    payload = unwrap_mihoyo_bin_data(raw)
    if hashlib.sha256(payload).hexdigest() != spec["payloadSha256"]:
        raise ValueError(f"{name}: unwrapped original 7.1 SHA-256 mismatch")
    if (disassembly.get("exe_sha256") != PROFILE_71.exe_sha256
            or disassembly.get("start_rva") != spec["nativeRva"]):
        raise ValueError(f"{name}: original disassembly executable identity mismatch")
    instructions = {item["rva"]: item for item in disassembly["instructions"]}
    for rva, mnemonic, operands in spec["nativeAnchors"]:
        found = instructions.get(rva)
        if not found or (found["mnemonic"], found["op_str"]) != (mnemonic, operands):
            raise ValueError(f"{name}: original native instruction mismatch at {rva}")

    # Original loader consumes first four bytes; proposed direct row reader
    # would begin immediately at payload offset four.
    start = 4
    if spec["headerMaskBytes"] == 2:
        word = struct.unpack_from("<H", payload, start)[0]
        mask = (((word + spec["maskAdd"]) & 0xFFFF) ^ spec["maskXor"]) & 0xFFFF
    else:
        word = struct.unpack_from("<I", payload, start)[0]
        mask = (((word + spec["maskAdd"]) & 0xFFFFFFFF) ^ spec["maskXor"]) & 0xFFFFFFFF
    if not (mask & spec["arrayPresentFlag"]):
        raise ValueError(f"{name}: hypothesized array flag is not present")
    offset = spec["firstArrayCountOffset"]
    serialized = struct.unpack_from("<I", payload, offset)[0]
    if spec["arrayCountOp"] == "xor":
        count = serialized ^ spec["arrayCountConstant"]
    else:
        count = (serialized + spec["arrayCountConstant"]) & 0xFFFFFFFF

    left = len(payload) - (offset + 4)
    if count <= left:
        raise ValueError(f"{name}: candidate no longer exceeds original payload bounds")
    return {
        "table": name,
        "nativeMethodOwnerCandidate": spec["metadataOwner"],
        "nativeMethodIndex": spec["methodIndex"],
        "nativeMethodRva": spec["nativeRva"],
        "rawExportSha256": spec["rawSha256"],
        "payloadSha256": spec["payloadSha256"],
        "candidateEntryOffsetAfterTableCount": 4,
        "firstRawMask": f"0x{word:0{spec['headerMaskBytes']*2}X}",
        "candidateDecodedMask": f"0x{mask:X}",
        "candidateArrayFlag": f"0x{spec['arrayPresentFlag']:X}",
        "firstArrayCountWireOffset": offset,
        "firstArrayCountWireU32": f"0x{serialized:08X}",
        "candidateArrayLength": count,
        "remainingPayloadBytes": left,
        "nativeInstructionAnchorsMatched": len(spec["nativeAnchors"]),
        "claim": "DIRECT_FIRST_ROW_READER_CANDIDATE_INCONSISTENT_WITH_ORIGINAL_PAYLOAD",
    }


def audit(raws: dict[str, bytes], native: dict[str, dict]) -> dict:
    return {
        "schemaVersion": 1,
        "status": "EXACT_71_SCENE_NEIGHBOR_METHODS_DIRECT_ROW_PARSE_FALSIFIED__ACTUAL_VTABLE_UNRESOLVED",
        "exeSha256": PROFILE_71.exe_sha256,
        "candidates": {
            name: inspect_first_row(name, raws[name], native[name])
            for name in SAMPLES
        },
        "limitations": [
            "These first-row array bounds rule out direct invocation of these particular neighboring methods at serialized offset 4; they are not a search of all possible row readers.",
            "The original vtable+0xF0 target has not been established from native registration data; metadata adjacency never proves it.",
            "The method call graph, array allocator and dynamic field defaults outside these first mandatory reads have not been modeled.",
            "No SceneTag game-state field, official scene instance or server chest drop_tag or reward root has been decoded.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export-dir", required=True, type=Path)
    parser.add_argument("--native-trace-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=REPORT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = audit(
        {name: (args.export_dir / spec["file"]).read_bytes()
         for name, spec in SAMPLES.items()},
        {name: json.loads((args.native_trace_dir / spec["disassemblyFile"]).read_bytes())
         for name, spec in SAMPLES.items()},
    )
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != data:
            raise SystemExit("source-validated Scene neighbor reader negative controls changed")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False)+"\n",
                               encoding="utf-8")
    print(json.dumps({
        "status": data["status"],
        "candidates": [
            {"table": name,
             "arrayLength": item["candidateArrayLength"],
             "remainingPayloadBytes": item["remainingPayloadBytes"]}
            for name, item in data["candidates"].items()],
    }, indent=2))


if __name__ == "__main__":
    main()
