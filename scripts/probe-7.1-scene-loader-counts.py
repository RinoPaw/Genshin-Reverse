#!/usr/bin/env python3
"""Find 7.1 native Excel table-count loader *instruction-pattern candidates*.

Exact native Gadget table loader uses:
  BF <imm32> 03 7C 08 20  (mov edi,imm32; add edi,[rax+rcx+0x20]).
Search related opcode variants in original executable sections, then apply
candidate addends to source-hash-checked SceneExcel/SceneTag headers.
Historically reported row counts supply ranking hints only; neither a byte
match nor a plausible count authenticates a native method until disassembled.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.callxref import attach_caller_methods
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

INPUTS = {
    "Gadget": ("d65ab32f.dat",
               "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35",
               30599),
    "SceneTag": ("b410089f.dat",
                 "f0cada8ea11c59fb32b72f0dd19e3aaf69af31382ed012573b9de92954567075",
                 1147),
    "SceneExcel": ("fd805cfc.dat",
                   "970ffecdec5b1f9368b6db5c7c0129a9f0b9ba624f81d5289e3142572caebb8d",
                   2377),
}
U32 = 0xffffffff
MAX_HITS = 20000


def candidates_in_section(blob: bytes, start_rva: int) -> list[dict]:
    """Return bounded matching-register ADD/XOR x86 patterns, not full disassembly."""
    found = []
    for operator, opcode in (("add", 0x03), ("xor", 0x33)):
        offset = 0
        while True:
            pos = blob.find(bytes([opcode]), offset)
            if pos < 0:
                break
            offset = pos + 1
            if pos < 5 or pos + 4 > len(blob):
                continue
            # x86-64: add/xor r32,[rax+rcx+0x20] with matching preceding
            # mov r32,imm32. Source-positive Gadget uses BF imm32 03 7C 08 20.
            modrm = blob[pos + 1]
            if (modrm & 0xC7) != 0x44 or blob[pos+2:pos+4] != b"\\x08\\x20":
                continue
            reg = (modrm >> 3) & 7
            if blob[pos - 5] != 0xB8 + reg:
                continue
            constant = int.from_bytes(blob[pos-4:pos], "little")
            found.append({
                "candidateMovRva": f"0x{start_rva+pos-5:X}",
                "candidateArithmeticRva": f"0x{start_rva+pos:X}",
                "operator": operator,
                "register": reg,
                "immediate": f"0x{constant:08X}",
                "signatureHex": blob[pos-5:pos+4].hex(),
                "localPrefixHex": blob[max(0, pos-21):pos-5].hex(),
            })
            if len(found) > MAX_HITS:
                raise ValueError("unbounded original loader arithmetic pattern count")
    return sorted(found, key=lambda row: int(row["candidateMovRva"], 16))


def audit(exe: Path, methods: Path, exports: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="original 7.1 executable")
    raw_headers = {}
    for label, (filename, digest, legacy_count) in INPUTS.items():
        raw = (exports / filename).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f"{label} exact original export SHA-256 mismatch")
        payload = unwrap_mihoyo_bin_data(raw)
        if len(payload) < 4:
            raise ValueError(f"{label} lacks a 4-byte table header")
        raw_headers[label] = {
            "sourceExport": filename,
            "exportSha256": digest,
            "first4ByteLittleEndian": f"0x{int.from_bytes(payload[:4], 'little'):08X}",
            "historicalCountHintUnverified": legacy_count,
        }

    hits = []
    with PEImage(exe) as image:
        for section in image.sections:
            if not (section.characteristics & 0x20000000):
                continue
            blob = image.read_rva(section.virtual_address, section.raw_size)
            hits.extend(candidates_in_section(blob, section.virtual_address))
            if len(hits) > MAX_HITS:
                raise ValueError("unbounded original EXE table loader candidates")
    gadget = [
        row for row in hits if row["candidateMovRva"] == "0x968F6D9"
        and row["immediate"] == "0x23F5AB5E" and row["operator"] == "add" and row["register"] == 7
    ]
    if len(gadget) != 1:
        raise ValueError("known Gadget original native table-loader instruction missing")
    annotations = attach_caller_methods(
        [int(row["candidateMovRva"], 16) for row in hits], methods)
    for row in hits:
        rva = int(row["candidateMovRva"], 16)
        row["nearestMetadataMethods"] = [
            {"methodIndex": m.get("method_index"), "typeName": m.get("type_name"),
             "methodName": m.get("method_name"), "methodRva": m.get("rva")}
            for m in annotations.get(rva, [])[:4]
        ]
        constant = int(row["immediate"], 16)
        row["rowCountIfAppliedToSourceHeader"] = {
            label: (((int(h["first4ByteLittleEndian"], 16) + constant) & U32)\n                    if row["operator"] == "add" else\n                    (int(h["first4ByteLittleEndian"], 16) ^ constant))
            for label, h in raw_headers.items()
        }
        row["plausibleSceneCountForEitherSource"] = any(
            100 <= row["rowCountIfAppliedToSourceHeader"][label] <= 20000
            for label in ("SceneTag", "SceneExcel")
        )
    plausible = [row for row in hits if row["plausibleSceneCountForEitherSource"]]
    # Include full list when bounded, but don't claim every match is a method.
    return {
        "schemaVersion": 1,
        "status": "GLOBAL_7_1_NATIVE_EXCEL_LOADER_SIGNATURE_CANDIDATES__SCENE_ROW_OWNER_UNVERIFIED",
        "client": PROFILE_71.identity,
        "exeSha256": PROFILE_71.exe_sha256,
        "sourceHeaders": raw_headers,
        "verifiedPositiveGadgetLoader": gadget[0]["candidateMovRva"],
        "nativeSignature": "mov r32,imm32; add/xor r32,[rax+rcx+0x20]",
        "candidateTotal": len(hits),
        "plausibleSceneCountCandidates": len(plausible),
        "plausibleCandidates": plausible,
        "allInstructionPatternCandidates": hits,
        "limits": [
            "Source exports require exact official SHA-256; Gadget instruction is a verified positive control.",
            "The historical 1147 SceneTag and 2377 SceneExcel counts are ranking hints from historical AstaPS-Resource, not authenticated original 7.1 row counts.",
            "A 9-byte byte-pattern hit is not a verified aligned instruction until native disassembly and method ownership are checked.",
            "This searches the exact Gadget loader add idiom and its matching-register XOR variant; other reader styles, register layouts and multi-step count decoding remain out of scope.",
            "No SceneTag drop_tag meaning, scene instance, server payout root or reward probability is inferred.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", required=True, type=Path)
    p.add_argument("--methods", required=True, type=Path)
    p.add_argument("--exports", required=True, type=Path,
                   help="MiHoYoBinData directory from the exact 7.1 official block")
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    result = audit(args.exe, args.methods, args.exports)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != result:
            raise SystemExit("native loader pattern evidence changed")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n",
                               encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "candidateTotal": result["candidateTotal"],
        "plausibleSceneCountCandidates": result["plausibleSceneCountCandidates"],
        "positiveGadgetLoader": result["verifiedPositiveGadgetLoader"],
        "plausibleCandidates": result["plausibleCandidates"][:12],
    }, indent=2))


if __name__ == "__main__":
    main()
