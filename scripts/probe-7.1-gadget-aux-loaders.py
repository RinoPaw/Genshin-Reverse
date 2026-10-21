#!/usr/bin/env python3
"""Source-pinned Global 7.1 GadgetProp/GadgetInteract native count-loader leads.

Original client PE and MiHoYoBinData Raw-export SHA-256 are required.
A matching x86 MOV + ADD/XOR count idiom is a *candidate*, never by itself
a verified table owner, binary row reader, chest grade or scene level.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.callxref import attach_caller_methods
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "native_scene_count_probe", ROOT / "scripts/probe-7.1-scene-loader-counts.py")
loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loader)

SOURCES = {
    "GadgetExcelConfigData": (
        "d65ab32f.dat",
        "a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35",
        "b8f35d6f3fe1aec90398ccbbe205335fe0d9ae45245b206096be5e434746c354"),
    "GadgetPropExcelConfigData": (
        "e37e8728.dat",
        "8907f4b717cd450ce084bd3a1a6a73e4409b8280fb4c74605afa520efbbc6a54",
        "a12f433fe834576f84cbd5521c5715a27dc64eed0ee0137eb0cb24573d38d091"),
    "GadgetInteractExcelConfigData": (
        "c71a7ea9.dat",
        "6481cd8b92185ffc13ffe8a12332eba8d53139077c75738aa40d15fc5bc8c24e",
        "ce9fcd3b2d7deb76c7e9f2a4ca2738f8d9e0e8500b7bb101768cd18be059fb11"),
}
MAX_SITES = 20000
U32 = 0xFFFFFFFF


def headers(export_dir: Path) -> dict:
    out = {}
    for label, (name, raw_hash, payload_hash) in SOURCES.items():
        raw = (export_dir / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != raw_hash:
            raise ValueError(f"{label}: original 7.1 Raw export mismatch")
        payload = unwrap_mihoyo_bin_data(raw)
        if hashlib.sha256(payload).hexdigest() != payload_hash or len(payload) < 8:
            raise ValueError(f"{label}: original 7.1 payload mismatch")
        out[label] = {"header": int.from_bytes(payload[:4], "little"),
                      "bytes": len(payload), "rawSha256": raw_hash,
                      "payloadSha256": payload_hash}
    return out


def count_candidates(instructions: list[dict], source_headers: dict) -> dict:
    """Test a bounded native idiom population without guessed community counts."""
    if len(instructions) > MAX_SITES:
        raise ValueError("unbounded exact-original native count-idiom population")
    out = {}
    for label, header in source_headers.items():
        rows = []
        upper_bound = (header["bytes"] - 4) // 4
        for ins in instructions:
            n = int(ins["immediate"], 16)
            count = (header["header"] + n) & U32 if ins["operator"] == "add" else header["header"] ^ n
            if 1 <= count <= upper_bound:
                rows.append({
                    "movRva": ins["candidateMovRva"],
                    "arithmeticRva": ins["candidateArithmeticRva"],
                    "operation": ins["operator"], "immediate": ins["immediate"],
                    "instructionBytes": ins["signatureHex"], "decodedCountIfMatched": count,
                })
        rows.sort(key=lambda x: int(x["movRva"], 16))
        out[label] = {
            "rawSha256": header["rawSha256"],
            "payloadSha256": header["payloadSha256"],
            "rawHeaderLittleEndian": f"0x{header['header']:08X}",
            "payloadBytes": header["bytes"],
            "fourBytesPerRowUpperBound": upper_bound,
            "candidateCount": len(rows),
            "candidates": rows,
        }
    return out


def investigate(exe: Path, methods: Path, exported: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="Global 7.1 original EXE")
    source_headers = headers(exported)
    instructions = []
    with PEImage(exe) as pe:
        for section in pe.sections:
            if not (section.characteristics & 0x20000000):
                continue
            code = pe.read_rva(section.virtual_address, section.raw_size)
            instructions.extend(loader.candidates_in_section(code, section.virtual_address))
            if len(instructions) > MAX_SITES:
                raise ValueError("too many native count idiom candidates")
    positives = [x for x in instructions if x["candidateMovRva"] == "0x968F6D9"
                 and x["operator"] == "add" and x["immediate"] == "0x23F5AB5E"]
    if len(positives) != 1:
        raise ValueError("missing original 7.1 Gadget native loader positive control")
    tables = count_candidates(instructions, source_headers)
    if not any(r["movRva"] == "0x968F6D9" and r["decodedCountIfMatched"] == 30599
               for r in tables["GadgetExcelConfigData"]["candidates"]):
        raise ValueError("original Gadget source header did not decode the proven row count")
    matching = sorted({int(r["movRva"], 16)
                      for name in SOURCES for r in tables[name]["candidates"]})
    owners = attach_caller_methods(matching, methods)
    for table in tables.values():
        for row in table["candidates"]:
            row["nativeMetadataOwnerCandidates"] = [{
                "methodIndex": x.get("method_index"),
                "typeDefinitionIndex": x.get("type_definition_index"),
                "typeName": x.get("type_name"), "methodRva": x.get("rva")
            } for x in owners.get(int(row["movRva"], 16), [])[:3]]
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_GADGET_AUXILIARY_NATIVE_COUNT_IDIOM_CANDIDATES__ROW_SEMANTICS_UNKNOWN",
        "originalExeSha256": PROFILE_71.exe_sha256,
        "nativeIdiom": "mov r32, imm32; add/xor r32, [rax+rcx+0x20]",
        "verifiedGadgetLoaderMovRva": "0x968F6D9",
        "totalNativeIdiomSites": len(instructions),
        "tables": tables,
        "limits": [
            "Only exact Global 7.1 original EXE and original Raw-export hash-verified headers are accepted.",
            "A matching count transform is a candidate: method ownership and virtual row reader are separate proof gates.",
            "The four-byte upper bound is deliberately permissive, not a reconstructed native row schema.",
            "Other encoded count operations and register/memory layouts are not covered by this scan.",
            "No loot contents, private-server field names, chest grade, instance level or type semantics are inferred.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, required=True)
    p.add_argument("--methods", type=Path, required=True)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    report = investigate(a.exe, a.methods, a.exports)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "totalNativeIdiomSites": report["totalNativeIdiomSites"],
        "candidateLoaders": {
            name: {"count": report["tables"][name]["candidateCount"],
                   "sites": report["tables"][name]["candidates"][:12]}
            for name in ("GadgetPropExcelConfigData", "GadgetInteractExcelConfigData")
        },
    }, indent=2))


if __name__ == "__main__":
    main()
