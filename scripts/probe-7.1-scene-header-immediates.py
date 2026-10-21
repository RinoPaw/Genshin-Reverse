#!/usr/bin/env python3
"""Locate bounded candidate 7.1 native SceneExcel/SceneTag row-count decoders.

Only tests arithmetic-immediate byte patterns implied by two historical
server/resource JSON row counts. Those counts have NOT been authenticated
against the native 7.1 binary. An immediate match is a byte-pattern lead
and does not identify a native loader without aligned disassembly.

Zero matches falsifies only the exact hypothesized immediate encoding in
file-backed executable sections; other count transforms or differing row
counts are outside the experiment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from genshinre.callxref import attach_caller_methods
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

SOURCES = {
    "SceneTagConfigData": {
        "rawExportSha256": "f0cada8ea11c59fb32b72f0dd19e3aaf69af31382ed012573b9de92954567075",
        "payloadSha256": "9c043ecdbfba6a17c00243b37ae2bb3566ac9c09dcf800b648a76c3e113958ee",
        "historicalRows": 1147,
    },
    "SceneExcelConfigData": {
        "rawExportSha256": "970ffecdec5b1f9368b6db5c7c0129a9f0b9ba624f81d5289e3142572caebb8d",
        "payloadSha256": "588563f62149d62038c7ee3b179e50191ecc9a3cfc003353e18a831918d27f6a",
        "historicalRows": 2377,
    },
}
U32 = (1 << 32) - 1


def candidates(payload: bytes, hypothetical_count: int) -> dict[str, int]:
    if len(payload) < 4 or not 0 < hypothetical_count < 100_000:
        raise ValueError("invalid bounded native count hypothesis")
    header = int.from_bytes(payload[:4], "little")
    return {
        "addModulo32": (hypothetical_count - header) & U32,
        "subModulo32": (header - hypothetical_count) & U32,
        "xor32": header ^ hypothetical_count,
    }


def inspect(exe: Path, methods_csv: Path, exports: dict[str, bytes]) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="exact 7.1 client EXE")
    sources = {}
    needle_map: dict[bytes, list[tuple[str, str]]] = {}
    for name, meta in SOURCES.items():
        raw = exports[name]
        if hashlib.sha256(raw).hexdigest() != meta["rawExportSha256"]:
            raise ValueError(f"original {name} SHA-256 mismatch")
        if len(raw) < 4:
            raise ValueError(f"truncated {name} length frame")
        frame = int.from_bytes(raw[:4], "little")
        if frame > len(raw) - 4:
            raise ValueError(f"corrupt {name} raw frame")
        payload = raw[4:4 + frame]
        if hashlib.sha256(payload).hexdigest() != meta["payloadSha256"]:
            raise ValueError(f"original {name} payload SHA-256 mismatch")
        transforms = candidates(payload, meta["historicalRows"])
        sources[name] = {
            "payloadSha256": meta["payloadSha256"],
            "headerU32": f"0x{int.from_bytes(payload[:4], 'little'):08X}",
            "historicalJsonRowCountHypothesis": meta["historicalRows"],
            "candidateImmediateTransforms": {
                key: f"0x{value:08X}" for key, value in transforms.items()
            },
            "literalHitCounts": {},
            "candidateSites": [],
        }
        for op, word in transforms.items():
            needle_map.setdefault(struct.pack("<I", word), []).append((name, op))

    sites: list[tuple[str, str, int, str, str]] = []
    with PEImage(exe) as pe:
        for section in pe.sections:
            if not (section.characteristics & 0x20000000):
                continue
            code = pe.read_rva(section.virtual_address, section.raw_size)
            for needle, owners in needle_map.items():
                pos = 0
                while (at := code.find(needle, pos)) >= 0:
                    pos = at + 1
                    rva = section.virtual_address + at
                    for name, operation in owners:
                        sites.append((name, operation, rva, section.name,
                                      code[max(0,at-12):at+16].hex()))
                    if len(sites) > 2000:
                        raise ValueError("native immediate byte-pattern hits are unbounded")
    attribution = attach_caller_methods(sorted({site[2] for site in sites}),
                                        methods_csv, max_method_body=0x10000)
    for name, op, rva, section, window in sites:
        sources[name]["candidateSites"].append({
            "candidateOperation": op,
            "immediateBytesAtRva": f"0x{rva:X}",
            "section": section,
            "unalignedWindowHex": window,
            "nearestMetadataMethods": [
                {
                    "methodIndex": m.get("method_index"),
                    "rva": m.get("rva"),
                    "typeName": m.get("type_name"),
                    "methodName": m.get("method_name"),
                } for m in attribution[rva][:4]
            ],
        })
    for name in sources:
        results = sources[name]
        results["literalHitCounts"] = {
            op: sum(site["candidateOperation"] == op for site in results["candidateSites"])
            for op in ("addModulo32", "subModulo32", "xor32")
        }
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_SCENE_TABLE_COUNT_IMMEDIATE_HYPOTHESES__NATIVE_LOADER_UNVERIFIED",
        "exeSha256": PROFILE_71.exe_sha256,
        "sources": sources,
        "limitations": [
            "Input raw SceneExcel and SceneTag files are SHA-256 pinned to the exact 7.1 Global Sophon export.",
            "Historical JSON counts 1147 and 2377 are only count hypotheses and do not authenticate the original binary row counts.",
            "Matched little-endian 4-byte immediate patterns in executable sections may be within arbitrary instructions or data; native disassembly is mandatory.",
            "Only one-step add, subtract and xor transforms with a direct 32-bit immediate are tested; absent matches do not exclude other native encodings.",
            "This research gives no original chest scene instance, drop_tag field, server payout root or reward probability.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--methods", type=Path, required=True)
    parser.add_argument("--scene-excel", type=Path, required=True)
    parser.add_argument("--scene-tag", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = inspect(args.exe, args.methods, {
        "SceneExcelConfigData": args.scene_excel.read_bytes(),
        "SceneTagConfigData": args.scene_tag.read_bytes(),
    })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n",
                           encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "summary": {
            name: {
                "headerU32": data["headerU32"],
                "hypothesizedRows": data["historicalJsonRowCountHypothesis"],
                "transforms": data["candidateImmediateTransforms"],
                "hits": data["literalHitCounts"],
                "sites": data["candidateSites"][:8],
            } for name, data in report["sources"].items()
        },
    }, indent=2))


if __name__ == "__main__":
    main()
