#!/usr/bin/env python3
"""Find native 7.1 audio/handbook table loader candidates by source-gated headers.

This tests finite one-step original-count hypotheses, without promoting
community JSON rows to original client counts or assuming reader ownership.
Only the exact original Global 7.1 EXE and source-pinned raw exports pass.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

U32 = 0xFFFFFFFF
MAX_TOTAL_SITES = 2000
SOURCES = {
    "audioChestType": {
        "filename": "5560e262.dat",
        "rawSha256": "c205c6d4efe69fde2b88800802816afd981a94df35e768746f5692e74febe591",
        "payloadSha256": "a59a480b86a0fcb85d7b0e4d72f631d1b78b6e2d87b58ac579c91ec4a9147257",
        "communityCountHypothesis": 56,
    },
    "handbookOpenChest": {
        "filename": "20c111a6.dat",
        "rawSha256": "417c4a73694b0d1d616929b0f6b4c1578575ce83ef03ec938e1b9197d40868d4",
        "payloadSha256": "fe23acff1adb3d7e2e5e3f2ba1552b5343a25a048af6509f6e91cd83e064e0e5",
        "communityCountHypothesis": 252,
    },
}
# Source-positive Gadget table loader: mov edi,0x23F5AB5E; add edi,[rax+rcx+0x20].
GADGET_POSITIVE_RVA = 0x968F6D9
GADGET_POSITIVE_SIGNATURE = "bf5eabf523037c0820"
GADGET_POSITIVE_OPCODE = "add"


def candidate_constants(header: int, count: int) -> dict[str, int]:
    if not 0 <= header <= U32 or not 1 <= count < 1_000_000:
        raise ValueError("invalid source header/count hypothesis")
    return {
        "add": (count - header) & U32,
        "sub": (header - count) & U32,
        "xor": header ^ count,
    }


def signature_hits(section: bytes, section_rva: int, allowed: set[tuple[str, int]]) -> list[dict]:
    """Nine-byte Gadget-style MOV immediate then matching ADD/XOR, file-backed."""
    rows = []
    for operation, opcode in (("add", 0x03), ("xor", 0x33)):
        start = 5
        while (at := section.find(bytes([opcode]), start)) >= 0:
            start = at + 1
            if at + 4 > len(section) or section[at + 2:at + 4] != b"\x08\x20":
                continue
            modrm = section[at + 1]
            if (modrm & 0xC7) != 0x44:
                continue
            reg = (modrm >> 3) & 7
            if section[at - 5] != 0xB8 + reg:
                continue
            immediate = int.from_bytes(section[at - 4:at], "little")
            if (operation, immediate) not in allowed:
                continue
            rows.append({
                "rva": section_rva + at - 5,
                "operator": operation,
                "immediate": immediate,
                "signatureHex": section[at - 5:at + 4].hex(),
            })
            if len(rows) > MAX_TOTAL_SITES:
                raise ValueError("too many Gadget-style candidate signatures")
    return rows


def inspect_source(raw: bytes, name: str) -> dict:
    spec = SOURCES[name]
    if hashlib.sha256(raw).hexdigest() != spec["rawSha256"]:
        raise ValueError(f"{name} original source raw SHA-256 mismatch")
    payload = unwrap_mihoyo_bin_data(raw)
    if hashlib.sha256(payload).hexdigest() != spec["payloadSha256"]:
        raise ValueError(f"{name} original payload SHA-256 mismatch")
    header = int.from_bytes(payload[:4], "little")
    return {
        "rawSha256": spec["rawSha256"],
        "payloadSha256": spec["payloadSha256"],
        "payloadBytes": len(payload),
        "rawHeaderHex": payload[:4].hex(),
        "rawHeaderLE": f"0x{header:08X}",
        "hypotheticalCommunityRowCount": spec["communityCountHypothesis"],
        "hypotheticalNativeArithmeticConstants": {
            op: f"0x{value:08X}"
            for op, value in candidate_constants(header, spec["communityCountHypothesis"]).items()
        },
    }


def inspect_sections(sections: list[tuple[int, bytes]], sources: dict) -> dict:
    needles: dict[bytes, list[tuple[str, str]]] = {}
    for name, detail in sources.items():
        for operator, word in detail["hypotheticalNativeArithmeticConstants"].items():
            raw = int(word, 16).to_bytes(4, "little")
            needles.setdefault(raw, []).append((name, operator))
    all_matches = {name: [] for name in sources}
    allowed = {(GADGET_POSITIVE_OPCODE, 0x23F5AB5E)}
    for detail in sources.values():
        allowed.update(
            (op, int(detail["hypotheticalNativeArithmeticConstants"][op], 16))
            for op in ("add", "xor")
        )
    signature = []
    positive = []
    for start, code in sections:
        for found in signature_hits(code, start, allowed):
            if found["rva"] == GADGET_POSITIVE_RVA:
                positive.append(found)
            if any(
                found["operator"] == op and found["immediate"] ==
                int(detail["hypotheticalNativeArithmeticConstants"][op], 16)
                for detail in sources.values() for op in ("add", "xor")
            ):
                signature.append(found)
        for needle, owners in needles.items():
            offset = 0
            while (pos := code.find(needle, offset)) >= 0:
                offset = pos + 1
                if sum(len(x) for x in all_matches.values()) >= MAX_TOTAL_SITES:
                    raise ValueError("unbounded 7.1 hypothesis literal scan")
                site = {"candidateImmediateRva": f"0x{start+pos:X}",
                        "contextHex": code[max(pos - 8, 0):pos + 12].hex()}
                for name, op in owners:
                    all_matches[name].append({"operation": op, **site})
    if len(positive) != 1 or positive[0]["signatureHex"] != GADGET_POSITIVE_SIGNATURE or positive[0]["operator"] != GADGET_POSITIVE_OPCODE:
        raise ValueError("exact Gadget loader source-positive signature missing")
    out = {}
    for name, detail in sources.items():
        hits = all_matches[name]
        associated = [m for m in signature
                      if any(m["operator"] == op and m["immediate"] ==
                             int(detail["hypotheticalNativeArithmeticConstants"][op], 16)
                             for op in ("add", "xor"))]
        out[name] = {
            **detail,
            "literalImmediateHits": len(hits),
            "literalHitByOperation": dict(sorted(Counter(x["operation"] for x in hits).items())),
            "literalCandidateSites": hits,
            "gadgetIdiomSignatureCandidates": associated,
        }
    return {
        "schemaVersion": 1,
        "status": "EXACT_71_NATIVE_AUDIO_HANDBOOK_COUNT_TRANSFORM_CANDIDATES__LOADERS_UNVERIFIED",
        "originalExeSha256": PROFILE_71.exe_sha256,
        "gadgetPositiveLoaderSignature": f"0x{GADGET_POSITIVE_RVA:X}",
        "tables": out,
        "limits": [
            "56 and 252 remain counts from public copied JSON, not original native table counts.",
            "Four-byte literal matches may be unaligned arbitrary machine bytes; matching MOV/ADD or MOV/XOR idiom is still not an authenticated loader without disassembly.",
            "The scan is bounded to a few single-step arithmetic transforms; absence of a candidate does not rule out an original native loader.",
            "No instance scene/group/config, drop_tag, server loot grade, amount or chance is verified.",
        ],
    }


def audit(exe: Path, exports: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="original Global 7.1 EXE")
    sources = {name: inspect_source((exports / spec["filename"]).read_bytes(), name)
               for name, spec in SOURCES.items()}
    sections = []
    with PEImage(exe) as pe:
        for section in pe.sections:
            if section.characteristics & 0x20000000:
                sections.append((section.virtual_address,
                                 pe.read_rva(section.virtual_address, section.raw_size)))
    return inspect_sections(sections, sources)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, required=True)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    result = audit(a.exe, a.exports)
    if a.output:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "tables": {k: {
            "header": v["rawHeaderLE"], "hypotheticalCounts": v["hypotheticalCommunityRowCount"],
            "immediates": v["hypotheticalNativeArithmeticConstants"],
            "hits": v["literalHitByOperation"],
            "gadgetIdiom": v["gadgetIdiomSignatureCandidates"][:12]
        } for k, v in result["tables"].items()}
    }, indent=2))


if __name__ == "__main__":
    main()
