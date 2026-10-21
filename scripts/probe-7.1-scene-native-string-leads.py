#!/usr/bin/env python3
"""Bounded original Global 7.1 native scene table/lua literal xref probe.

Uses the maintained PE string and RIP-relative reference scanners. Searches
plain ASCII and UTF-16LE bytes only, so zero matches do not prove the
table/field/script missing from the game or the official server.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.sampleidentity import require_sha256
from genshinre.stringxref import find_pe_string_hits
from genshinre.xrefs import scan_rip_xrefs

LITERALS = (
    "SceneExcelConfigData",
    "SceneTagConfigData",
    "ScenePoint",
    "scene3_group133003154",
    "Scripts/Scene",
    "drop_tag",
    "chest_drop_id",
    "GadgetExcelConfigData",
)
ENCODINGS = ("ascii", "utf-16le")


def analyze(exe: Path, methods_csv: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="Global 7.1 GenshinImpact.exe")
    hits_by_literal = {}
    all_rvas = set()
    for value in LITERALS:
        hits = find_pe_string_hits(exe, value, encodings=ENCODINGS)
        if len(hits) > 50:
            raise ValueError(f"unbounded native literal hit count for {value}")
        hits_by_literal[value] = hits
        all_rvas.update(int(row["rva"], 16) for row in hits)
    # Source xrefs are candidate instruction byte patterns until checked in
    # an aligned native disassembly. Empty target sets are a valid scoped result.
    xrefs = scan_rip_xrefs(
        exe, sorted(all_rvas), window=16,
        methods_csv=methods_csv, max_method_body=0x10000,
    ) if all_rvas else {"matches": {}}

    groups = {}
    for literal, hits in hits_by_literal.items():
        evidence = []
        for hit in hits:
            references = xrefs["matches"].get(hit["rva"], [])
            evidence.append({
                "encodedAs": hit["encoding"],
                "originalSection": hit["section"],
                "originalRva": hit["rva"],
                "rvaReferences": [
                    {
                        "instructionRva": ref["instruction_rva"],
                        "kind": ref.get("access"),
                        "candidateOwners": ref.get("caller_methods", [])[:5],
                    } for ref in references[:20]
                ],
                "rawRipReferenceCount": len(references),
            })
        groups[literal] = {
            "exactPlainLiteralCount": len(hits),
            "positiveBytesOnly": bool(hits),
            "hitAndCandidateReferences": evidence,
        }
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_NATIVE_SCENE_TABLE_LITERAL_PROBE__NATIVE_FIELD_SEMANTICS_UNRESOLVED",
        "sample": PROFILE_71.identity,
        "exeSha256": PROFILE_71.exe_sha256,
        "encodings": list(ENCODINGS),
        "examinedLiterals": len(LITERALS),
        "literalCandidates": groups,
        "limitations": [
            "A missing ASCII/UTF-16LE literal in original client PE file-backed sections does not prove absence of an encoded/obfuscated table path or runtime-generated string.",
            "The scene3_group path is an unverified historical server Lua identifier, not an authenticated official 7.1 scene placement.",
            "RIP-relative byte matches and nearest-method annotations are leads only; native instruction disassembly and source-owner validation are still required.",
            "SceneTag and server chest drop_tag are semantically distinct pending exact 7.1 method and field evidence.",
            "No original client string alone authenticates server payout roots, drop probabilities or reward amounts.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--methods", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = analyze(args.exe, args.methods)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("original 7.1 scene native string leads diverged")
        print("PASS: exact 7.1 native scene literal probe")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "counts": {name: row["exactPlainLiteralCount"]
                   for name, row in report["literalCandidates"].items()},
    }, indent=2))


if __name__ == "__main__":
    main()
