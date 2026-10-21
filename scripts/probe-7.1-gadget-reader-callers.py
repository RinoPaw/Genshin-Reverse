#!/usr/bin/env python3
"""Trace potential callers of the pinned Global 7.1 Gadget inner-row reader.

Direct E8/rel32 byte matches and aligned method-address pointer holders are
independent, narrowly defined xref candidates. They do not prove the
parent-table loader, row-count encoding or indirect runtime dispatch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.callxref import scan_direct_call_xrefs
from genshinre.nativeprofile import PROFILE_71
from genshinre.pointerxref import scan_pointer_xrefs
from genshinre.sampleidentity import require_sha256

TARGET_RVA = 0x10278E50
METHODS_GIT_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"


def git_blob(path: Path) -> str:
    size = path.stat().st_size
    result = hashlib.sha1()
    result.update(f"blob {size}\0".encode("ascii"))
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def summarize(direct: dict, pointers: dict) -> dict:
    calls = direct["matches"].get(f"0x{TARGET_RVA:X}", [])
    holders = pointers["holders"]
    caller_count = sum(len(row.get("caller_methods", [])) for row in calls)
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_GADGET_READER_CANDIDATE_XREFS__LOADER_UNVERIFIED",
        "target": PROFILE_71.identity,
        "executableSha256": PROFILE_71.exe_sha256,
        "methodsCsvGitBlob": METHODS_GIT_BLOB,
        "nativeReaderRva": f"0x{TARGET_RVA:X}",
        "nativeReaderMethodIndex": 483590,
        "nativeReaderOwner": "DCCHEHMHFGC",
        "directCallPattern": "x86-64 E8 rel32",
        "directCallCandidateCount": len(calls),
        "directCallCandidates": calls,
        "methodRowsAttributedToDirectCandidates": caller_count,
        "alignedMethodPointerCandidateCount": pointers["holder_count"],
        "methodPointersWithSimpleRipXrefs": pointers["holders_with_code_xrefs"],
        "methodPointerCandidates": holders,
        "limits": [
            "E8 matches are byte-pattern candidates until aligned instruction streams are verified.",
            "Method annotations use nearest preceding metadata method RVA, with bounded inferred method-body length.",
            "Aligned pointer candidates alone do not identify call behavior.",
            "No matched caller is assumed to decode table headers, four-byte ID candidates, or outer prefix fields without disassembly.",
            "Indirect calls, encrypted pointers and non-executable dispatch routes are outside the bounded xref scanner.",
            "Client native gadget definition readers do not authenticate scene drop tags or server reward tables.",
        ],
    }


def run(exe: Path, methods: Path) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="exact 7.1 GenshinImpact.exe")
    if git_blob(methods) != METHODS_GIT_BLOB:
        raise ValueError("7.1 methods.csv Git blob mismatch")
    direct = scan_direct_call_xrefs(
        exe, [TARGET_RVA], methods_csv=methods,
        max_method_body=0x10000, window=32)
    pointers = scan_pointer_xrefs(
        exe, TARGET_RVA, TARGET_RVA + 1,
        alignment=8, window=32)
    return summarize(direct, pointers)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--methods", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.exe, args.methods)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "directCallCandidateCount": result["directCallCandidateCount"],
        "methodRowsAttributedToDirectCandidates": result["methodRowsAttributedToDirectCandidates"],
        "alignedMethodPointerCandidateCount": result["alignedMethodPointerCandidateCount"],
        "methodPointersWithSimpleRipXrefs": result["methodPointersWithSimpleRipXrefs"],
        "directCallSites": [x["instruction_rva"] for x in result["directCallCandidates"]],
    }, indent=2))


if __name__ == "__main__":
    main()
