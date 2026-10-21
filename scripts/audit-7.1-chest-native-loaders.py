#!/usr/bin/env python3
"""Disassemble exact Global 7.1 Audio/Investigation loader and Audio row leads.

Each entry is a source-pinned original executable instruction-region candidate,
not automatically a vtable owner or correct serialized-row parser.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

TARGETS = {
    "audioLoader": {
        "entryRva": 0x130156D0,
        "size": 0x260,
        "movRva": 0x13015719,
        "xorRva": 0x1301571E,
        "immediate": 0x81F9C781,
        "rawHeader": 0x81F9C7B9,
        "communityRowCountHypothesis": 56,
    },
    "investigationLoader": {
        "entryRva": 0xB0128D0,
        "size": 0x260,
        "movRva": 0xB012919,
        "xorRva": 0xB01291E,
        "immediate": 0x6F0ECCD2,
        "rawHeader": 0x6F0ECC2E,
        "communityRowCountHypothesis": 252,
    },
    "audioRowReaderCandidate": {
        "entryRva": 0x77C01B0,
        "size": 0x320,
        "typeDefinitionIndexCandidate": 36519,
        "methodIndexCandidate": 287887,
        "methodNameCandidate": "LAGPEMOIAKN.GMENPOPMKAA",
    },
}
MAX_INSTRUCTION_ROWS = 1000


def verify(disasm: dict[str, dict]) -> dict:
    reports = {}
    for key, target in TARGETS.items():
        src = disasm[key]
        if (src.get("exe_sha256") != PROFILE_71.exe_sha256
                or int(src["start_rva"], 16) != target["entryRva"]
                or int(src["size"]) != target["size"]):
            raise ValueError(f"{key}: original EXE or exact RVA range mismatch")
        rows = src["instructions"]
        if not rows or len(rows) > MAX_INSTRUCTION_ROWS:
            raise ValueError(f"{key}: invalid bounded native instruction count")
        by_rva = {int(row["rva"], 16): row for row in rows}
        if len(by_rva) != len(rows):
            raise ValueError(f"{key}: repeated RVA in original disassembly")
        if "movRva" in target:
            mov = by_rva.get(target["movRva"])
            xor = by_rva.get(target["xorRva"])
            if (mov is None or (mov["mnemonic"], mov["op_str"]) !=
                    ("mov", f"edi, 0x{target['immediate']:x}")):
                raise ValueError(f"{key}: original native row-count MOV anchor mismatch")
            if (xor is None or (xor["mnemonic"], xor["op_str"]) !=
                    ("xor", "edi, dword ptr [rax + rcx + 0x20]")):
                raise ValueError(f"{key}: original native row-count XOR anchor mismatch")
            native_count = target["rawHeader"] ^ target["immediate"]
            if native_count != target["communityRowCountHypothesis"]:
                raise ValueError(f"{key}: count-hypothesis arithmetic changed")
        else:
            native_count = None
        virtual = [r for r in rows if (r["mnemonic"] == "call"
                   and ("[rax + 0xf0]" in r["op_str"] or
                        "[rcx + 0xf0]" in r["op_str"] or
                        "[rdx + 0xf0]" in r["op_str"]))]
        signatures = Counter(r["mnemonic"] for r in rows)
        near = [r for r in rows if (key == "audioRowReaderCandidate" and
                int(r["rva"], 16) < target["entryRva"] + 0xE0) or
                (key != "audioRowReaderCandidate" and
                 target["entryRva"] + 0x25 <= int(r["rva"], 16) < target["entryRva"] + 0x165)]
        reports[key] = {
            "candidateMethodEntryRva": f"0x{target['entryRva']:X}",
            "originalInstructionCount": len(rows),
            "disassemblySourceSha256": src.get("verifiedDisassemblySha256"),
            "fixedCountHypothesisFromHeaderAndNativeXor": native_count,
            "nativeCountInstructionAnchorsVerified": "movRva" in target,
            "observedVirtualF0CallsInWindow": [
                {"rva": r["rva"], "op": r["op_str"]} for r in virtual[:10]
            ],
            "nativeMnemonicHistogram": dict(sorted(signatures.items())),
            "originalInstructionExcerpt": [{
                "rva": r["rva"], "hex": r["bytes"],
                "mnemonic": r["mnemonic"], "operands": r["op_str"],
            } for r in near],
        }
    return {
        "schemaVersion": 1,
        "status": "EXACT_71_AUDIO_HANDBOOK_HEADER_INSTRUCTION_DISASM__ROW_VTABLE_UNVERIFIED",
        "originalExeSha256": PROFILE_71.exe_sha256,
        "sourceMethodHypothesis": "Audio row type LAGPEMOIAKN method 287887 at 0x77C01B0 from original pinned metadata",
        "regions": reports,
        "limitations": [
            "An exact MOV/XOR table-header transform shows native code can produce the community row-count candidate; ownership and loops still require flow analysis.",
            "Vtable +0xF0 callsite and candidate row reader must be tied to an original runtime class registration before the reader identity is proven.",
            "A bounded linear disassembly may read into the next function, so only anchored addresses within a known method may be promoted.",
            "No original audio labels, actual investigation trigger, scene placement, server drop_tag, payout root, amount or weight has been authenticated.",
        ],
    }


def audit(exe: Path) -> dict:
    from tools.disassemble_rva import disassemble_rva

    disasm = {
        key: disassemble_rva(
            exe, t["entryRva"], t["size"],
            expected_sha256=PROFILE_71.exe_sha256, label=key)
        for key, t in TARGETS.items()
    }
    return verify(disasm)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = audit(args.exe)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n",
                           encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "regions": {k: {
            "countTransform": v["fixedCountHypothesisFromHeaderAndNativeXor"],
            "virtualF0Calls": v["observedVirtualF0CallsInWindow"],
            "excerptRows": len(v["originalInstructionExcerpt"])
        } for k,v in result["regions"].items()}
    }, indent=2))


if __name__ == "__main__":
    main()
