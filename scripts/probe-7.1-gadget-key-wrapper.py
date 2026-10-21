#!/usr/bin/env python3
"""Verify the original 7.1 Gadget inherited scalar wrapper/getter relationship.

This evidence stops at native instruction identity. The runtime byte tables
used by the wrapper are initialized dynamically and are not reconstructed
from these bounded static slices; never publish pre-wrapper uint32 values as
authenticated runtime-managed field values without validating the tables.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

ROOT = Path(__file__).resolve().parents[1]
REPORT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-native-gadget-key-wrapper-evidence.json")
SOURCES = {
    "inherited": ("0xBD56F60",
                  "d52f3a83a010f744a38471b980ef1b94125f355856985de1212c4c71eb147d21"),
    "wrapper": ("0xBB16020",
                "e206c1c9f062e4d8277d05ece74e7bcc63c8a6c8edaf03248937eaa6a898c581"),
    "getter": ("0xBB15F50",
               "f7649f42eee426295c45a46cee98e72333c420c59a714e833535d8b1dc6ed319"),
    "loader": ("0x968F690",
               "c0a6cc4f9b686002e1ee3c98bf9d9aeed749fcc10d9ea95f70161066592b744b"),
}
# Exact RVA, mnemonic and Capstone operands from pinned Global 7.1 slices.
ANCHORS = {
    "inherited": (
        ("0xBD56FCF", "add", "esi, 0x5486"),
        ("0xBD57223", "mov", "edx, 0xc6e69ca5"),
        ("0xBD5723B", "call", "0x14bb16020"),
        ("0xBD57243", "mov", "dword ptr [r12 + 0x18], eax"),
        ("0xBD5734B", "mov", "ebx, 0x4894cea6"),
        ("0xBD57365", "call", "0x14bb16020"),
        ("0xBD5736D", "mov", "dword ptr [r12 + 0x30], eax"),
    ),
    "wrapper": (
        ("0xBB1603C", "shr", "r8, 0x18"),
        ("0xBB16052", "or", "r10, 0x100"),
        ("0xBB16061", "or", "rdi, 0x200"),
        ("0xBB16070", "or", "rdx, 0x300"),
        ("0xBB1607C", "movzx", "eax, byte ptr [r11 + r8 + 0x20]"),
        ("0xBB16082", "movzx", "esi, byte ptr [r11 + r10 + 0x20]"),
        ("0xBB16088", "movzx", "edi, byte ptr [r11 + rdi + 0x20]"),
        ("0xBB1608E", "movzx", "edx, byte ptr [r11 + rdx + 0x20]"),
        ("0xBB160A3", "xor", "edi, dword ptr [rip - 0x638afa9]"),
        ("0xBB160A9", "mov", "dword ptr [rcx], edi"),
    ),
    "getter": (
        ("0xBB15F73", "xor", "ebx, dword ptr [rcx]"),
        ("0xBB15F7A", "or", "rax, 0x400"),
        ("0xBB15F91", "or", "rcx, 0x500"),
        ("0xBB15FA0", "or", "rsi, 0x600"),
        ("0xBB15FAF", "or", "rbx, 0x700"),
        ("0xBB15FBB", "movzx", "edx, byte ptr [r9 + rax + 0x20]"),
        ("0xBB15FC1", "movzx", "ecx, byte ptr [r9 + rcx + 0x20]"),
        ("0xBB15FC7", "movzx", "eax, byte ptr [r9 + rsi + 0x20]"),
        ("0xBB15FCD", "movzx", "ebx, byte ptr [r9 + rbx + 0x20]"),
    ),
    "loader": (
        ("0x968F6D9", "mov", "edi, 0x23f5ab5e"),
        ("0x968F76E", "call", "0x150278e50"),
        ("0x968F791", "mov", "eax, dword ptr [rbx + 0x30]"),
        ("0x968F79B", "call", "0x14bb15f50"),
    ),
}


def inspect(samples: dict[str, dict], digests: dict[str, str]) -> dict:
    for label, (rva, pinned_sha) in SOURCES.items():
        item = samples[label]
        if (digests[label] != pinned_sha
                or item["exe_sha256"] != PROFILE_71.exe_sha256
                or item["start_rva"] != rva):
            raise ValueError(f"pinned native {label} identity mismatch")
        by_rva = {row["rva"]: row for row in item["instructions"]}
        for at, mnemonic, operands in ANCHORS[label]:
            found = by_rva.get(at)
            if found is None or (found["mnemonic"], found["op_str"]) != (mnemonic, operands):
                raise ValueError(f"pinned native {label} instruction mismatch at {at}")
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_GADGET_U32_WRAPPER_AND_GETTER_TRACED__RUNTIME_TABLES_UNRESOLVED",
        "sample": PROFILE_71.identity,
        "exeSha256": PROFILE_71.exe_sha256,
        "sources": {label: {
            "rva": rva, "disassemblySha256": digest,
            "matchedAnchorCount": len(ANCHORS[label]),
        } for label, (rva, digest) in SOURCES.items()},
        "nativeRelationship": {
            "inheritedReader": "FGGKFGECPJJ.GMENPOPMKAA / method 395933",
            "preWrapperScalarOffsets": ["0x18", "0x30"],
            "wireIdScalarAdd": "0x4894CEA6",
            "writeWrapperRva": "0xBB16020",
            "readWrapperRva": "0xBB15F50",
            "writeByteLookupPages": ["0x000", "0x100", "0x200", "0x300"],
            "readByteLookupPages": ["0x400", "0x500", "0x600", "0x700"],
            "writeAdditionalXor": True,
            "readAdditionalXor": True,
            "tableLoader": "AACCGEFDDMD.GMENPOPMKAA / method 197827",
            "tableLoaderKeyFieldOffset": "0x30",
            "tableLoaderKeyGetterRva": "0xBB15F50",
            "runtimeLookupTableValues": "UNRESOLVED",
            "roundTripEquivalence": "UNVERIFIED",
        },
        "limitations": [
            "The serialized 32-bit value is directly decoded before a native byte-substitution wrapper.",
            "The managed field at offset 0x30 is stored after 0xBB16020, and the table loader reads it through 0xBB15F50.",
            "A paired writer/getter is strong evidence of an intended reversible value wrapper, but equivalence for all uint32 values is not proven from these instruction slices.",
            "The dynamically loaded substitution tables and XOR globals must be recovered or independently validated before claiming final runtime-managed ID identities.",
            "This provides no server-side scene identifier, drop tag or reward value.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for label in SOURCES:
        parser.add_argument("--" + label, type=Path, required=True)
    parser.add_argument("--output", type=Path, default=REPORT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = {label: getattr(args, label).read_bytes() for label in SOURCES}
    report = inspect(
        {label: json.loads(raw) for label, raw in files.items()},
        {label: hashlib.sha256(raw).hexdigest() for label, raw in files.items()})
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("native Gadget wrapper evidence differs from pinned disassembly")
        print("PASS: original client Gadget u32 wrapper/getter instructions match")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n",
                               encoding="utf-8")
        print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
