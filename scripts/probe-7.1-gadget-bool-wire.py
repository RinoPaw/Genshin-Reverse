#!/usr/bin/env python3
"""Recover narrowly evidenced Gadget boolean wire-byte comparisons from 7.1 disassembly.

The input is a local Github Actions disassembly artifact, pinned by SHA-256.
This reports compare instructions and native memory stores only. It does not
assert a source-level boolean meaning, schema, grade or payout rule.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from genshinre.nativeprofile import PROFILE_71

ROOT = Path(__file__).resolve().parents[1]
ECONOMY = ROOT / "versions/7.1.0-global/analyses/progression/economy"
LAYOUT = ECONOMY / "7.1-chest-native-gadget-layout-candidate.json"
READER = ECONOMY / "7.1-chest-native-gadget-reader-static.json"
OUTPUT = ECONOMY / "7.1-chest-native-gadget-boolean-wire.json"
STORE = re.compile(r"byte ptr \[r14 \+ (0x[0-9a-f]+)\], (al|cl)")
COMPARE = re.compile(r"(al|dl), (0x[0-9a-f]+)")
SOURCE_ARTIFACT_URL = "https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39475423384"


def inspect(disassembly: dict, layout: dict, reader: dict, *, source_sha256: str) -> dict:
    source = reader["source"]
    if (source_sha256 != source["disassemblyJsonSha256"]
            or disassembly["exe_sha256"] != PROFILE_71.exe_sha256
            or disassembly["start_rva"] != source["methodRva"]
            or disassembly["instruction_count"] != reader["disassembly"]["decodedInstructions"]
            or layout["readerRva"] != source["methodRva"]):
        raise ValueError("native Gadget disassembly or layout source identity mismatch")
    fields = {int(row["candidateInstanceOffset"], 16): row
              for row in layout["result"]["mapping"] if row["candidateWidth"] == 1}
    if len(fields) != 8 or set(fields) != set(range(0x78, 0x80)):
        raise ValueError("pinned candidate bool layout changed")
    found: dict[int, dict] = {}
    instructions = disassembly["instructions"]
    for index, ins in enumerate(instructions):
        m = STORE.fullmatch(ins["op_str"]) if ins["mnemonic"] == "mov" else None
        if not m:
            continue
        offset = int(m.group(1), 16)
        if offset not in fields:
            continue
        prior = instructions[max(0, index - 8):index]
        setne = [(i, op) for i, op in enumerate(prior) if op["mnemonic"] == "setne"
                 and op["op_str"] == m.group(2)]
        encoded = None
        if len(setne) == 1:
            setpos, setrow = setne[0]
            if setpos:
                previous = prior[setpos - 1]
                cmp = COMPARE.fullmatch(previous["op_str"]) if previous["mnemonic"] == "cmp" else None
                if cmp:
                    encoded = {
                        "comparisonRva": previous["rva"],
                        "inputRegister": cmp.group(1),
                        "encodedFalseByte": f"0x{int(cmp.group(2), 16):02X}",
                        "predicateRva": setrow["rva"],
                        "predicate": "SETNE",
                        "storeRva": ins["rva"],
                    }
        entry = found.setdefault(offset, {"decodedByteBranches": [], "zeroStores": []})
        if encoded:
            entry["decodedByteBranches"].append(encoded)
        elif any(op["mnemonic"] == "xor"
                 and op["op_str"] in ("ecx, ecx", "eax, eax") for op in prior):
            entry["zeroStores"].append(ins["rva"])
        else:
            raise ValueError(f"unclassified direct bool write at {ins['rva']}")

    if set(found) != set(fields) or any(len(v["decodedByteBranches"]) != 1
                                       for v in found.values()):
        raise ValueError("missing or ambiguous native bool compare/store sequence")

    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_GADGET_BOOLEAN_READ_BRANCHES__SEMANTICS_UNRESOLVED",
        "sample": PROFILE_71.identity,
        "source": {
            "workflowRun": SOURCE_ARTIFACT_URL,
            "disassemblyArtifact": "7.1-rva-disassembly/method-disassembly.json",
            "disassemblySha256": source_sha256,
            "exeSha256": PROFILE_71.exe_sha256,
            "readerRva": source["methodRva"],
            "layoutCandidate": LAYOUT.name,
        },
        "byteFields": [
            {
                "fieldName": fields[offset]["fieldName"],
                "fieldIndex": fields[offset]["fieldIndex"],
                "candidateMemoryOffset": f"0x{offset:X}",
                **found[offset],
            } for offset in sorted(found)
        ],
        "limits": [
            "Each decoded branch compares one encoded input byte with a fixed immediate, then SETNE writes one memory byte.",
            "The encoded comparison constant describes the zero/false branch for this reader, not a generic asset decryption key.",
            "Zero-write paths are only reported where the scanned basic region includes an explicit zero assignment.",
            "The field-to-offset association depends on the separately documented 22-field candidate memory layout.",
            "Presence mask linkage, file framing, original field semantics and full GadgetExcel row decoding remain unresolved.",
            "No chest grade, special context, tag source, server root or reward probabilities follow from these instructions.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassembly", type=Path, required=True)
    parser.add_argument("--layout", type=Path, default=LAYOUT)
    parser.add_argument("--reader", type=Path, default=READER)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    raw = args.disassembly.read_bytes()
    report = inspect(
        json.loads(raw),
        json.loads(args.layout.read_text(encoding="utf-8")),
        json.loads(args.reader.read_text(encoding="utf-8")),
        source_sha256=hashlib.sha256(raw).hexdigest(),
    )
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("Gadget bool-wire evidence diverges from pinned disassembly")
        print("PASS: all eight candidate Gadget bool fields have direct wire comparisons")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
