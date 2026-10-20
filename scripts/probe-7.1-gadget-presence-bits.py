#!/usr/bin/env python3
"""Correlate 7.1 Gadget row presence tests with the 22-field layout candidate.

Requires the exact pinned native disassembly JSON. A static branch association
is evidence about this reader; it is not a recovered field name, original
client row value, or chest reward semantics.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

ROOT = Path(__file__).resolve().parents[1]
ECONOMY = ROOT / "versions/7.1.0-global/analyses/progression/economy"
LAYOUT = ECONOMY / "7.1-chest-native-gadget-layout-candidate.json"
READER = ECONOMY / "7.1-chest-native-gadget-reader-static.json"
OUTPUT = ECONOMY / "7.1-chest-native-gadget-presence-bits.json"

# (candidate owner displacement, bit in the transformed 64-bit row mask,
#  exact native TEST RVA). Linked manually by following the reader's ordered
#  branches in the pinned method; tests independently check the instructions.
ANCHORS = (
    (0x7E, 17, 0x10278ED1),
    (0x7D, 5, 0x10278EDF),
    (0x98, 11, 0x10278EEB),
    (0x48, 22, 0x10278FEC),
    (0x79, 9, 0x10279415),
    (0x80, 15, 0x10279468),
    (0x88, 2, 0x102794BE),
    (0x7A, 12, 0x10279521),
    (0x70, 3, 0x10279574),
    (0x78, 1, 0x102795E1),
    (0x74, 19, 0x10279632),
    (0x68, 18, 0x10279687),
    (0x50, 0, 0x102796F1),
    (0x7C, 26, 0x10279986),
    (0x84, 10, 0x102799D5),
    (0x60, 24, 0x10279A27),
    (0x58, 25, 0x10279D2B),
    (0x7B, 4, 0x10279E2C),
    (0x90, 16, 0x10279E7D),
    (0x94, 20, 0x10279EF5),
    (0x6C, 7, 0x10279F68),
    (0x7F, 28, 0x10279FBF),
)

MASK_STEPS = (
    (0x10278EAC, "mov", "ecx, dword ptr [rbx]"),
    (0x10278EBE, "add", "ecx, 8"),
    (0x10278EC1, "mov", "edi, 0x466db4eb"),
    (0x10278EC6, "add", "rdi, qword ptr [rax + rdx + 0x20]"),
    (0x10278ECB, "mov", "dword ptr [rbx], ecx"),
    (0x10278ECD, "mov", "qword ptr [rbp + 0x28], rdi"),
)


def correlate(disassembly: dict, layout: dict, reader: dict, *, digest: str) -> dict:
    src = reader["source"]
    if (digest != src["disassemblyJsonSha256"]
            or disassembly.get("exe_sha256") != PROFILE_71.exe_sha256
            or disassembly.get("start_rva") != src["methodRva"]
            or disassembly.get("instruction_count") != reader["disassembly"]["decodedInstructions"]
            or layout["readerRva"] != src["methodRva"]
            or layout["ownerTypeDefinitionIndex"] != src["typeDefinitionIndex"]):
        raise ValueError("pinned native disassembly, executable or layout identity mismatch")
    rows = disassembly["instructions"]
    by_rva = {int(ins["rva"], 16): ins for ins in rows}
    if len(by_rva) != len(rows):
        raise ValueError("duplicate native instruction RVA")
    for rva, mnemonic, operands in MASK_STEPS:
        ins = by_rva.get(rva)
        if ins is None or (ins["mnemonic"], ins["op_str"]) != (mnemonic, operands):
            raise ValueError(f"native row mask construction changed at 0x{rva:X}")
    fields = {int(row["candidateInstanceOffset"], 16): row
              for row in layout["result"]["mapping"]}
    if len(fields) != 22 or len(ANCHORS) != 22:
        raise ValueError("unexpected Gadget layout or anchor count")
    if (len({o for o, _, _ in ANCHORS}) != 22
            or len({b for _, b, _ in ANCHORS}) != 22
            or len({rva for _, _, rva in ANCHORS}) != 22
            or set(fields) != {o for o, _, _ in ANCHORS}):
        raise ValueError("presence mask has missing, duplicated or foreign offsets/bits")

    # After the TEST, one nearby native conditional branch selects a read or
    # skip. Alternative branches (including explicit zero assignments) remain
    # visible in the artifact. No general CFG completeness is claimed.
    records = []
    for offset, bit, rva in ANCHORS:
        test = by_rva.get(rva)
        if test is None or test["mnemonic"] != "test":
            raise ValueError(f"missing TEST at 0x{rva:X}")
        operand = test["op_str"]
        try:
            immediate = int(operand.rsplit(", ", 1)[1], 0)
        except (IndexError, ValueError) as exc:
            raise ValueError(f"unparseable native bit test at 0x{rva:X}") from exc
        if immediate != (1 << bit):
            raise ValueError(f"presence bit mismatch at 0x{rva:X}")
        test_idx = next(i for i, ins in enumerate(rows) if int(ins["rva"], 16) == rva)
        nxt = rows[test_idx + 1:test_idx + 5]
        branches = [ins for ins in nxt if ins["mnemonic"] in ("je", "jne")]
        if len(branches) != 1:
            raise ValueError(f"no unique local branch after 0x{rva:X}")
        field = fields[offset]
        records.append({
            "fieldToken": field["fieldName"],
            "metadataFieldIndex": field["fieldIndex"],
            "metadataType": field["metadataType"],
            "candidateMemoryOffset": f"0x{offset:X}",
            "maskBit": bit,
            "maskHex": f"0x{1 << bit:016X}",
            "testRva": f"0x{rva:X}",
            "testOperands": operand,
            "branchRva": branches[0]["rva"],
            "branchMnemonic": branches[0]["mnemonic"].upper(),
            "branchTarget": branches[0]["op_str"],
            "readOrderCandidate": len(records),
        })
    return {
        "schemaVersion": 1,
        "status": "NATIVE_GADGET_PRESENCE_BITS_STATIC__SOURCE_ROW_DECODER_UNRESOLVED",
        "target": PROFILE_71.identity,
        "readerRva": src["methodRva"],
        "sourceDisassemblySha256": digest,
        "sourceReports": [LAYOUT.name, READER.name],
        "mask": {
            "readWidthBytes": 8,
            "wireEndian": "little",
            "decodeOperation": "add_modulo_2_64",
            "decodeConstant": "0x00000000466DB4EB",
            "evidenceRvas": [f"0x{rva:X}" for rva, _, _ in MASK_STEPS],
            "testedDistinctBits": len(records),
            "testedBitRange": [min(row["maskBit"] for row in records),
                               max(row["maskBit"] for row in records)],
        },
        "fieldsInNativeReadOrder": records,
        "limitations": [
            "Row-mask arithmetic and TEST instructions are from an exact 7.1 binary.",
            "Field tokens depend on the earlier 22-field in-memory layout candidate, not a verified native field-offset table.",
            "The read branches were correlated from bounded disassembly; this is not a complete CFG/loader proof.",
            "All 22 tested bits being present does not establish whether the original serialized row has other control flags.",
            "No table header framing, row values, gadget grade or server payout semantics are decoded here.",
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
    result = correlate(json.loads(raw),
                       json.loads(args.layout.read_text(encoding="utf-8")),
                       json.loads(args.reader.read_text(encoding="utf-8")),
                       digest=hashlib.sha256(raw).hexdigest())
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != result:
            raise SystemExit("Gadget presence-bit report differs from exact static trace")
        print("PASS: 22 candidate field guards match exact native Gadget reader")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
