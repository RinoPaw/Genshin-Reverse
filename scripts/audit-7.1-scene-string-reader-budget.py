#!/usr/bin/env python3
"""Bound an exact-7.1 SceneTag *candidate* row reader using original bytes.

Native method 696558 (IKEJJGKKAOO.GMENPOPMKAA) uses a two-byte
presence mask and, when bit 0x20 is set, reads a transformed u16 length.
The bound assumes that the byte-span reader consumes at least that length
and that no reader rewinds the shared input cursor. Bit 0x01 may consume
ANY nonnegative additional number of bytes; all unmodeled reads are
optimistically ignored. Thus the computed row maximum is an upper bound
under the explicit forward-only assumptions, not vtable identification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71
from genshinre.scenebin71 import SOURCES, decode_source_header

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (ROOT / "versions/7.1.0-global/analyses/progression/economy"
          / "7.1-chest-scene-string-reader-budget.json")
DISASM_SHA256 = "7ecd093986c70a8f6ea08362f1f670166a841f0066ab0b5eec7b3f4a6be903fc"
METHOD_INDEX = 696558
TYPE_NAME = "IKEJJGKKAOO"
METHOD_RVA = "0x99C3380"
# The RVA/operands must occur in exact-source original client disassembly.
ANCHORS = (
    ("0x99C33EB", "movzx", "esi, word ptr [rax + rdx + 0x20]"),
    ("0x99C33F7", "add", "esi, 0xffff99f0"),
    ("0x99C33FF", "test", "sil, 2"),
    ("0x99C340F", "test", "r12b, 0x80"),
    ("0x99C3453", "add", "ecx, dword ptr [rax + rdi + 0x20]"),
    ("0x99C34A2", "add", "ebx, dword ptr [rax + rdx + 0x20]"),
    ("0x99C34B7", "call", "0x14bb16020"),
    ("0x99C34BF", "mov", "dword ptr [r15 + 0x28], eax"),
    ("0x99C34C3", "test", "r12b, 0x20"),
    ("0x99C3511", "mov", "si, 0x75d6"),
    ("0x99C3515", "add", "si, word ptr [rax + rdx + 0x20]"),
    ("0x99C35C1", "test", "r12b, 0x10"),
    ("0x99C360C", "test", "r12b, 0x40"),
    ("0x99C365F", "test", "r12b, 1"),
    ("0x99C37D4", "mov", "rcx, r13"),
    ("0x99C37D7", "mov", "edx, edi"),
    ("0x99C37DD", "call", "0x14fd53090"),
)


def necessary_fields(payload: bytes, start: int) -> dict | None:
    """One row's *minimum* byte budget for source-anchored native reads.

    Optional 0x01 helper reads are deliberately omitted. No record-field
    meaning, key ownership, or unknown calls are inferred.
    """
    end = len(payload)
    if start + 2 > end:
        return None
    mask = (struct.unpack_from("<H", payload, start)[0] + 0x99F0) & 0xFFFF
    cursor = start + 2
    if mask & 0x02:
        cursor += 4
    if mask & 0x80:
        cursor += 4
    length = None
    if mask & 0x20:
        if cursor + 2 > end:
            return None
        length = (struct.unpack_from("<H", payload, cursor)[0] + 0x75D6) & 0xFFFF
        cursor += 2 + length
    if mask & 0x10:
        cursor += 4
    if mask & 0x40:
        cursor += 4
    if cursor > end:
        return None
    return {"mask": mask, "necessaryEnd": cursor, "spanLength": length,
            "unboundedForwardSkipAllowed": bool(mask & 0x01)}


def relaxed_max_rows(payload: bytes, start: int = 4) -> dict:
    """Max possible rows in any forward-only execution; over-approximate.

    The bit-0x01 helper may skip any >=0 number of bytes, even when it
    would normally consume more. If no such helper is called, the cursor
    advances by the native reads' *minimum* required length. Ignoring all
    other reads can only increase the reported upper bound.
    """
    n = len(payload)
    if not 0 <= start <= n:
        raise ValueError("row start outside payload")
    max_from = [0] * (n + 1)
    suffix_max = [0] * (n + 2)
    for pos in range(n - 2, -1, -1):
        row = necessary_fields(payload, pos)
        if row is not None:
            end = row["necessaryEnd"]
            continuation = (suffix_max[end] if row["unboundedForwardSkipAllowed"]
                            else max_from[end])
            max_from[pos] = 1 + continuation
        suffix_max[pos] = max(max_from[pos], suffix_max[pos + 1])
    return {"maxRowsStartingAtOffset": max_from[start],
            "maxRowsStartingAnywhereAtOrAfterOffset": suffix_max[start],
            "firstRowMinimumBudget": necessary_fields(payload, start)}


def audit(original: bytes, native_raw: bytes) -> dict:
    table = "SceneTagConfigData"
    header = decode_source_header(original, source=table)
    if hashlib.sha256(native_raw).hexdigest() != DISASM_SHA256:
        raise ValueError("candidate native disassembly SHA-256 mismatch")
    native = json.loads(native_raw)
    if native.get("exe_sha256") != PROFILE_71.exe_sha256 or native.get("start_rva") != METHOD_RVA:
        raise ValueError("wrong exact 7.1 candidate native method")
    by_rva = {item["rva"]: item for item in native["instructions"]}
    if len(by_rva) != len(native["instructions"]):
        raise ValueError("duplicate native instruction RVA")
    for rva, op, args in ANCHORS:
        actual = by_rva.get(rva)
        if not actual or (actual["mnemonic"], actual["op_str"]) != (op, args):
            raise ValueError(f"missing exact native reader anchor {rva}")
    payload = unwrap_mihoyo_bin_data(original)
    bound = relaxed_max_rows(payload)
    first = bound["firstRowMinimumBudget"]
    if first is None or first["spanLength"] is None:
        raise ValueError("original candidate first-row length branch missing")
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_SCENETAG_CANDIDATE_696558_FORWARD_ONLY_ROW_BUDGET_REJECTION__VTABLE_UNRESOLVED",
        "source": {"table": table, "rawSha256": SOURCES[table]["raw_sha"],
                   "payloadSha256": SOURCES[table]["payload_sha"],
                   "originalExecutableSha256": PROFILE_71.exe_sha256,
                   "candidateDisassemblySha256": DISASM_SHA256,
                   "candidateMethodIndex": METHOD_INDEX,
                   "candidateType": TYPE_NAME, "candidateRva": METHOD_RVA,
                   "nativeAnchorsMatched": len(ANCHORS)},
        "firstRow": {"startOffset": 4,
                     "wireMaskU16": f"0x{struct.unpack_from('<H', payload, 4)[0]:04X}",
                     "decodedMaskU16": f"0x{first['mask']:04X}",
                     "mandatoryLengthFromBit0x20": first["spanLength"],
                     "minimumCursorAfterNativeReads": first["necessaryEnd"],
                     "unknownBit0x01HelperMaySkipForward": first["unboundedForwardSkipAllowed"]},
        "forwardOnlyRelaxedBound": {"originalRowCount": header.row_count,
                                    "maxPossibleRows": bound["maxRowsStartingAtOffset"],
                                    "candidateMeetsOriginalRowCount": (
                                        bound["maxRowsStartingAtOffset"] >= header.row_count),
                                    "originalPayloadBytes": len(payload)},
        "limitations": [
            "The maximum is conditional on the observed bit-0x20 byte-span length being consumed and all reader helpers advancing the shared stream cursor without rewinding.",
            "The bit-0x01 helper is allowed to skip ANY nonnegative byte count; unknown extra field reads and record semantics are omitted to favor the candidate.",
            "This falsifies the candidate as a direct full table row parser only under those forward-only stream assumptions, not as a general native method or an inherited helper.",
            "Original vtable+0xF0 resolution, native SceneTag field names, original scene placement and server drop_tag/reward roots remain unverified.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scene-tag-raw", type=Path, required=True)
    p.add_argument("--candidate-disasm", type=Path, required=True)
    p.add_argument("--output", type=Path, default=OUTPUT)
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    report = audit(args.scene_tag_raw.read_bytes(), args.candidate_disasm.read_bytes())
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("pinned 7.1 candidate reader budget evidence changed")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"],
                      "maxPossibleRows": report["forwardOnlyRelaxedBound"]["maxPossibleRows"],
                      "originalRowCount": report["forwardOnlyRelaxedBound"]["originalRowCount"]}))


if __name__ == "__main__":
    main()
