#!/usr/bin/env python3
"""Byte-exact 7.1 Global audio chest type table scan from native row instructions.

Original row method candidate LAGPEMOIAKN.GMENPOPMKAA, metadata index
287887, RVA 0x77C01B0. The table's actual vtable binding remains a separate
gate, even if this source-bound candidate consumes the complete payload.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71

RAW_SHA = "c205c6d4efe69fde2b88800802816afd981a94df35e768746f5692e74febe591"
PAYLOAD_SHA = "a59a480b86a0fcb85d7b0e4d72f631d1b78b6e2d87b58ac579c91ec4a9147257"
U32 = 0xFFFFFFFF
U16 = 0xFFFF
COUNT_XOR = 0x81F9C781
PRESENCE_XOR = 0xFFFFE5C7
PRESENCE_ADD = 0xFFFFEE77
AUDIO_FIELD_ADD = 0x1520DAED
KEY_FIELD_ADD = 0x1C53C8D1
KEY_WRAPPER_RVA = 0xBB16020
NATIVE_ROW_METHOD_INDEX = 287887
NATIVE_ROW_RVA = 0x77C01B0


def scan_payload(payload: bytes) -> dict:
    if len(payload) < 4:
        raise ValueError("truncated native Audio table header")
    header = struct.unpack_from("<I", payload)[0]
    count = header ^ COUNT_XOR
    if not 1 <= count <= 100_000 or 4 + count * 6 > len(payload):
        raise ValueError(f"impossible original Audio row count {count}")
    pos = 4
    rows = []
    unique_keys = set()
    for ordinal in range(count):
        start = pos
        if pos + 2 > len(payload):
            raise ValueError(f"Audio row {ordinal} missing native mask")
        raw_mask = struct.unpack_from("<H", payload, pos)[0]
        pos += 2
        mask = ((raw_mask ^ PRESENCE_XOR) + PRESENCE_ADD) & U32
        field = None
        if mask & 0x20:
            if pos + 4 > len(payload):
                raise ValueError(f"Audio row {ordinal} truncated class field")
            field = (struct.unpack_from("<I", payload, pos)[0] + AUDIO_FIELD_ADD) & U32
            pos += 4
        if not mask & 0x10:
            raise ValueError(f"Audio row {ordinal} missing native gadget key")
        if pos + 4 > len(payload):
            raise ValueError(f"Audio row {ordinal} truncated native gadget key")
        key = (struct.unpack_from("<I", payload, pos)[0] + KEY_FIELD_ADD) & U32
        pos += 4
        if key in unique_keys:
            raise ValueError(f"duplicate pre-wrapper audio gadget scalar {key}")
        unique_keys.add(key)
        rows.append({
            "ordinal": ordinal,
            "offset": start,
            "bytes": pos - start,
            "nativeMaskLow16": f"0x{mask & U16:04X}",
            "nativeClassFieldPresent": field is not None,
            "nativeClassScalar": field,
            "gadgetIdPreWrapperScalar": key,
        })
    if pos != len(payload):
        raise ValueError(f"unconsumed Audio bytes: {len(payload)-pos} at {pos}")
    flags = Counter(row["nativeMaskLow16"] for row in rows)
    scalar_counts = Counter(
        str(row["nativeClassScalar"]) if row["nativeClassFieldPresent"] else "(absent)"
        for row in rows
    )
    keys = [r["gadgetIdPreWrapperScalar"] for r in rows]
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_AUDIO_NATIVE_ROW_CANDIDATE_FULL_WIRE_CONSUMPTION__VTABLE_UNRESOLVED",
        "originalClientExeSha256": PROFILE_71.exe_sha256,
        "sourceRawSha256": RAW_SHA,
        "sourcePayloadSha256": PAYLOAD_SHA,
        "nativeTableLoaderRvaCandidate": "0x130156D0",
        "nativeRowMethodIndexCandidate": NATIVE_ROW_METHOD_INDEX,
        "nativeRowRvaCandidate": f"0x{NATIVE_ROW_RVA:X}",
        "nativeWrappedKeyWriterRva": f"0x{KEY_WRAPPER_RVA:X}",
        "nativeHeaderCount": count,
        "decodedRecords": len(rows),
        "payloadBytes": len(payload),
        "bytesConsumed": pos,
        "unparsedBytes": len(payload) - pos,
        "uniquePreWrapperGadgetKeyScalars": len(unique_keys),
        "maskLow16Histogram": dict(sorted(flags.items())),
        "nativeClassScalarHistogram": dict(sorted(scalar_counts.items())),
        "firstRecords": rows[:8],
        "lastRecords": rows[-8:],
        "decodedKeySequenceSha256": hashlib.sha256(
            json.dumps(keys, separators=(",", ":")).encode()).hexdigest(),
        "rows": rows,
        "limitations": [
            "The candidate row method's native presence-mask and two uint32 scalar read instructions are confirmed by original EXE disassembly; runtime vtable owner still needs a separate class registration link.",
            "The second scalar is decoded before original native runtime key wrapper 0xBB16020; the wrapper's actual substitution tables/round trip remain unknown.",
            "A numeric field value is not a verified audio Mid/Hi/Top label or a server payable chest grade.",
            "A complete parse of the original client table is not evidence of scene/group/config placement, drop_tag, root payout, reward items or probability.",
        ],
    }


def scan_original(raw: bytes) -> dict:
    if hashlib.sha256(raw).hexdigest() != RAW_SHA:
        raise ValueError("original 7.1 Audio source Raw SHA-256 mismatch")
    payload = unwrap_mihoyo_bin_data(raw)
    if hashlib.sha256(payload).hexdigest() != PAYLOAD_SHA:
        raise ValueError("original 7.1 Audio payload SHA-256 mismatch")
    return scan_payload(payload)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--audio-raw", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = scan_original(args.audio_raw.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "rows": result["decodedRecords"],
        "unparsedBytes": result["unparsedBytes"],
        "uniquePreWrapperKeys": result["uniquePreWrapperGadgetKeyScalars"],
        "classes": result["nativeClassScalarHistogram"],
        "masks": result["maskLow16Histogram"],
        "first": result["firstRecords"][:4]
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
