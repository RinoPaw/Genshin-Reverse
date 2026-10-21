#!/usr/bin/env python3
"""Test exact Global 7.1 GadgetProp source against a native row reader candidate.

The mask/read sequence comes exclusively from original EXE method index 225165
(RVA 0x9EB86F0), disassembled at original client SHA-256 in run 39624413563.
This is a FALSIFIABLE schema candidate, not the proven +0xF0 virtual target.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.binconfig import BinaryConfigReader, decode_native_chunks
from genshinre.nativeprofile import PROFILE_71

RAW_SHA256 = "8907f4b717cd450ce084bd3a1a6a73e4409b8280fb4c74605afa520efbbc6a54"
PAYLOAD_SHA256 = "a12f433fe834576f84cbd5521c5715a27dc64eed0ee0137eb0cb24573d38d091"
CANDIDATE_DISASM_SHA256 = "76c49f4e003814a5b4ce7d4150796acf1811e9da27218da73e42e3e6ea59d808"
READER_RVA = "0x9EB86F0"
ROW_COUNT = 326
MASK_ADD = 0xA302
ALLOWED_BITS = 0x8F
STRING_LENGTH_ADD = 0xD46F
STRING_CHUNK_XOR = 0xCA2ABFA5D72AD46F
U32 = 0xffffffff
MAX_STRLEN = 65535


def decode_mask(raw: int) -> int:
    mask = (raw + MASK_ADD) & 0xFFFF
    if mask & ~ALLOWED_BITS:
        raise ValueError(f"unsupported original native GadgetProp candidate mask 0x{mask:X}")
    return mask


def candidate_row(reader: BinaryConfigReader, ordinal: int) -> dict:
    start = reader.pos
    mask = decode_mask(reader.u16())
    fields = {}
    if mask & 0x80:
        fields["0x20"] = reader.u32() ^ 0x89E1EE3D
    if mask & 0x04:
        fields["0x1C"] = (reader.u32() + 0xFA34DCA4) & U32
    if mask & 0x02:
        length = (reader.u16() + STRING_LENGTH_ADD) & 0xFFFF
        if length > MAX_STRLEN:
            raise ValueError("impossible original native string length")
        data = decode_native_chunks(reader.take(length), STRING_CHUNK_XOR, "xor")
        try:
            fields["0x10"] = data.decode("utf-8")
        except UnicodeDecodeError as err:
            raise ValueError(f"native GadgetProp candidate row {ordinal} UTF-8 failed") from err
    if mask & 0x01:
        fields["0x18"] = (reader.u32() + 0xFFE30423) & U32
    if mask & 0x08:
        fields["0x24"] = (reader.u32() + 0x4649B56A) & U32
    return {"ordinal": ordinal, "nativeMask": f"0x{mask:04X}",
            "start": start, "end": reader.pos,
            "fields": fields}


def scan(raw: bytes) -> dict:
    if hashlib.sha256(raw).hexdigest() != RAW_SHA256:
        raise ValueError("original Global 7.1 GadgetProp raw SHA-256 mismatch")
    payload = unwrap_mihoyo_bin_data(raw)
    if hashlib.sha256(payload).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("original Global 7.1 GadgetProp payload SHA-256 mismatch")
    reader = BinaryConfigReader(payload, label="original GadgetProp row candidate")
    encoded_count = reader.u32()
    count = encoded_count ^ 0x5BD303D6
    if count != ROW_COUNT:
        raise ValueError("original Global 7.1 GadgetProp native count does not match")
    records = []
    for i in range(count):
        records.append(candidate_row(reader, i))
    if reader.pos != len(payload):
        raise ValueError(f"native GadgetProp candidate left {len(payload)-reader.pos} bytes at 0x{reader.pos:X}")
    keys = [row["fields"].get("0x1C") for row in records]
    present_keys = [key for key in keys if key is not None]
    return {
        "schemaVersion": 1,
        "status": "ORIGINAL_7_1_GADGET_PROP_CANDIDATE_NATIVE_READER_FULL_BYTES__VTABLE_UNRESOLVED",
        "originalExeSha256": PROFILE_71.exe_sha256,
        "sourceRawSha256": RAW_SHA256,
        "sourcePayloadSha256": PAYLOAD_SHA256,
        "originalReaderMethodIndexCandidate": 225165,
        "originalReaderRvaCandidate": READER_RVA,
        "originalReaderDisassemblySha256": CANDIDATE_DISASM_SHA256,
        "nativeTableLoaderRva": "0x124F2CF0",
        "nativeHeaderRowCount": count,
        "decodedRows": len(records),
        "sourcePayloadBytes": len(payload),
        "consumedBytes": reader.pos,
        "unparsedBytes": len(payload) - reader.pos,
        "maskHistogram": dict(sorted(Counter(r["nativeMask"] for r in records).items())),
        "fieldPresence": dict(sorted(Counter(k for r in records for k in r["fields"]).items())),
        "preWrapperRowKeyPresence": len(present_keys),
        "uniquePreWrapperRowKeys": len(set(present_keys)),
        "preWrapperKeysSha256": hashlib.sha256(
            json.dumps(keys, separators=(",", ":")).encode()).hexdigest(),
        "nonemptyStringCount": sum(bool(r["fields"].get("0x10")) for r in records),
        "exampleRows": [{"ordinal": r["ordinal"], "mask": r["nativeMask"],
                         "key": r["fields"].get("0x1C"),
                         "stringLength": len(r["fields"].get("0x10", ""))}
                        for r in records[:8]],
        "limitations": [
            "Byte consumption and original instructions constrain a reader schema but do not link it to the loader's runtime vtable +0xF0.",
            "The decoded 0x1C scalar is pre-wrapper; actual runtime wrapper lookup identity remains unverified.",
            "Strings and integers are original client values without imported semantics.",
            "There is no authentication of loot chest grade, level, type, scene instance or payout.",
            "Original raw assets and full decoded copyrighted rows are not committed.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = scan(args.raw.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
