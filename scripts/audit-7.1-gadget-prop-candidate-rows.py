#!/usr/bin/env python3
"""Falsify direct-first-row use of the nearest original 7.1 GadgetProp reader.

The method NHPHDCFACCL.GMENPOPMKAA, index 225165, RVA 0x9EB86F0, was
disassembled directly from the original SHA-256-pinned Global 7.1 executable.
Its native first U16 mask, conditional U32, and U16 string-length arithmetic
are tested against the exact original GadgetProp Raw export, at table offset 4.

This *only* falsifies the direct-at-offset-four parse hypothesis. The loader's
runtime vtable +0xF0 concrete method, inheritance and nested readers remain
unresolved. No private-server data is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.binconfig import BinaryConfigReader
from genshinre.nativeprofile import PROFILE_71

RAW_SHA256 = "8907f4b717cd450ce084bd3a1a6a73e4409b8280fb4c74605afa520efbbc6a54"
PAYLOAD_SHA256 = "a12f433fe834576f84cbd5521c5715a27dc64eed0ee0137eb0cb24573d38d091"
DISASSEMBLY_SHA256 = "76c49f4e003814a5b4ce7d4150796acf1811e9da27218da73e42e3e6ea59d808"
READER_RVA = "0x9EB86F0"
LOADER_RVA = "0x124F2CF0"
ROW_COUNT = 326
COUNT_XOR = 0x5BD303D6
MASK_ADD = 0xA302
STRING_LENGTH_ADD = 0xD46F


def inspect_direct_first_record(payload: bytes) -> dict:
    """Follow only native-verified first-mask, U32 and length reads.

    Native instructions:
      0x9EB8755: movzx esi, word ptr [rax + rdx + 0x20]
      0x9EB8762: add esi, 0xffffa302
      0x9EB876F: test sil, 0x80
      0x9EB87A9: conditional U32 read
      0x9EB8838: test dil, 2
      0x9EB8889/0x9EB888E: decoded string U16 length = raw + 0xD46F
    The compiler tests bits in the low byte; other mask bits are not
    rejected merely because they are not tested by this method.
    """
    reader = BinaryConfigReader(payload, label="original GadgetProp candidate")
    header = reader.u32()
    count = header ^ COUNT_XOR
    if count != ROW_COUNT:
        raise ValueError(f"original GadgetProp header count changed: {count}")
    raw_mask = reader.u16()
    mask = (raw_mask + MASK_ADD) & 0xFFFF
    if not (mask & 0x80 and mask & 0x02) or mask & 0x04:
        raise ValueError(f"first original GadgetProp mask control changed: 0x{mask:04X}")
    # First conditional U32, mandatory for the original row's test bit 0x80.
    first_integer = reader.u32() ^ 0x89E1EE3D
    # Mask bit 0x04 is clear here, so the candidate skips its 0x1C U32.
    length_raw = reader.u16()
    length = (length_raw + STRING_LENGTH_ADD) & 0xFFFF
    available = len(payload) - reader.pos
    if not length > available:
        raise ValueError(
            "the nearest candidate is no longer falsified by first-row length bounds")
    if (header, raw_mask, mask, length_raw, length, available) != (
            0x5BD30290, 0x16D8, 0xB9DA, 0xA31F, 30606, 9376):
        raise ValueError("original Global 7.1 first record witness changed")
    return {
        "tableHeaderDecodedRows": count,
        "candidateFirstRowStartOffset": 4,
        "candidateDecodedMask": f"0x{mask:04X}",
        "candidateFirstIntegerDecoded": first_integer,
        "candidateStringLength": length,
        "remainingPayloadBytes": available,
        "candidateStringExceedsSourceByBytes": length - available,
        "directAtFirstRowPossible": False,
    }


def audit(raw: bytes) -> dict:
    if hashlib.sha256(raw).hexdigest() != RAW_SHA256:
        raise ValueError("original GadgetProp Raw SHA-256 mismatch")
    payload = unwrap_mihoyo_bin_data(raw)
    if hashlib.sha256(payload).hexdigest() != PAYLOAD_SHA256:
        raise ValueError("original GadgetProp payload SHA-256 mismatch")
    witness = inspect_direct_first_record(payload)
    return {
        "schemaVersion": 1,
        "status": "EXACT_7_1_GADGET_PROP_NEAREST_READER_DIRECT_FIRST_ROW_FALSIFIED",
        "source": {
            "sample": PROFILE_71.identity,
            "exeSha256": PROFILE_71.exe_sha256,
            "rawSha256": RAW_SHA256,
            "payloadSha256": PAYLOAD_SHA256,
            "originalPayloadBytes": len(payload),
            "loaderRva": LOADER_RVA,
            "methodIndexCandidate": 225165,
            "readerRvaCandidate": READER_RVA,
            "nativeDisassemblySha256": DISASSEMBLY_SHA256,
            "disassemblySourceRun": "https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39624413563",
        },
        "firstRecordProof": witness,
        "limitations": [
            "This rejects the candidate method as a direct reader starting at table payload offset four.",
            "The loader may call an inherited/base reader or use an earlier row prefix; no concrete +0xF0 virtual target is identified.",
            "Unused high mask bits were not assumed invalid; the native-required string length alone exceeds the entire source remainder.",
            "No LootCSS grade, level, type, original placement, reward amounts or probabilities are inferred.",
            "No original raw asset bytes or decoded proprietary rows are committed.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    result = audit(args.raw.read_bytes())
    if args.check:
        expected = json.loads(args.output.read_text(encoding="utf-8"))
        if result != expected:
            raise SystemExit("original GadgetProp first-row falsification witness changed")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
