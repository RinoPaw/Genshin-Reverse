#!/usr/bin/env python3
"""Original Global 7.1 GadgetInteract near-reader first-row native branch probe.

Candidate HFMNIBLLOGG.GMENPOPMKAA index 219773, RVA 0xBE94FB0,
uses an 8-bit wire mask (RVA 0xBE9500D), tests raw bit 0, invokes
0xFF7AE70 on that path and XORs its mask with 0x74. These are original
native disassembly observations; the actual loader vtable +0xF0
binding remains unverified. Do not parse the rest of the row as if
the nested method could be skipped.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71

RAW_SHA="6481cd8b92185ffc13ffe8a12332eba8d53139077c75738aa40d15fc5bc8c24e"
PAYLOAD_SHA="ce9fcd3b2d7deb76c7e9f2a4ca2738f8d9e0e8500b7bb101768cd18be059fb11"
COUNT_ADD=0xDA262FFE
ROW_COUNT=363
METHOD_INDEX=219773
METHOD_RVA="0xBE94FB0"
NESTED_METHOD_RVA="0xFF7AE70"
FIRST_MASK_RVA="0xBE9500D"


def inspect_prefix(payload:bytes)->dict:
    if len(payload)<5: raise ValueError("GadgetInteract first row prefix absent")
    header=struct.unpack_from("<I",payload)[0]
    count=(header+COUNT_ADD)&0xFFFFFFFF
    if count!=ROW_COUNT: raise ValueError("original native GadgetInteract row count mismatch")
    raw=payload[4]
    # Original 0xBE95018 branch goes to 0xBE95102 if (raw & 1).
    nested=bool(raw&1)
    decoded=raw^0x74
    # The original candidate tests 0x20 before its key read; this branch
    # delegates to another method and may advance the cursor. Never treat
    # the following bytes as a key on that path.
    delegates_before_key=bool(decoded&0x20)
    native_key=None
    prefix_end=None
    if not nested and not delegates_before_key and decoded&0x40:
        if len(payload)<9:
            raise ValueError("truncated native GadgetInteract key prefix")
        original_key_word=struct.unpack_from("<I",payload,5)[0]
        native_key=(original_key_word ^ 0x2B845856)
        native_key=(native_key+0x8B76314E)&0xFFFFFFFF
        prefix_end=9
    result={
        "rawHeaderU32":f"0x{header:08X}",
        "nativeHeaderDecodedRows":count,
        "firstRowCandidateByteOffset":4,
        "firstRowRawMaskByte":f"0x{raw:02X}",
        "rawBitZeroRequiresNestedReaderCall":nested,
        "nativeNestedReaderDirectCallRva":NESTED_METHOD_RVA,
        "candidateDecodedMaskByte":f"0x{decoded:02X}",
        "candidateHasConditionalU32KeyRead":bool(decoded&0x40),
        "candidateHasConditionalStringRead":bool(decoded&0x10),
        "candidateOtherBits":{f"0x{x:02X}":bool(decoded&x) for x in (0x01,0x20)},
        "preWrapperKeyIfUninterrupted":native_key,
        "nativePrefixCursorIfUninterrupted":prefix_end,
        "prefixEndsAtRowBoundaryProven":False,
        "recordBoundaryConfirmed":False,
    }
    return result


def probe(raw:bytes)->dict:
    if hashlib.sha256(raw).hexdigest()!=RAW_SHA:raise ValueError("original GadgetInteract Raw SHA-256 mismatch")
    payload=unwrap_mihoyo_bin_data(raw)
    if hashlib.sha256(payload).hexdigest()!=PAYLOAD_SHA:raise ValueError("original GadgetInteract payload SHA-256 mismatch")
    return {
        "schemaVersion":1,
        "status":"EXACT_7_1_GADGET_INTERACT_NEAREST_NATIVE_FIRST_ROW_BRANCHES__VTABLE_UNRESOLVED",
        "source":{
            "sample":PROFILE_71.identity,"exeSha256":PROFILE_71.exe_sha256,
            "rawSha256":RAW_SHA,"payloadSha256":PAYLOAD_SHA,
            "payloadBytes":len(payload),
            "candidateMethodIndex":METHOD_INDEX,
            "candidateMethodRva":METHOD_RVA,
            "firstByteNativeReadRva":FIRST_MASK_RVA,
            "conditionalNestedNativeCallRva":NESTED_METHOD_RVA,
            "originalDisassemblySource":"https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39624413563",
        },
        "firstRecordHypothesis":inspect_prefix(payload),
        "limitations":[
            "Original bytes establish only the branch that this candidate would take if called at the first record after the four-byte header.",
            "The native direct nested call under raw mask bit 0 is part of the candidate code; its exact schema and inherited cursor consumption are unresolved.",
            "The native prefix cursor after the first u32 is conditional; a subsequent tail helper may still consume source bytes. It is not an established row boundary.",
            "The calculated key is the candidate's original pre-wrapper u32 scalar, with runtime wrapper mapping unresolved.",
            "No row field labels, chest type/grade/level, scene instance, probabilities or reward contents are inferred.",
            "The concrete native vtable +0xF0 method remains unknown."
        ],
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    result=probe(a.raw.read_bytes())
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps(result,indent=2,ensure_ascii=False))


if __name__=="__main__":main()
