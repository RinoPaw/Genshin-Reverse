#!/usr/bin/env python3
"""Reproduce source-bound Global 7.1 GadgetInteract candidate call/branch chain.

Use the original SHA-256-pinned source first-row report and native disassemblies.
The original client target is exact. The loader's actual virtual +0xF0
row reader remains UNRESOLVED and no reward selector semantics are assigned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

EXPECTED_SHA={
  "first": "8492df688bccf6ed9713e602d241fbbaa851778fa8af42229bc863496f218387",
  "candidate": "0be8f3091c13eb1a93f5e98c71a2c5b2f04d893d63e90fc9a5ecdd576ef1e2de",
  "nested": "b3ccfed6c2ae43504fe68f231075da55fe4748d1696345ba59047f43d97e73b9",
  "tail": "21169bce1031ebc453205e2e83841f6e54e995dfd1021574159ba85666bdc9fa",
  "conditional": "1222ae6723915d82b15d67557ece7e04a96b93ab25da90755702f961e57cf082"
}
ORIGINAL_METHOD_RVAS={
    "candidate":"0xBE94FB0", "nested":"0xFF7AE70",
    "tail":"0xD95D180","conditional":"0x9EA9CB0",
}
NATIVE_ANCHORS={
  "candidate": {
    "0xBE9500D": [
      "movzx",
      "ebx, byte ptr [rax + rdx + 0x20]",
      "0fb65c1020"
    ],
    "0xBE95018": [
      "test",
      "bl, 1",
      "f6c301"
    ],
    "0xBE95031": [
      "xor",
      "bl, 0x74",
      "80f374"
    ],
    "0xBE9504B": [
      "test",
      "bl, 0x40",
      "f6c340"
    ],
    "0xBE9508A": [
      "xor",
      "edx, dword ptr [rax + rdi + 0x20]",
      "33543820"
    ],
    "0xBE95095": [
      "add",
      "edx, 0x8b76314e",
      "81c24e31768b"
    ],
    "0xBE950AE": [
      "mov",
      "dword ptr [r14 + 0x28], eax",
      "41894628"
    ],
    "0xBE950B6": [
      "test",
      "bl, 0x10",
      "f6c310"
    ],
    "0xBE950FD": [
      "jmp",
      "0x14d95d180",
      "e97e80ac01"
    ],
    "0xBE95121": [
      "call",
      "0x14ff7ae70",
      "e84a5d0e04"
    ],
    "0xBE95139": [
      "call",
      "0x149ea9cb0",
      "e8724b01fe"
    ]
  },
  "nested": {
    "0xFF7AED3": [
      "test",
      "byte ptr [rax + rdx + 0x20], 0x10",
      "f644102010"
    ],
    "0xFF7AF23": [
      "movzx",
      "r13d, word ptr [rax + rdx + 0x20]",
      "440fb76c1020"
    ],
    "0xFF7AF30": [
      "xor",
      "r13, 0xb92",
      "4981f5920b0000"
    ],
    "0xFF7AF3A": [
      "add",
      "ax, 0x8a8",
      "6605a808"
    ]
  },
  "tail": {
    "0xD95D260": [
      "mov",
      "rsi, qword ptr [r15 + 0x18]",
      "498b7718"
    ]
  },
  "conditional": {
    "0x9EA9CFA": [
      "mov",
      "eax, dword ptr [rax + rcx + 0x20]",
      "8b440820"
    ],
    "0x9EA9D05": [
      "mov",
      "r12d, 0xd78d7a5a",
      "41bc5a7a8dd7"
    ],
    "0x9EA9D0B": [
      "xor",
      "r12, rax",
      "4931c4"
    ],
    "0x9EA9D5E": [
      "call",
      "0x149ea9e20",
      "e8bd000000"
    ],
    "0x9EA9DAD": [
      "cmp",
      "rbx, r12",
      "4c39e3"
    ]
  }
}
OUTPUT=Path("versions/7.1.0-global/analyses/progression/economy/7.1-gadget-interact-native-first-branch-chain.json")
SOURCE_RAW_SHA="6481cd8b92185ffc13ffe8a12332eba8d53139077c75738aa40d15fc5bc8c24e"
SOURCE_PAYLOAD_SHA="ce9fcd3b2d7deb76c7e9f2a4ca2738f8d9e0e8500b7bb101768cd18be059fb11"


def verify_native_anchors(method:dict, kind:str)->int:
    if method["exe_sha256"]!=PROFILE_71.exe_sha256:
        raise ValueError(f"{kind}: original EXE source SHA-256 drift")
    if method["start_rva"].upper()!=ORIGINAL_METHOD_RVAS[kind].upper():
        raise ValueError(f"{kind}: wrong native method RVA")
    ins={r["rva"].upper():r for r in method["instructions"]}
    if len(ins)!=len(method["instructions"]):
        raise ValueError(f"{kind}: duplicate disassembly instruction RVA")
    for addr,(mnemonic,operand,opcode) in NATIVE_ANCHORS[kind].items():
        row=ins.get(addr.upper())
        if row is None or (row["mnemonic"],row["op_str"],row["bytes"])!=(mnemonic,operand,opcode):
            raise ValueError(f"{kind}: native source instruction mismatch at {addr}")
    return len(NATIVE_ANCHORS[kind])


def investigate(files:dict[str,bytes])->dict:
    documents={}
    for name,sha in EXPECTED_SHA.items():
        raw=files[name]
        if hashlib.sha256(raw).hexdigest()!=sha:
            raise ValueError(f"{name}: source-run original artifact SHA-256 mismatch")
        documents[name]=json.loads(raw)
    first=documents["first"]
    if (first["source"]["exeSha256"]!=PROFILE_71.exe_sha256
            or first["source"]["rawSha256"]!=SOURCE_RAW_SHA
            or first["source"]["payloadSha256"]!=SOURCE_PAYLOAD_SHA):
        raise ValueError("first source report not original Global 7.1 GadgetInteract")
    item=first["firstRecordHypothesis"]
    control={
        "nativeHeaderDecodedRows":363,
        "firstRowCandidateByteOffset":4,
        "firstRowRawMaskByte":"0x36",
        "candidateDecodedMaskByte":"0x42",
        "rawBitZeroRequiresNestedReaderCall":False,
        "candidateHasConditionalU32KeyRead":True,
        "candidateHasConditionalStringRead":False,
        "preWrapperKeyIfUninterrupted":938583754,
        "nativePrefixCursorIfUninterrupted":9,
        "recordBoundaryConfirmed":False,
    }
    for name,value in control.items():
        if item[name]!=value:
            raise ValueError(f"first native source field {name} drift")
    checked={name:verify_native_anchors(documents[name],name)
             for name in ORIGINAL_METHOD_RVAS}
    return {
        "schemaVersion":1,
        "status":"EXACT_7_1_GADGET_INTERACT_FIRST_SOURCE_NATIVE_CALL_CHAIN__VTABLE_UNRESOLVED",
        "originalExeSha256":PROFILE_71.exe_sha256,
        "originalRawExportSha256":SOURCE_RAW_SHA,
        "originalPayloadSha256":SOURCE_PAYLOAD_SHA,
        "sourceRuns":[
            "https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39624413563",
            "https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39643045058",
        ],
        "exactOriginalDerivedArtifactSha256":EXPECTED_SHA,
        "methodRvas":ORIGINAL_METHOD_RVAS,
        "checkedNativeInstructionAnchors":checked,
        "sourceFirstRecord":{
            **control,
            "cursor9IsConfirmedRowEnd":False,
            "originalDecodedKeyRemainsPreWrapper":True,
        },
        "nativeConditionalEdges":{
            "rawMaskBit0NestedReader":{"callRva":"0xBE95121","targetRva":"0xFF7AE70",
                "takenForActualFirstRawMask0x36":False,
                "targetHasOwnPresenceFlagAndStringLengthTransform":True},
            "transformedMask0x20ContainerReader":{"callRva":"0xBE95139","targetRva":"0x9EA9CB0",
                "takenForActualFirstRawMask0x36":False,
                "originalU32CountXor":"0xD78D7A5A","elementReaderCallRva":"0x9EA9D5E",
                "elementReaderTargetRva":"0x9EA9E20"},
            "originalCandidateTailHelper":{
                "jmpRva":"0xBE950FD","targetRva":"0xD95D180",
                "runtimeBranchConditionsUnresolved":True},
        },
        "limitations":[
            "The source branch is conditional on the unverified hypothesis that this candidate is called from the original loader at first payload record offset 4.",
            "The raw original first byte and native method opcodes are independently source pinned, but do not prove the loader's +0xF0 virtual target.",
            "The native u32 count/loop in the conditional helper is an array-like container pattern, not a verified original semantic field name.",
            "The original cursor at offset 9 is a conditional read-prefix extent; exact record end is not verified.",
            "Native wrapped u32 scalar precedes the unresolved runtime key substitution; it is not a proven Gadget ID.",
            "No scene-instance level, chest grade/type, server payout, amount or probability is proven.",
        ],
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    for name in EXPECTED_SHA:
        p.add_argument("--"+name,required=True,type=Path)
    p.add_argument("--output",type=Path,default=OUTPUT)
    p.add_argument("--check",action="store_true")
    a=p.parse_args()
    result=investigate({name:getattr(a,name).read_bytes() for name in EXPECTED_SHA})
    if a.check:
        if json.loads(a.output.read_text(encoding="utf-8"))!=result:
            raise SystemExit("original 7.1 native GadgetInteract chain report drift")
    else:
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({"status":result["status"],"anchors":result["checkedNativeInstructionAnchors"],
                       "first":result["sourceFirstRecord"]},indent=2))


if __name__=="__main__":main()
