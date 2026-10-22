#!/usr/bin/env python3
"""Reproduce exact Global 7.1 packet field 2 native keyed-container evidence.

Inputs are two original-client source artifacts from run 39710073036 and
one original factory method artifact from run 39703359133. All source SHA-256s
are checked. Original RVA, mnemonic, operands,
opcode bytes and independent owner-method metadata are validated. This does
not assign a gameplay semantic name to the key or establish server loot level.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from genshinre.nativeprofile import PROFILE_71

CALLEE_SHA="c284a06813e8addd777706b16c0f10987d194dbe2e4af143619772e070e327de"
OWNER_SHA="747577559de57bb0fa637964b1b5c83c49ed4f5221cadf08682b970c522a8b44"
FACTORY_SOURCE_SHA="7bec3f006b819bcc956cc3c85a38a71176945b232767ca6f48294c779f78bc11"
ANCHORS={
  "initialization": {
    "0x184EE979": [
      "mov",
      "r13d, edx",
      "4189d5"
    ],
    "0x184EE97C": [
      "mov",
      "r15, rcx",
      "4989cf"
    ],
    "0x184EE983": [
      "inc",
      "dword ptr [rcx + 0x44]",
      "ff4144"
    ],
    "0x184EE98C": [
      "cmp",
      "qword ptr [rcx + 0x10], 0",
      "4883791000"
    ],
    "0x184EEBB7": [
      "cmp",
      "dword ptr [r12 + r15], ebp",
      "43392c3c"
    ],
    "0x184EEBC1": [
      "mov",
      "r14d, dword ptr [r12 + r15 + 8]",
      "478b743c08"
    ]
  },
  "lookup": {
    "0x184EE690": [
      "mov",
      "dword ptr [rsp + 0x24], edx",
      "89542424"
    ],
    "0x184EE694": [
      "mov",
      "rsi, qword ptr [rcx + 0x10]",
      "488b7110"
    ],
    "0x184EE69D": [
      "mov",
      "r12, qword ptr [rcx + 0x18]",
      "4c8b6118"
    ],
    "0x184EE71E": [
      "mov",
      "ebp, dword ptr [rsi + 0x18]",
      "8b6e18"
    ],
    "0x184EE73A": [
      "mov",
      "ebx, dword ptr [rsi + rax*4 + 0x20]",
      "8b5c8620"
    ],
    "0x184EE767": [
      "cmp",
      "dword ptr [r12 + rbp], ecx",
      "41390c2c"
    ],
    "0x184EE76D": [
      "cmp",
      "dword ptr [r12 + rbp + 8], edi",
      "41397c2c08"
    ],
    "0x184EE780": [
      "mov",
      "ebx, dword ptr [r12 + rbp + 4]",
      "418b5c2c04"
    ],
    "0x184EE70A": [
      "mov",
      "ebx, 0xffffffff",
      "bbffffffff"
    ],
    "0x184EE8DF": [
      "mov",
      "eax, ebx",
      "89d8"
    ],
    "0x184EE8F1": [
      "ret",
      "",
      "c3"
    ]
  },
  "factory": {
    "0xFCDF4B9": [
      "mov",
      "r14, r8",
      "4d89c6"
    ],
    "0xFCDF4BC": [
      "mov",
      "rbx, rdx",
      "4889d3"
    ],
    "0xFCDF4BF": [
      "mov",
      "rsi, rcx",
      "4889ce"
    ],
    "0xFCDF50F": [
      "mov",
      "rdi, rax",
      "4889c7"
    ],
    "0xFCDF512": [
      "mov",
      "qword ptr [rax + 0x28], rbx",
      "48895828"
    ],
    "0xFCDF516": [
      "mov",
      "qword ptr [rax + 0x20], r14",
      "4c897020"
    ],
    "0xFCDF550": [
      "mov",
      "rcx, rdi",
      "4889f9"
    ],
    "0xFCDF553": [
      "mov",
      "rdx, rsi",
      "4889f2"
    ],
    "0xFCDF556": [
      "call",
      "0x14fcdf5d0",
      "e875000000"
    ]
  },
  "handle": {
    "0xFCDF855": [
      "mov",
      "rdi, qword ptr [rax + rcx*8 + 0x20]",
      "488b7cc820"
    ],
    "0xFCDF863": [
      "mov",
      "rbx, qword ptr [rsi + 0x28]",
      "488b5e28"
    ],
    "0xFCDF870": [
      "mov",
      "edx, dword ptr [rdi + 0x98]",
      "8b9798000000"
    ],
    "0xFCDF87A": [
      "mov",
      "rcx, rbx",
      "4889d9"
    ],
    "0xFCDF87D": [
      "call",
      "0x1584ee680",
      "e8feed8008"
    ]
  }
}
OUT=Path("versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-field2-keyed-container-native-flow.json")


def check_insns(rows: list[dict], expected: dict, *, op_key: str) -> int:
    ins={row["rva"].upper():row for row in rows}
    if len(ins)!=len(rows):raise ValueError("duplicate original native instruction")
    for addr,(mnemonic,operand,code) in expected.items():
        row=ins.get(addr.upper())
        if row is None or (row["mnemonic"],row["operands"],row[op_key]) != (mnemonic,operand,code):
            raise ValueError("original native instruction mismatch at "+addr)
    return len(expected)


def audit(callee_raw:bytes, owner_raw:bytes, factory_raw:bytes)->dict:
    if hashlib.sha256(callee_raw).hexdigest()!=CALLEE_SHA:
        raise ValueError("original callee source artifact hash mismatch")
    if hashlib.sha256(owner_raw).hexdigest()!=OWNER_SHA:
        raise ValueError("original owner source artifact hash mismatch")
    if hashlib.sha256(factory_raw).hexdigest()!=FACTORY_SOURCE_SHA:
        raise ValueError("original factory source artifact hash mismatch")
    caller=json.loads(callee_raw)
    owner=json.loads(owner_raw)
    factory_report=json.loads(factory_raw)
    if (caller["originalExeSha256"]!=PROFILE_71.exe_sha256
        or owner["originalExeSha256"]!=PROFILE_71.exe_sha256
        or caller["knownOriginalElementType"]!="KFOLLNPEMHH"):
        raise ValueError("exact original 7.1 source identity changed")
    if caller["callsite"]["originalBytes"]!="e89df28008" or caller["callsite"]["nativeCallTargetRva"]!="0x184EE960":
        raise ValueError("original OnAccept callsite drift")
    if caller["peerCallsite"]["originalOpcode"]!="e8feed8008" or caller["peerCallsite"]["nativeCalleeRva"]!="0x184EE680":
        raise ValueError("original Handle callsite drift")
    if owner["onAcceptOwner"]["ownerTypeDefinitionIndex"]!=24767:
        raise ValueError("original collector owner type drift")
    original_fields=owner["onAcceptOwner"]["fields"]
    if sorted((f["fieldTypeName"],f["fieldRuntimeTypeIndex"]) for f in original_fields)!=[("Action",452455),("kind_0x15",484299)]:
        raise ValueError("original declared instance fields drift")
    if factory_report["originalExeSha256"]!=PROFILE_71.exe_sha256:
        raise ValueError("original factory EXE source drift")
    factory=factory_report["methodSources"]["190172"]
    if factory["methodRva"]!="0xFCDF4B0":
        raise ValueError("original factory RVA drift")
    if not any(m["methodIndex"]==190172 and m["originalParameterTypes"]=='["KIIKIELOHOG","kind_0x15","Action"]' for m in owner["onAcceptOwner"]["methods"]):
        raise ValueError("original factory method signature drift")
    original_methods=owner["onAcceptOwner"]["methods"]
    if not any(m["methodIndex"]==190174 and m["originalMethodName"]=="OnAccept" and m["nativeMethodRva"]=="0xFCDF5D0" for m in original_methods):
        raise ValueError("native OnAccept metadata drift")
    if not any(m["methodIndex"]==190173 and m["originalMethodName"]=="Handle" and m["originalParameterTypes"]=='["int32"]' for m in original_methods):
        raise ValueError("native Handle index-parameter metadata drift")
    handle=owner["nativeConstructors"]["190173"]["firstInstructions"]
    if owner["nativeConstructors"]["190173"]["originalMethodRva"]!="0xFCDF7F0":
        raise ValueError("original Handle executable owner drift")
    checked={
        "initialization":check_insns(caller["callee"]["disassembledInstructions"],ANCHORS["initialization"],op_key="hex"),
        "lookup":check_insns(caller["peerCallee"]["decodedInstructions"],ANCHORS["lookup"],op_key="hex"),
        "handle":check_insns(handle,ANCHORS["handle"],op_key="hex"),
        "factory":check_insns(factory["firstInstructionSnapshots"],ANCHORS["factory"],op_key="bytes")
    }
    if (caller["callee"]["sourceBytesSha256"]!="4637364e72901d3633c3054c1f28df94ba6e5897026d66e565d2b28f7ebc2a16"
        or caller["peerCallee"]["sourceBytesSha256"]!="9c1958d233a71dae693b41dfc6a0b652938f31778ae3770b07235e5589fe2af1"):
        raise ValueError("original native helper source bytes changed")
    result=json.loads(OUT.read_text(encoding="utf-8"))
    if result["originalExeSha256"]!=PROFILE_71.exe_sha256 or result["originalInstructionWitness"]!=ANCHORS:
        raise ValueError("published original source boundary changed")
    if checked!=result["evidence"]["nativeInstructionAnchorsByRole"]:
        raise ValueError("published original instruction witness count drift")
    return result


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--callee-artifact",type=Path,required=True)
    p.add_argument("--owner-artifact",type=Path,required=True)
    p.add_argument("--factory-artifact",type=Path,required=True)
    a=p.parse_args()
    result=audit(a.callee_artifact.read_bytes(),a.owner_artifact.read_bytes(),a.factory_artifact.read_bytes())
    print(json.dumps({"status":result["status"],
                      "verifiedInstructionGroups":result["evidence"]["nativeInstructionAnchorsByRole"]},indent=2))


if __name__=="__main__":
    main()
