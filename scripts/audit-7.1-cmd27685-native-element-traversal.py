#!/usr/bin/env python3
"""Audit verified 7.1 native array-element traversal from CmdId 27685.

Inputs are separately generated exact-client native opcode reports. Every
promoted instruction address, opcode and provenance hash is checked. This
proves that the observed +0x98 scalar is read FROM AN ELEMENT OF A MESSAGE
COLLECTION. It does NOT establish a level, entity-id or loot selector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

OWNER_REPORT_SHA256 = "b5af80c132d5fe282a41f3270215887ac578e8d71b1942b34991a02febddee3a"
CONSUMER_REPORT_SHA256 = "7bec3f006b819bcc956cc3c85a38a71176945b232767ca6f48294c779f78bc11"
METHODS = {"constructor": "530821", "staticInitializer": "530822",
           "collector": "190174", "factory": "190172"}
NATIVE_INSTRUCTIONS = {
  "constructor": {
    "0xC16BC49": [
      "mov",
      "rcx, qword ptr [rip - 0x69674b8]",
      "488b0d488b69f9"
    ],
    "0xC16BC50": [
      "call",
      "0x140529a10",
      "e8bbdd3bf4"
    ],
    "0xC16BC62": [
      "call",
      "0x1570c2ab0",
      "e8496ef50a"
    ],
    "0xC16BC67": [
      "mov",
      "qword ptr [rsi + 0x18], rdi",
      "48897e18"
    ]
  },
  "staticInitializer": {
    "0xC16BF9D": [
      "call",
      "0x140529a10",
      "e86eda3bf4"
    ],
    "0xC16BFA5": [
      "mov",
      "dword ptr [rax + 0x10], 0x42",
      "c7401042000000"
    ],
    "0xC16BFAC": [
      "mov",
      "qword ptr [rax + 0x18], rdi",
      "48897818"
    ],
    "0xC16BFC8": [
      "mov",
      "qword ptr [rax + 0x28d40], rsi",
      "4889b0408d0200"
    ]
  },
  "factory": {
    "0xFCDF556": [
      "call",
      "0x14fcdf5d0",
      "e875000000"
    ]
  },
  "collector": {
    "0xFCDF5EC": [
      "mov",
      "qword ptr [rdi + 0x10], r14",
      "4c897710"
    ],
    "0xFCDF600": [
      "mov",
      "rax, qword ptr [r14 + 0x18]",
      "498b4618"
    ],
    "0xFCDF60D": [
      "mov",
      "rax, qword ptr [rax + 0x10]",
      "488b4010"
    ],
    "0xFCDF61A": [
      "mov",
      "eax, dword ptr [rax + 0x18]",
      "8b4018"
    ],
    "0xFCDF61D": [
      "mov",
      "dword ptr [rdi + 0x18], eax",
      "894718"
    ],
    "0xFCDF672": [
      "mov",
      "ecx, dword ptr [rax + 0x18]",
      "8b4818"
    ],
    "0xFCDF67E": [
      "mov",
      "rax, qword ptr [rax + 0x10]",
      "488b4010"
    ],
    "0xFCDF697": [
      "mov",
      "rax, qword ptr [rax + rsi*8 + 0x20]",
      "488b44f020"
    ],
    "0xFCDF6B2": [
      "mov",
      "edx, dword ptr [rax + 0x98]",
      "8b9098000000"
    ],
    "0xFCDF6B8": [
      "xor",
      "r8d, r8d",
      "4531c0"
    ],
    "0xFCDF6BB": [
      "mov",
      "r9b, 1",
      "41b101"
    ]
  }
}


def verify_opcode_rows(records: list[dict], anchors: dict[str, list[str]],
                       *, instruction_address_field: str,
                       instruction_operand_field: str) -> None:
    lookup = {x["rva"].upper(): x for x in records}
    if len(lookup) != len(records):
        raise ValueError("duplicate original native instruction")
    for address, (mnemonic, operand, hexbytes) in anchors.items():
        actual = lookup.get(address.upper())
        if actual is None:
            raise ValueError(f"native source missing original RVA {address}")
        fields = (actual["mnemonic"], actual[instruction_operand_field],
                  actual["bytes"])
        if fields != (mnemonic, operand, hexbytes):
            raise ValueError(f"native instruction changed at {address}")


def build(original_owner_json: bytes, original_consumers_json: bytes) -> dict:
    if hashlib.sha256(original_owner_json).hexdigest() != OWNER_REPORT_SHA256:
        raise ValueError("original owner disassembly artifact SHA-256 mismatch")
    if hashlib.sha256(original_consumers_json).hexdigest() != CONSUMER_REPORT_SHA256:
        raise ValueError("original consumers disassembly artifact SHA-256 mismatch")
    owner = json.loads(original_owner_json)
    consumers = json.loads(original_consumers_json)
    if (owner["source"]["exeSha256"] != PROFILE_71.exe_sha256
        or owner["nativeRegistry"]["cmdId"] != 27685
        or owner["nativeRegistry"]["typeName"] != "KIIKIELOHOG"
        or consumers["originalExeSha256"] != PROFILE_71.exe_sha256
        or consumers["verifiedNativeCmdId"] != 27685
        or consumers["verifiedNativeTypeName"] != "KIIKIELOHOG"):
        raise ValueError("original client/source packet identity mismatch")

    ctor = owner["boundedNativeMethods"][METHODS["constructor"]]
    static = owner["boundedNativeMethods"][METHODS["staticInitializer"]]
    accept = consumers["methodSources"][METHODS["collector"]]
    factory = consumers["methodSources"][METHODS["factory"]]
    if (ctor["rva"], static["rva"], accept["methodRva"], factory["methodRva"]) != (
        "0xC16BC40", "0xC16BF80", "0xFCDF5D0", "0xFCDF4B0"):
        raise ValueError("wrong native declaring method")
    verify_opcode_rows(ctor["firstInstructions"], NATIVE_INSTRUCTIONS["constructor"],
                       instruction_address_field="rva", instruction_operand_field="operands")
    verify_opcode_rows(static["firstInstructions"], NATIVE_INSTRUCTIONS["staticInitializer"],
                       instruction_address_field="rva", instruction_operand_field="operands")
    verify_opcode_rows(accept["firstInstructionSnapshots"], NATIVE_INSTRUCTIONS["collector"],
                       instruction_address_field="rva", instruction_operand_field="operands")
    verify_opcode_rows(factory["firstInstructionSnapshots"],
                       NATIVE_INSTRUCTIONS["factory"],
                       instruction_address_field="rva", instruction_operand_field="operands")
    if not any(m["methodIndex"] == 530822 and m["name"] == ".cctor"
               for m in owner["ownerMethods"]):
        raise ValueError("static initializer metadata method unverified")
    if not any(m["methodIndex"] == 530821 and m["name"] == ".ctor"
               for m in owner["ownerMethods"]):
        raise ValueError("constructor metadata method unverified")
    if not any(m["methodIndex"] == 190174 and m["methodName"] == "OnAccept"
               for m in consumers["originalParameterReferences"]):
        raise ValueError("original OnAccept typed parameter unverified")

    return {
        "schemaVersion": 1,
        "status": "ORIGINAL_71_CMD27685_OBJECT_PLUS_0X98_IS_NESTED_COLLECTION_ELEMENT__LEVEL_UNVERIFIED",
        "originalExeSha256": PROFILE_71.exe_sha256,
        "originalCmdId": 27685,
        "originalNativeType": "KIIKIELOHOG",
        "originalDerivedEvidence": {
            "ownerNativeMethodArtifactSha256": OWNER_REPORT_SHA256,
            "consumerNativeMethodArtifactSha256": CONSUMER_REPORT_SHA256,
            "ownerSourceRun": "https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39702524539",
            "consumerSourceRun": "https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39703359133",
        },
        "originalInstructionWitness": {
            "checkedInstructionCount": sum(len(v) for v in NATIVE_INSTRUCTIONS.values()),
            "constructorInitializesMessageCollectionPointerAtObjectOffset": "0x18",
            "staticInitializerConstructedObjectLiteralAtOffset0x10": "0x42",
            "staticInitializerLiteralInterpretedAsProtobufTag": False,
            "staticInitializerTagShapedValueIfWireKey": {
                "potentialFieldNumber": 8, "potentialWireType": 2
            },
            "typedOnAcceptOwner": "JLDCJCKHJEM",
            "onAcceptRva": "0xFCDF5D0",
            "onAcceptReceivesThisPacketAsParameter": True,
            "onAcceptReadsMessageCollectionOffset": "0x18",
            "onAcceptReadsCollectionCountAtNestedOffset": "0x18",
            "onAcceptReadsIndexedElementPointerAtRelativeOffset": "0x20 + index*8",
            "onAcceptReads32bitScalarFromElementOffset": "0x98",
            "element32bitScalarIsFieldOfRootPacket": False,
            "concreteElementClassProven": False,
            "scalarSemanticLevelProven": False,
            "scalarSemanticEntityIdProven": False,
        },
        "limits": [
            "The +0x98 load is reached after an indexed pointer load from the packet's +0x18 collection, so it is an element object offset. Its type and semantic field name are not known.",
            "The source .cctor creates a codec-shaped object containing 0x42. Protobuf field 8 / wire type 2 is only a numerical interpretation; the specific codec class is not independently resolved.",
            "This is native original-client object memory layout, not native scene placement or any official server reward schema.",
            "The 7.1 CmdId semantic name, protocol direction, original PropPair level handling, and chest loot grade/level/type remain unknown.",
            "Original executable and derived large disassemblies are not vendored.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner-artifact", required=True, type=Path)
    parser.add_argument("--consumers-artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    value = build(args.owner_artifact.read_bytes(), args.consumers_artifact.read_bytes())
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != value:
            raise SystemExit("original native element traversal witness changed")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": value["status"],
                      "instructionWitness": value["originalInstructionWitness"]}, indent=2))


if __name__ == "__main__":
    main()
