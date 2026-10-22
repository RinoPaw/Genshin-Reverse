#!/usr/bin/env python3
"""Revalidate original Global 7.1 CmdId27685 repeated-element field 2.

Two exact-client native artifacts from source-pinned GitHub Actions are
content-SHA-256 checked. This proves native cross-type CopyFrom edges,
element candidate class, its protobuf-shaped field 2 read at object offset
+0x98, and the consumer reading the same offset from an indexed element.
It does NOT grant a semantic name like entityId/level or server loot grade.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71

XREF_SHA256="81f3f942f34e11d069502d8dc20e2d6331d13c7a004e903979b171943cd55301"
NATIVE_SHA256="ced2db435cb9b5c8885df6a4d30821f339c722866fe1eed68025c05c1eaa1f4b"
ORIGINAL_CLASS_SLOT="0x57D1928"
EXPECTED_ORIGINAL_TYPE="KFOLLNPEMHH"
EXPECTED_NATIVE_READER="0xB43A2A0"
EXPECTED_NATIVE_COPYFROM="0xB43D570"
EXPECTED_NATIVE_MESSAGE_CONSUMER="0xFCDF5D0"
OUTPUT=Path("versions/7.1.0-global/analyses/progression/economy/7.1-cmd27685-kfoll-element-wire-field2.json")


def instruction_at(method: dict, rva: str):
    for hit in method["offset98Instructions"]:
        if hit["instruction"]["rva"].upper()==rva.upper():
            return hit
    raise ValueError(f"original +0x98 instruction missing: {rva}")


def context_op(hit:dict,rva:str, mnemonic:str, operand:str)->bool:
    return any(x["rva"].upper()==rva.upper() and
               x["mnemonic"]==mnemonic and x["operand"]==operand
               for x in hit["context"])


def audit(xrefs_raw: bytes,native_raw: bytes)->dict:
    if hashlib.sha256(xrefs_raw).hexdigest()!=XREF_SHA256:
        raise ValueError("original native xref artifact SHA-256 mismatch")
    if hashlib.sha256(native_raw).hexdigest()!=NATIVE_SHA256:
        raise ValueError("original field-offset artifact SHA-256 mismatch")
    xref=json.loads(xrefs_raw)
    native=json.loads(native_raw)
    if (xref["originalExeSha256"]!=PROFILE_71.exe_sha256
        or native["originalExeSha256"]!=PROFILE_71.exe_sha256):
        raise ValueError("unexpected original executable identity")
    ext=xref["typeInfoSlotXrefs"]
    expected_refs={
        "collectionAllocationTypeInfo":3,
        "collectionConstructorAuxiliaryTypeInfo":3,
        "repeatedElementStaticTypeInfo":26,
        "staticCodecAllocationTypeInfo":2604
    }
    if {k:v["allAlignedRipReferences"] for k,v in ext.items()}!=expected_refs:
        raise ValueError("original aligned static pointer reference counts changed")
    if ext["repeatedElementStaticTypeInfo"]["sourceStaticSlotRva"]!=ORIGINAL_CLASS_SLOT:
        raise ValueError("original element static TypeInfo slot changed")
    if (native["verifiedRelatedMetadata"]["soleFieldType"]!=EXPECTED_ORIGINAL_TYPE
        or native["verifiedRelatedMetadata"]["elementTypeDefIndex"]!=85506
        or native["verifiedRelatedMetadata"]["ownerType"]!="CEOGMKOJDBL"):
        raise ValueError("independent original CEOG typed-field evidence changed")
    original=xref["associatedOriginalMetadataTypes"]
    if (len(original[EXPECTED_ORIGINAL_TYPE]["fields"])!=27
        or len(original[EXPECTED_ORIGINAL_TYPE]["methods"])!=17
        or len(original["HEOLIIGOCNH"]["fields"])!=21):
        raise ValueError("original native field/member inventories changed")
    vision=[row["field_name"] for row in original["HEOLIIGOCNH"]["fields"]
            if row["field_name"]!="value__"]
    if len(vision)!=20 or not {"VisionMeet","VisionDie","VisionBorn","VisionRemove"}.issubset(vision):
        raise ValueError("original enum Vision field names changed")
    if not any(m["method_index"]=="705948"
               and m["rva"]==EXPECTED_NATIVE_COPYFROM
               for m in original[EXPECTED_ORIGINAL_TYPE]["methods"]):
        raise ValueError("original element CopyFrom owner identity changed")
    local=native["methodReports"]
    if (local["elementReader"]["sourceRva"]!=EXPECTED_NATIVE_READER
        or local["elementCopyFrom"]["sourceRva"]!=EXPECTED_NATIVE_COPYFROM
        or local["collectionConsumer"]["sourceRva"]!=EXPECTED_NATIVE_MESSAGE_CONSUMER):
        raise ValueError("original native method identities changed")
    if not any(q["rva"]=="0x79DE19A" and
               q["operand"]=="0x14b43d570" and q["mnemonic"]=="jmp"
               for q in local["containerCopyFrom"]["directControlCalls"]):
        raise ValueError("original CEOG typed CopyFrom->KFOLL direct edge missing")
    owner_refs=ext["repeatedElementStaticTypeInfo"]["sampleReferenceMethods"]
    if not any(row["loadInstructionRva"]=="0x79DE160"
               and row["nearestOriginalMethods"] and
               row["nearestOriginalMethods"][0]["methodIndex"]=="409306"
               for row in owner_refs):
        raise ValueError("original CEOG CopyFrom TypeInfo slot positive control missing")
    readers=local["elementReader"]
    a=instruction_at(readers,"0xB43A342")
    b=instruction_at(readers,"0xB43AD6F")
    if (a["instruction"]["operand"]!="dword ptr [r12 + 0x98], eax"
        or b["instruction"]["operand"]!="dword ptr [r12 + 0x98], eax"):
        raise ValueError("native +0x98 field write shape changed")
    if not context_op(a,"0xB43A328","cmp","eax, 0x10"):
        raise ValueError("original native wire-tag 0x10 conditional missing")
    if not context_op(a,"0xB43A33D","call","0x1499a23f0"):
        raise ValueError("original scalar value reader missing")
    copy_src=instruction_at(local["elementCopyFrom"],"0xB43D5C0")
    copy_dst=instruction_at(local["elementCopyFrom"],"0xB43D5CA")
    if (copy_src["instruction"]["operand"]!="eax, dword ptr [rdi + 0x98]"
        or copy_dst["instruction"]["operand"]!="dword ptr [r15 + 0x98], eax"):
        raise ValueError("original native CopyFrom scalar chain mismatch")
    consumed=instruction_at(local["collectionConsumer"],"0xFCDF6B2")
    if consumed["instruction"]["operand"]!="edx, dword ptr [rax + 0x98]":
        raise ValueError("original native consumer scalar location changed")
    if not context_op(consumed,"0xFCDF697","mov",
                      "rax, qword ptr [rax + rsi*8 + 0x20]"):
        raise ValueError("original indexed element load missing")
    return {
       "schemaVersion":1,
       "status":"EXACT_7_1_CMD27685_KFOLL_NATIVE_ELEMENT_SCHEMA_FIELD2_VARINT__GAMEPLAY_SEMANTICS_UNPROVEN",
       "originalExeSha256":PROFILE_71.exe_sha256,
       "evidence":{
          "originalRvaXrefArtifactSha256":XREF_SHA256,
          "originalFieldOffsetArtifactSha256":NATIVE_SHA256,
          "originalRvaXrefRun":"https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39707120407",
          "originalFieldOffsetRun":"https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39707594991",
       },
       "nativePacket":{
          "cmdId":27685,
          "obfuscatedClass":"KIIKIELOHOG",
          "visionEnumNativeClass":"HEOLIIGOCNH",
          "verifiedOriginalVisionEnumValues":vision,
          "originalDirectionVerified":False,
       },
       "elementType":{
          "obfuscatedClass":EXPECTED_ORIGINAL_TYPE,
          "nativeTypeDefinitionIndex":85506,
          "originalFieldCount":27,
          "originalMethodCount":17,
          "sourceClassStaticSlotRva":ORIGINAL_CLASS_SLOT,
          "slotAlignedNativeXrefCount":26,
          "classSlotDirectUsersIncludeOtherMessageCode":True,
          "crossTypeEdge":{
              "containerObfuscatedType":"CEOGMKOJDBL",
              "soleOriginalNativeFieldType":EXPECTED_ORIGINAL_TYPE,
              "nativeClassSlotLoadRva":"0x79DE160",
              "nativeCopyFromDirectTailJumpRva":"0x79DE19A",
              "nativeCopyFromTargetRva":EXPECTED_NATIVE_COPYFROM,
          },
          "runtimeGenericArgumentRegistrationIndependentlyResolved":False,
       },
       "field":{
          "objectMemoryOffset":"0x98",
          "writerOriginalMethodRva":EXPECTED_NATIVE_READER,
          "writerNativeInstructions":["0xB43A342","0xB43AD6F"],
          "nativeWireKeyBranchCompare":"0x10",
          "interpretedProtocolWireFieldNumber":2,
          "interpretedProtocolWireType":0,
          "originalReadValueCall":"0x1499A23F0",
          "copyFromSourceRva":"0xB43D5C0",
          "copyFromTargetRva":"0xB43D5CA",
          "externalConsumerMethodRva":EXPECTED_NATIVE_MESSAGE_CONSUMER,
          "externalConsumerReadRva":"0xFCDF6B2",
          "externalConsumerReadsIndexedElement":True,
          "confirmedNativeFieldSemanticName":None,
          "provenOriginalSceneLevel":False,
          "provenOriginalGadgetId":False,
       },
       "limitations":[
          "The native field writer compares protobuf-shaped key 0x10, equivalent to field 2 and varint wire 0, then stores a 32-bit integer at object offset +0x98.",
          "The CEOG sole native field KFOLL and direct tailjump to KFOLL CopyFrom tie the shared TypeInfo slot to KFOLL code; the generic runtime registration itself is unresolved.",
          "OnAccept reads the same +0x98 scalar on a repeated indexed element; field2 semantic name/entityId/level and official server reward authority are not proven.",
          "Native HEOLIIGOCNH enum Vision* names support a scene visibility protocol role, but original registry semantic name and packet direction remain unresolved.",
          "No source binary, full native disassembly, private-server field names or loot reward values were committed.",
       ],
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--xrefs",type=Path,required=True)
    p.add_argument("--native",type=Path,required=True)
    p.add_argument("--output",type=Path,default=OUTPUT)
    p.add_argument("--check",action="store_true")
    a=p.parse_args()
    result=audit(a.xrefs.read_bytes(),a.native.read_bytes())
    if a.check:
        if json.loads(a.output.read_text(encoding="utf-8"))!=result:
            raise SystemExit("original Cmd27685 class/field evidence changed")
    else:
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({"status":result["status"],"elementType":result["elementType"],
                      "field":result["field"]},indent=2))
if __name__=="__main__":
    main()
