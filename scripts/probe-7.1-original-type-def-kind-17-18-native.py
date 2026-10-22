#!/usr/bin/env python3
"""Global 7.1 source original raw type-record kind 0x11/0x12 to type-definition path.

Original client binary is the sole source of executable/Il2CppType structure.
The 30-case 0x50D9C0 original native resolver has two raw numeric cases
(17,18) jumping to one code branch 0x50D9EA, which reads a dword at
record+0 and tail-jumps to internal 0x51CD50. Audit its native target and
compare the canonical original runtime-type array's source bytes with
generated original metadata. Do not use community enum meanings or infer
that any runtime factory static class slot is mapped by this branch.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256
from genshinre.typearray import decode_type_entry,is_valid_type_entry,ENTRY_SIZE

PRIOR="versions/7.1.0-global/analyses/progression/world/7.1-original-metadata-kind1-type-resolver-30-case-native.json"
RESOLVER_RVA=0x50D9C0
RESOLVER_SIZE=0x480
RESOLVER_SHA="83347d5b374e29f40e0b35ff2e99bb69b387d1d57286d953ccf7a39b982c971b"
COMMON_BRANCH=0x50D9EA
TAIL_JUMP=0x50D9F2
TYPEDEF_NATIVE_RVA=0x51CD50
TYPEDEF_WINDOW=0x680
EXPECTED_TYPE_ARRAY_RVA=0x2E1EA20
SOURCE_RUNTIME_INDEXES=(0,1,405772,683573)
TYPE_NAMES_BLOB=None  # types.csv is original generated, guard count and known anchor


def source_prior(path:Path)->dict:
    j=json.loads(path.read_text(encoding="utf-8"))
    raw=j["originalNativeTypeRecordResolver"]
    by_id={x["rawNumericKind"]:x for x in raw["originalKindJumpTableTargets"]}
    if (j["originalGlobal71ExeSha256"]!=PROFILE_71.exe_sha256 or
        j["originalMetadataSha256"]!=PROFILE_71.metadata_sha256 or
        raw["entryRva"]!=f"0x{RESOLVER_RVA:X}" or
        raw["sourceWindowSha256"]!=RESOLVER_SHA or
        len(by_id)!=30 or
        any(by_id[k]["sourceTargetRva"]!=f"0x{COMMON_BRANCH:X}" for k in (17,18))):
        raise ValueError("source-original 7.1 raw type-kind 17/18 native dispatch drift")
    return j


def original_types(types:Path)->dict[int,str]:
    targets={84249}
    found={}
    count=0
    with types.open("r",encoding="utf-8-sig",newline="") as stream:
        rows=csv.DictReader(stream)
        if not {"type_definition_index","type_name"}.issubset(rows.fieldnames or ()):
            raise ValueError("missing original type definition fields")
        for row in rows:
            count+=1
            idx=int(row["type_definition_index"])
            if idx in targets:
                found[idx]=row["type_name"]
    if count!=PROFILE_71.type_definition_count or found!={84249:"DMMJNICDOHM"}:
        raise ValueError("original 7.1 metadata type names/count drift")
    return found


def inspect(exe:Path,types:Path,prior:Path)->dict:
    source_prior(prior)
    names=original_types(types)
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 client")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86 import X86_OP_MEM,X86_REG_RIP
    with PEImage(exe) as pe:
        resolver=pe.read_rva(RESOLVER_RVA,RESOLVER_SIZE)
        if len(resolver)!=RESOLVER_SIZE or hashlib.sha256(resolver).hexdigest()!=RESOLVER_SHA:
            raise ValueError("original raw type record native resolver source SHA drift")
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        md.detail=True
        native=list(md.disasm(resolver,pe.image_base+RESOLVER_RVA))
        rows={x.address-pe.image_base:{"rva":f"0x{x.address-pe.image_base:X}",
              "mnemonic":x.mnemonic,"operands":x.op_str,"bytes":bytes(x.bytes).hex()} for x in native}
        required={
          0x50D9C9:("movsx","ecx, byte ptr [rcx + 0xa]"),
          0x50D9CF:("dec","ecx"),
          0x50D9D1:("cmp","ecx, 0x1d"),
          0x50D9EA:("mov","ecx, dword ptr [rdi]"),
          0x50D9EC:("add","rsp, 0x48"),
          0x50D9F0:("pop","rdi"),
          0x50D9F1:("pop","rsi"),
          0x50D9F2:("jmp",f"0x{pe.image_base+TYPEDEF_NATIVE_RVA:x}")
        }
        for rva,(mnemonic,ops) in required.items():
            row=rows.get(rva)
            if row is None or (row["mnemonic"],row["operands"])!=(mnemonic,ops):
                raise ValueError(f"original Global 7.1 native type record branch changed: 0x{rva:X}")
        blob=pe.read_rva(TYPEDEF_NATIVE_RVA,TYPEDEF_WINDOW)
        if len(blob)!=TYPEDEF_WINDOW:raise ValueError("original type-def resolver native window not file backed")
        full=list(md.disasm(blob,pe.image_base+TYPEDEF_NATIVE_RVA))
        helper_rows=[{"rva":f"0x{x.address-pe.image_base:X}",
             "mnemonic":x.mnemonic,"operands":x.op_str,"bytes":bytes(x.bytes).hex()}
             for x in full]
        helper_calls=[{"instruction":row,"nativeTargetRva":f"0x{int(row['operands'],16)-pe.image_base:X}"}
             for row in helper_rows if row["mnemonic"]=="call" and row["operands"].startswith("0x")]
        type_array_blob=pe.read_rva(PROFILE_71.type_array_pointer_rva,8)
        if len(type_array_blob)!=8:raise ValueError("original IL2CPP runtime type array pointer missing")
        type_array_va=int.from_bytes(type_array_blob,"little")
        array_rva=type_array_va-pe.image_base
        if array_rva!=EXPECTED_TYPE_ARRAY_RVA:raise ValueError("original runtime type-array pointer changed")
        samples=[]
        for i in SOURCE_RUNTIME_INDEXES:
            cell=pe.read_rva(array_rva+i*ENTRY_SIZE,ENTRY_SIZE)
            if len(cell)!=ENTRY_SIZE or not is_valid_type_entry(cell):
                raise ValueError(f"original source runtime type index {i} invalid")
            decoded=decode_type_entry(cell)
            typedef=decoded["data_u32"] if decoded["kind"] in (0x11,0x12) else None
            samples.append({
                "sourceRuntimeTypeIndex":i,
                "originalTypeArrayEntryRva":f"0x{array_rva+i*ENTRY_SIZE:X}",
                "sourceOriginalNative16ByteRecordHex":cell.hex(),
                "rawOriginalTypeRecordKind":f"0x{decoded['kind']:02X}",
                "rawSourceRecordDataU32":decoded["data_u32"],
                "sourceOriginalTypeDefinitionIndexForKind17Or18":typedef,
                "sourceOriginalTypeDefinitionNameIfProven":names.get(typedef),
            })
        anchor=next(x for x in samples if x["sourceRuntimeTypeIndex"]==PROFILE_71.runtime_type_anchor.type_index)
        if (anchor["rawOriginalTypeRecordKind"]!=f"0x{PROFILE_71.runtime_type_anchor.kind:02X}" or
            anchor["sourceOriginalTypeDefinitionIndexForKind17Or18"]!=PROFILE_71.runtime_type_anchor.type_definition_index or
            anchor["sourceOriginalTypeDefinitionNameIfProven"]!=PROFILE_71.runtime_type_anchor.type_name):
            raise ValueError("mandatory source-original runtime Il2CppType type-definition anchor missing")
    return {
        "schemaVersion":1,
        "status":"SOURCE_GLOBAL_7_1_NATIVE_RAW_TYPE_KIND_17_18_TO_TYPEDEF_INDEX__FACTORY_CLASS_SLOT_UNVERIFIED",
        "originalExecutableSha256":PROFILE_71.exe_sha256,
        "originalMetadataSha256":PROFILE_71.metadata_sha256,
        "previousOriginalResolverReport":PRIOR,
        "sourceNativeRawRecordResolverRva":f"0x{RESOLVER_RVA:X}",
        "sourceNativeResolverWindowSha256":RESOLVER_SHA,
        "sourceCommonBranchRva":f"0x{COMMON_BRANCH:X}",
        "sourceRecordTypeNumericKindAlternatives":[17,18],
        "sourceBranchInstructions":[rows[i] for i in required],
        "sourceOriginalTypeDefinitionNativeLookup":{
            "calleeRva":f"0x{TYPEDEF_NATIVE_RVA:X}",
            "sampledBoundedWindowBytes":TYPEDEF_WINDOW,
            "sourceWindowSha256":hashlib.sha256(blob).hexdigest(),
            "decodedBoundedNativeInstructions":len(helper_rows),
            "sourceFirstNativeInstructions":helper_rows[:135],
            "sourceDirectCalls":helper_calls[:120],
            "sourceWindowNotProvenExactMethod":True,
            "numericRecordFieldMeaningProvenFromDirectCall":False
        },
        "originalRuntimeTypeArrayPointerRva":f"0x{PROFILE_71.type_array_pointer_rva:X}",
        "originalRuntimeTypeArrayRva":f"0x{array_rva:X}",
        "canonicalOriginalRuntimeTypeCount":PROFILE_71.runtime_type_count,
        "sourceOriginalTypeArraySampleRecords":samples,
        "nativeSourceTypeRecordKind17Or18ReadsDataU32AndCallsResolver":True,
        "originalFactoryCase1ConcreteClassResolved":False,
        "originalFactoryCase14ConcreteClassResolved":False,
        "originalScenePointResourceLoaderLinkedToFactory":False,
        "originalChestInstancePositionOrLevelProven":False,
        "limits":[
            "Numeric record kinds 17 and 18 were independently observed to branch to the same native routine reading dword at Il2CppType+0 and tail-jumping 0x51CD50.",
            "Original names come solely from original decoded 7.1 type metadata and original static Il2CppType raw bytes; no historical enum names are needed.",
            "The 0x51CD50 source-native bounded disassembly is a lead for its exact class mapping, not yet proof of concrete original factory class-slot identity.",
            "Original Scene/Point asset loader, Gadget/chest instance coordinates, level, and client/server scene placement authority remain unverified."
        ]
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("exe","types","prior","output"):
        p.add_argument("--"+key,required=True,type=Path)
    a=p.parse_args()
    d=inspect(a.exe,a.types,a.prior)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(d,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_TYPEDEF_NATIVE_BEGIN")
    print(json.dumps({k:v for k,v in d.items() if k!="sourceOriginalTypeDefinitionNativeLookup"}|
       {"sourceOriginalTypeDefinitionNativeLookup":{k:v for k,v in d["sourceOriginalTypeDefinitionNativeLookup"].items()
             if k!="sourceFirstNativeInstructions"}},indent=2,ensure_ascii=False))
    print("ORIGINAL_TYPEDEF_NATIVE_END")

if __name__=="__main__":main()
