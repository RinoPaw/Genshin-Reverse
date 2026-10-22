#!/usr/bin/env python3
"""Original Global 7.1 entity element native oneof/field consumer target census.

Exact Global 7.1 EXE and original methods.csv SHA-1 git blob are required.
Only exact-RVA method records may name direct calls. Protobuf-shaped tags
and native oneof discriminator offsets are reported as raw evidence.
Never assign oneof or spatial semantics to a field by declaration order.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import hashlib
import json
from pathlib import Path
import re

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

METHODS_BLOB="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
PARENT_RVA=0xB43A2A0
PARENT_SIZE=0xCD0
PARENT_HASH="b9daf495a99150725dcadff1d6ba717e9a6edf1461b764ebd13b7f3905eb0c9e"
COPY_RVA=0xB43D570
COPY_SIZE=0x7F0
COPY_HASH="58d93293b78b1614f00effd7d0b4a4a175100ce0c0c4fe6f192b058ac6e11855"
STATIC_RVA=0xB439EF0
STATIC_SIZE=0x3B0
STATIC_HASH="c644e8e01e603d2b90e4c7bbf8a7b688d9814030ae6463220e47280bf9b390a9"
ELEMENT="KFOLLNPEMHH"
CHILD="ABOOLMJBDKE"
CHILD_COPY_RVA=0x11B252C0
CHILD_READER_RVA=0x11B25D70
NATIVE_BASE=0x140000000
VARIANT_OFFSET=0x94
UNION_OFFSET=0x28
TAGS=(0x52,0x5A,0x62,0x6A)
MAX_METHODS_PER_RVA=20


def git_blob(p:Path)->str:
    h=hashlib.sha1()
    h.update(f"blob {p.stat().st_size}\0".encode("ascii"))
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""):
            h.update(b)
    return h.hexdigest()


def method_lookup(methods:Path, target_rvas:set[int]) -> dict[int,list[dict]]:
    if git_blob(methods)!=METHODS_BLOB:
        raise ValueError("original Global 7.1 methods.csv Git blob changed")
    exact=defaultdict(list)
    with methods.open(encoding="utf-8-sig",newline="") as f:
        for m in csv.DictReader(f):
            if not m.get("rva"): continue
            rva=int(m["rva"],16)
            if rva not in target_rvas: continue
            hits=exact[rva]
            if len(hits)>=MAX_METHODS_PER_RVA:
                raise ValueError("ambiguous exact RVA method owners exceed cap")
            hits.append({
                "originalTypeName":m["type_name"],
                "originalTypeDefinitionIndex":int(m["type_definition_index"]),
                "originalMethodIndex":int(m["method_index"]),
                "originalMethodName":m["method_name"],
                "originalParameterTypes":m.get("parameter_types",""),
                "originalReturnType":m.get("return_type",""),
            })
    return dict(exact)


def disasm(data:bytes,base_va:int,origin_rva:int)->list[dict]:
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    return [{"rva":f"0x{ins.address-base_va:X}",
             "mnemonic":ins.mnemonic,"op":ins.op_str,
             "bytes":bytes(ins.bytes).hex()}
             for ins in md.disasm(data,base_va+origin_rva)]


def context(insns:list[dict],i:int,n:int=7)->list[dict]:
    return insns[max(i-n,0):min(i+n+1,len(insns))]


def find_calls(rows:list[dict],base_va:int,method:str)->list[dict]:
    found=[]
    for i,r in enumerate(rows):
        if r["mnemonic"] not in ("call","jmp"):continue
        m=re.fullmatch(r"0x([0-9a-f]+)",r["op"])
        if not m:continue
        dest=int(m.group(1),16)
        if dest<base_va: continue
        target=dest-base_va
        found.append({
            "method":method,"siteRva":r["rva"],
            "mnemonic":r["mnemonic"],
            "targetRva":f"0x{target:X}",
            "targetRvaInteger":target,
            "opcode":r["bytes"],
            "context":context(rows,i,4),
        })
    return found


def inspect_native(exe:Path)->dict:
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 EXE")
    targets={
        "parentReader":(PARENT_RVA,PARENT_SIZE,PARENT_HASH),
        "parentCopyFrom":(COPY_RVA,COPY_SIZE,COPY_HASH),
        "parentStaticInit":(STATIC_RVA,STATIC_SIZE,STATIC_HASH),
    }
    collected={}
    with PEImage(exe) as pe:
        for label,(rva,size,sha) in targets.items():
            b=pe.read_rva(rva,size)
            if len(b)!=size or hashlib.sha256(b).hexdigest()!=sha:
                raise ValueError(f"source native RVA {label} window hash mismatch")
            rows=disasm(b,pe.image_base,rva)
            calls=find_calls(rows,pe.image_base,label)
            collected[label]={
                "startRva":f"0x{rva:X}","sourceSha256":sha,
                "windowBytes":size,"decodedInstructions":len(rows),
                "calls":calls,
                "instructions":rows
            }
    return collected


def tag_witnesses(rows:list[dict]) -> list[dict]:
    seen=[]
    for tag in TAGS:
        tag_hex=f"0x{tag:x}"
        for i,row in enumerate(rows):
            if row["mnemonic"]!="cmp" or row["op"]!=f"eax, {tag_hex}":
                continue
            # Only an x86 CMP and branch chain is observed here; tag numbering
            # follows the protobuf wire-key interpretation.
            seen.append({
                "wireKeyCandidateHex":f"0x{tag:X}",
                "wireFieldNumberIfProtoKey":tag>>3,
                "wireTypeIfProtoKey":tag&7,
                "compareRva":row["rva"],"bytes":row["bytes"],
                "context":context(rows,i,6),
                "linkedTypedFieldProven":False,
            })
    if len(seen)<len(TAGS):
        raise ValueError("original oneof tag-shaped positive control missing")
    return seen


def discriminator_witnesses(rows:list[dict]) ->list[dict]:
    observations=[]
    for i,row in enumerate(rows):
        m=re.fullmatch(r"cmp dword ptr \[r12 \+ 0x94\], (0x[0-9a-f]+|[0-9]+)",row["op"])
        if m:
            value=int(m.group(1),0)
            observations.append({
                "compareRva":row["rva"],
                "discriminatorObjectOffset":"0x94",
                "discriminatorValue":value,
                "context":context(rows,i,5),
                "originalDiscriminatorSemanticName":None,
            })
    got={r["discriminatorValue"] for r in observations}
    if not {10,11,12,13}.issubset(got):
        raise ValueError("source original discriminator positive control absent")
    return observations


def investigate(exe:Path,methods:Path,prior:Path)->dict:
    earlier=json.loads(prior.read_text(encoding="utf-8"))
    if (earlier["originalExeSha256"]!=PROFILE_71.exe_sha256
       or earlier["parentReader"]["sourceSha256"]!=PARENT_HASH
       or earlier["additionalNativeMethods"]["elementCopyFrom"]["originalWindowSha256"]!=COPY_HASH):
        raise ValueError("earlier exact-source native parent report does not match")
    report=inspect_native(exe)
    targets=set()
    for item in report.values():
        targets.update(c["targetRvaInteger"] for c in item["calls"])
    targets.update({CHILD_COPY_RVA,CHILD_READER_RVA})
    owners=method_lookup(methods,targets)
    # A direct target without an exact index row remains unresolved.
    direct=[]
    for name,data in report.items():
        for c in data["calls"]:
            direct.append({
                "originalCallerMethod":name,
                "callRva":c["siteRva"],
                "opcode":c["opcode"],
                "targetRva":c["targetRva"],
                "exactNativeMetadataOwners":owners.get(c["targetRvaInteger"],[]),
                "nativeTargetIdentityFromExactRva":bool(owners.get(c["targetRvaInteger"])),
            })
    call_summary={}
    for name,data in report.items():
        recs=[x for x in direct if x["originalCallerMethod"]==name]
        call_summary[name]={
            "sourceRva":data["startRva"],
            "windowSha256":data["sourceSha256"],
            "decodedInstructionCount":data["decodedInstructions"],
            "callCount":len(recs),
            "exactMappedCalls":sum(bool(r["exactNativeMetadataOwners"]) for r in recs),
            "distinctTargetOwners":[{
                "targetRva":f"0x{k:X}",
                "owners":owners.get(k,[]),
            } for k in sorted(set(c["targetRvaInteger"] for c in data["calls"]))],
        }
    parent=report["parentReader"]["instructions"]
    variants=tag_witnesses(parent)
    disc=discriminator_witnesses(parent)
    child_owners={key:owners.get(key,[]) for key in (CHILD_COPY_RVA,CHILD_READER_RVA)}
    # Restrict declaration to structural results and keep a source audit trail.
    return {
        "schemaVersion":1,
        "status":"ORIGINAL_71_ELEMENT_NATIVE_TAG_DISCRIMINATOR_EXACT_RVA_CALL_OWNERS__TYPED_PAYLOAD_UNRESOLVED",
        "originalClient":PROFILE_71.identity,
        "originalExeSha256":PROFILE_71.exe_sha256,
        "originalMethodsGitBlob":METHODS_BLOB,
        "parentTypeName":ELEMENT,
        "nestedTypeName":CHILD,
        "verifiedOriginalNativeWindows":call_summary,
        "fullDirectNativeCallsWithExactOwners":direct,
        "nativeTagShapedComparisons":variants,
        "nativeDiscriminatorComparisons":disc,
        "originalChildMethodExactOwners":{
            f"0x{key:X}":value for key,value in child_owners.items()
        },
        "evidenceLimits":{
            "unionValueObjectOffsetIfOneof":"0x28",
            "oneofCaseScalarOffsetIfOneof":"0x94",
            "oneofCaseAndTypedOriginalFieldLinked":False,
            "typedABOOLMemoryOffsetProven":False,
            "originalRuntimeDispatchTargetProven":False,
            "originalFloatSemanticPositionProven":False,
            "originalChestPlacementOwnershipProven":False,
        },
        "notes":[
            "A repeated comparison of scalar +0x94 to values 10 through 13 supports a tagged-variant structure, but source does not give its original semantic label.",
            "A field-number-shaped compare does not by itself bind a specific IL2CPP metadata field token to a pointer offset.",
            "Exact-RVA method lookup only names method owners whose start exactly matches the native call target; no nearest-method or generic helper guesses are used.",
            "No current AstaPS, historical Lua, public schema or community JSON fields were used to interpret the original native executable."
        ]
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    for label in ("exe","methods","prior","output"):
        p.add_argument("--"+label,type=Path,required=True)
    args=p.parse_args()
    result=investigate(args.exe,args.methods,args.prior)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_EXACT_ONEOF_CALL_OWNERS_BEGIN")
    print(json.dumps({
        "status":result["status"],
        "windows":result["verifiedOriginalNativeWindows"],
        "tagCandidates":[{"key":x["wireKeyCandidateHex"],"at":x["compareRva"]}
           for x in result["nativeTagShapedComparisons"]],
        "oneofComparisons":[{"rva":x["compareRva"],"v":x["discriminatorValue"]}
           for x in result["nativeDiscriminatorComparisons"]],
        "childOwners":result["originalChildMethodExactOwners"],
    },indent=2,ensure_ascii=False))
    print("ORIGINAL_EXACT_ONEOF_CALL_OWNERS_END")

if __name__=="__main__":
    main()
