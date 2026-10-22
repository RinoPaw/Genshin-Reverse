#!/usr/bin/env python3
"""Scan exact Global 7.1 native machine code for source-guided Scene/Point header transforms.

This is a *hypothesis test*, NOT a decoder. All 13 source Point prefixes and
raw/payload hashes come from the previously authenticated original Unity
block. Candidate additive/XOR 32-bit count transforms are selected purely
by the conservative physical input size bound. We then look for these same
32-bit constants as aligned source-native instruction immediates. A
matching constant is a lead until the original reader call hierarchy and
the full byte-consumption path are verified.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import struct

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

PRIOR_REPORT="versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-source-payload-census.json"
METHOD_BLOB="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
INDEX_SHA="fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
RAW_SCENE3="b27346051cb456c1018ee1726e99de7bd379b2bb910bb3adebcad0b15f540c73"
SOURCE_RUN_COMMIT="63980a635f7202ab7dd4b964047c0788108db893"
MAX_HEADER_OFFSET=8
MIN_BYTES_PER_RECORD=2
MAX_ROOT_COUNT_PROBE=15000
MAX_METHOD_DISASSEMBLY_BYTES=16384
MAX_MATCHES=1024
EXECUTABLE_SECTION_BIT=0x20000000


def git_blob(p:Path)->str:
    h=hashlib.sha1()
    h.update(f"blob {p.stat().st_size}\0".encode())
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(1<<20),b""):
            h.update(chunk)
    return h.hexdigest()


def validate_prior(j:dict)->list[dict]:
    if (j["exactOriginalExeSha256"]!=PROFILE_71.exe_sha256
        or j["exactOriginalDesignIndexRawSha256"]!=INDEX_SHA
        or j["scenesChecked"]!=13
        or j["source"]["exactBranchCommit"]!=SOURCE_RUN_COMMIT
        or j["assetRows"][0]["rawExportSha256"]!=RAW_SCENE3):
        raise ValueError("source-original 7.1 Scene Point census changed")
    if (j["statusCounts"]!={"SOURCE_RAW_AND_FRAMING_VERIFIED":13}
            or [r["sceneId"] for r in j["assetRows"]] !=
               [3,4,5,6,7,9,10,11,100,101,102,103,51195]
            or not all(len(bytes.fromhex(r["unwrappedPayloadFirst32Hex"]))==32
                           and r["status"]=="SOURCE_RAW_AND_FRAMING_VERIFIED"
                           and r["originalBlockVerifiedAsWorldAreaBlock"]
                           and r["chestGadgetInstanceProven"] is False
                       for r in j["assetRows"])):
        raise ValueError("original Point binary prefixes/source identity changed")
    return j["assetRows"]


def candidate_transforms(rows:list[dict])->list[dict]:
    prefixes=[bytes.fromhex(row["unwrappedPayloadFirst32Hex"]) for row in rows]
    bounds=[row["payloadBytes"]//MIN_BYTES_PER_RECORD for row in rows]
    leads=[]
    for offset in range(MAX_HEADER_OFFSET+1):
        encoded=[struct.unpack_from("<I",b,offset)[0] for b in prefixes]
        for first_count in range(min(MAX_ROOT_COUNT_PROBE,bounds[0])+1):
            for model in ("xor","add"):
                key=(encoded[0]^first_count) if model=="xor" else (first_count-encoded[0]) & 0xFFFFFFFF
                counts=([v^key for v in encoded] if model=="xor"
                        else [(v+key)&0xFFFFFFFF for v in encoded])
                if all(count<=cap for count,cap in zip(counts,bounds,strict=True)):
                    leads.append({
                        "headerOffset":offset,
                        "operation":model,
                        "candidateImmediateU32":key,
                        "candidateImmediateHex":f"0x{key:08X}",
                        "candidateCountsIfTransform":counts,
                        "allScenesPlausibleUnderByteBound":True,
                        "nativeCountTransformProven":False,
                    })
    return leads


def original_methods(path:Path)->tuple[list[int],dict[int,list[dict]]]:
    if git_blob(path)!=METHOD_BLOB:
        raise ValueError("source-original Global 7.1 method index Git blob drift")
    indexed={}
    with path.open(encoding="utf-8-sig",newline="") as f:
        for row in csv.DictReader(f):
            if not row.get("rva"):continue
            addr=int(row["rva"],16)
            indexed.setdefault(addr,[])
            if len(indexed[addr])<8:
                indexed[addr].append({
                    "typeName":row["type_name"],
                    "typeDefinitionIndex":int(row["type_definition_index"]),
                    "methodName":row["method_name"],
                    "methodIndex":int(row["method_index"]),
                    "parameterTypes":row.get("parameter_types",""),
                })
    return sorted(indexed),indexed


def native_immediate_witnesses(exe:Path,methods:Path,leads:list[dict])->dict:
    require_sha256(exe,PROFILE_71.exe_sha256,
                   label="original Global 7.1 Windows x64 executable")
    start_rvas,method_index=original_methods(methods)
    candidates={row["candidateImmediateU32"] for row in leads}
    accepted=[]
    raw_candidates=0
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    with PEImage(exe) as pe:
        for sec in pe.sections:
            if not (sec.characteristics & EXECUTABLE_SECTION_BIT):
                continue
            data=pe.read_rva(sec.virtual_address,sec.raw_size)
            pattern=b"\x81\x4b\xc1"
            pos=0
            while True:
                offset=data.find(pattern,pos)
                if offset<0:break
                pos=offset+1
                if offset<1: continue
                candidate=struct.unpack_from("<I",data,offset-1)[0]
                if candidate not in candidates:continue
                raw_candidates+=1
                if raw_candidates>MAX_MATCHES:
                    raise ValueError("source-native constant candidate scan unexpectedly large")
                immediate_rva=sec.virtual_address+offset-1
                method_i=bisect_right(start_rvas,immediate_rva)-1
                if method_i<0:continue
                start=start_rvas[method_i]
                if immediate_rva-start>=MAX_METHOD_DISASSEMBLY_BYTES:
                    accepted.append({
                        "immediateRva":f"0x{immediate_rva:X}",
                        "candidateImmediateHex":f"0x{candidate:08X}",
                        "nearestOriginalMethodStartRva":f"0x{start:X}",
                        "maxBoundedMethodDisassemblyExceeded":True,
                        "alignedImmediateProof":False,
                    })
                    continue
                buf=pe.read_rva(start,immediate_rva-start+16)
                matching=[]
                for ins in md.disasm(buf,pe.image_base+start):
                    ins_rva=ins.address-pe.image_base
                    if ins_rva>immediate_rva:break
                    offset_in_ins=immediate_rva-ins_rva
                    if (getattr(ins,"imm_offset",0)==offset_in_ins
                        and getattr(ins,"imm_size",0)==4
                        and ins.bytes[offset_in_ins:offset_in_ins+4] ==
                            struct.pack("<I",candidate)):
                        matching.append({
                            "instructionRva":f"0x{ins_rva:X}",
                            "mnemonic":ins.mnemonic,
                            "operands":ins.op_str,
                            "instructionBytesHex":bytes(ins.bytes).hex(),
                            "originalMethodStartRva":f"0x{start:X}",
                            "exactOriginalMethodStartOwners":method_index[start],
                            "nativeArithmeticReaderProven":False
                        })
                accepted.append({
                    "immediateRva":f"0x{immediate_rva:X}",
                    "candidateImmediateHex":f"0x{candidate:08X}",
                    "maxBoundedMethodDisassemblyExceeded":False,
                    "alignedImmediateProof":bool(matching),
                    "nativeInstructions":matching
                })
    return {
        "rawFileBackedExecutableMatches":raw_candidates,
        "instructionAlignedImmediateMatches":sum(x["alignedImmediateProof"] for x in accepted),
        "allSourceMatches":accepted,
        "matchedConstantKeys":sorted({r["candidateImmediateHex"] for r in accepted}),
        "matchedAlignedKeys":sorted({r["candidateImmediateHex"] for r in accepted if r["alignedImmediateProof"]}),
        "anyRootReaderProven":False,
    }



VERIFIED_CANDIDATE_METHOD_RVA=0xAD23000
VERIFIED_CANDIDATE_IMM_RVA=0xAD23067
VERIFIED_CANDIDATE_KEY=0xC14B813C
VERIFIED_CANDIDATE_METHOD_INDEX=514423


def inspect_native_candidate_reader(exe:Path,methods:Path,rows:list[dict])->dict:
    """Disassemble exact original IL2CPP binary-reader method at the key witness.

    The single source-aligned immediate is an independent positive control.
    Native read-loop or complete loader linkage is reported independently.
    """
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    starts,index=original_methods(methods)
    orig=index.get(VERIFIED_CANDIDATE_METHOD_RVA,[])
    if len(orig)!=1 or (orig[0]["typeName"],orig[0]["methodName"],orig[0]["methodIndex"])!=(
        "NLDEPJEOJGC","GMENPOPMKAA",VERIFIED_CANDIDATE_METHOD_INDEX):
        raise ValueError("original native reader method owner changed")
    pos=bisect_right(starts,VERIFIED_CANDIDATE_METHOD_RVA)
    if pos>=len(starts):raise ValueError("original method has no successor")
    next_start=starts[pos]
    length=min(next_start-VERIFIED_CANDIDATE_METHOD_RVA,MAX_METHOD_DISASSEMBLY_BYTES)
    if length<VERIFIED_CANDIDATE_IMM_RVA-VERIFIED_CANDIDATE_METHOD_RVA+4:
        raise ValueError("original source method window shorter than native immediate")
    with PEImage(exe) as pe:
        buf=pe.read_rva(VERIFIED_CANDIDATE_METHOD_RVA,length)
        if len(buf)!=length:raise ValueError("original source method window not backed")
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        md.detail=True
        insns=[{
            "rva":f"0x{ins.address-pe.image_base:X}",
            "mnemonic":ins.mnemonic,"operands":ins.op_str,
            "bytes":bytes(ins.bytes).hex(),
            "immOffset":ins.imm_offset,"immBytes":ins.imm_size,
          } for ins in md.disasm(buf,pe.image_base+VERIFIED_CANDIDATE_METHOD_RVA)]
    at=next((i for i,x in enumerate(insns) if x["rva"]=="0xAD23066"),None)
    if at is None or not(insns[at]["mnemonic"]=="mov" and
                          insns[at]["operands"]=="ebx, 0xc14b813c" and
                          insns[at]["immOffset"]==1 and
                          insns[at]["immBytes"]==4 and
                          insns[at]["bytes"]=="bb3c814bc1"):
        raise ValueError("original native count constant aligned instruction drift")
    # Exact original instruction chain: read a U32 from the input cursor,
    # advance that cursor four bytes, XOR the word with the native constant,
    # and loop over the decoded count. This proves the *native function's*
    # count transform, not its linkage to the scene Point asset.
    required={
       "0xAD23053":("mov","ecx, dword ptr [r15 + 0x28]"),
       "0xAD23060":("movsxd","rdx, ecx"),
       "0xAD23063":("add","ecx, 4"),
       "0xAD2306B":("xor","ebx, dword ptr [rax + rdx + 0x20]"),
       "0xAD2306F":("mov","dword ptr [rbp + 0xc], ebx"),
       "0xAD23072":("mov","dword ptr [r15 + 0x28], ecx"),
       "0xAD230BB":("call","rbx"),
       "0xAD230CC":("cmp","ebx, dword ptr [rbp + 0xc]"),
    }
    observed={x["rva"]:x for x in insns}
    for rva,(mnemonic,operands) in required.items():
        x=observed.get(rva)
        if x is None or (x["mnemonic"],x["operands"])!=(mnemonic,operands):
            raise ValueError(f"original array-count read/loop instruction drift at {rva}")
    reader_evidence=[observed[x] for x in required]
    nearby=insns[max(0,at-22):at+55]
    read_arithmetic=[x for x in insns[at:at+40]
                     if x["mnemonic"] in ("xor","add","sub","cmp","test")
                        and ("ebx" in x["operands"] or "rbx" in x["operands"])]
    counts=[struct.unpack_from("<I",bytes.fromhex(r["unwrappedPayloadFirst32Hex"]),3)[0]
                ^ VERIFIED_CANDIDATE_KEY for r in rows]
    bounds=[r["payloadBytes"]//MIN_BYTES_PER_RECORD for r in rows]
    if any(x>cap for x,cap in zip(counts,bounds,strict=True)):
        raise ValueError("original 13 scene point prefixes no longer match source constant")
    return {
      "exactOriginalNativeType":"NLDEPJEOJGC",
      "methodName":"GMENPOPMKAA",
      "methodIndex":VERIFIED_CANDIDATE_METHOD_INDEX,
      "originalMethodRva":f"0x{VERIFIED_CANDIDATE_METHOD_RVA:X}",
      "methodWindowBytes":len(buf),
      "methodWindowSha256":hashlib.sha256(buf).hexdigest(),
      "nextOriginalMethodRva":f"0x{next_start:X}",
      "entireMethodProven":length==next_start-VERIFIED_CANDIDATE_METHOD_RVA,
      "decodedInstructions":len(insns),
      "sourceAlignedInstruction":insns[at],
      "sourceInstructionContext":nearby,
      "verifiedNativeArrayCountReadAndLoopInstructions":reader_evidence,
      "genericNativeU32XorCountReaderConfirmed":True,
      "nearbyReadArithmetic":read_arithmetic,
      "crossSceneCandidateCounts":counts,
      "allCountsFitSourceOriginalByteBounds":True,
      "originalScenePointLoaderReachedThisMethodProven":False,
      "originalScenePointFullBytesConsumedProven":False,
      "originalScenePointCountEncodingProven":False,
    }

def investigate(prior:Path,exe:Path,methods:Path)->dict:
    rows=validate_prior(json.loads(prior.read_text(encoding="utf-8")))
    leads=candidate_transforms(rows)
    scan=native_immediate_witnesses(exe,methods,leads)
    candidate_reader=(inspect_native_candidate_reader(exe,methods,rows)
                      if f"0x{VERIFIED_CANDIDATE_KEY:08X}" in scan["matchedAlignedKeys"] else None)
    return {
        "schemaVersion":1,
        "status":"ORIGINAL_GLOBAL_71_SCENE_POINT_CROSS_SCENE_HEADER_TRANSFORM_CANDIDATES__READER_UNVERIFIED",
        "originalExeSha256":PROFILE_71.exe_sha256,
        "originalMetadataSha256":PROFILE_71.metadata_sha256,
        "sourceOriginalScenePointReport":PRIOR_REPORT,
        "originalMethodsGitBlob":METHOD_BLOB,
        "inputSceneIds":[r["sceneId"] for r in rows],
        "transformPhysicalBound":"0 <= count <= floor(payload bytes/2)",
        "headerU32OffsetsChecked":[0,1,2,3,4,5,6,7,8],
        "candidateCount":len(leads),
        "candidates":leads,
        "nativeExecutableImmediateScan":scan,
        "sourceNativeCandidateReader":candidate_reader,
        "clientScenePointNativeReaderLocated":False,
        "scenePointCoordinatesDecoded":False,
        "originalChestPlacementProven":False,
        "serverChestPlacementOwnershipProven":False,
        "limits":[
            "These arithmetic keys are only mathematically compatible with short source-file lengths, not authenticated real array counts.",
            "An instruction-aligned immediate is not proof that the instruction parses Scene Point, absent its original source asset consumer call edge.",
            "The check tests only XOR and modular ADD over 4-byte little-endian values at offsets 0..8. Other masks, bitfields, nesting and encoding schemes remain possible.",
            "No historical Lua, community data or AstaPS reward semantics were imported.",
        ]
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--prior",type=Path,required=True)
    p.add_argument("--exe",type=Path,required=True)
    p.add_argument("--methods",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    report=investigate(a.prior,a.exe,a.methods)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("ORIGINAL_SCENE_POINT_NATIVE_HEADER_SCAN_BEGIN")
    print(json.dumps({
       "status":report["status"],
       "candidateCount":report["candidateCount"],
       "candidates":[{"offset":x["headerOffset"],"op":x["operation"],"key":x["candidateImmediateHex"]}
                     for x in report["candidates"]],
       "nativeExecutableImmediateScan":report["nativeExecutableImmediateScan"],
       "sourceNativeCandidateReader":report["sourceNativeCandidateReader"],
    },ensure_ascii=False,indent=2))
    print("ORIGINAL_SCENE_POINT_NATIVE_HEADER_SCAN_END")


if __name__=="__main__":
    main()
