#!/usr/bin/env python3
"""Identify original 7.1 native byte-producer call targets feeding parent parser.

All input method origins, instruction sites, PE bytes, and method indices
come from SHA-pinned original Global 7.1 evidence. Original declaration
identities are preserved; obfuscated code is not given guessed API semantics.
"""
from __future__ import annotations
import argparse
from bisect import bisect_right
import hashlib
import importlib.util
import json
from pathlib import Path

from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM
from genshinre.callxref import _load_method_starts
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

ROOT=Path(__file__).resolve().parents[1]
PRIOR=ROOT/"versions/7.1.0-global/analyses/progression/world/7.1-original-scene-parent-native-pre-input-callees.json"
OWNER_RVAS={"string_source":0xF06A600,"record_reader":0x1016E3F0}
OWNER_SHAS={"string_source":"30aa25a225ed483582a124a4bb9167f34bb1354b1b8c2e2fa8f4ae21961340b2",
            "record_reader":"87061bba87ceb2983cf61ae6e9903a5c9ba986def3841ddf82670a452cc2ff73"}
OWNER_NAMES={"string_source":"source_original_uint32_lookup","record_reader":"source_original_lookup_result_consumer"}
# Source original direct calls and tail jumps. Same bytes are required in prior original report.
CALLEES={
 "string_hash_parameter_builder":("string_source",0xF06A628,0x194AED40,"e81347440a","call"),
 "string_key_formatter":("string_source",0xF06A634,0x195F34B0,"e8778e580a","call"),
 "string_fast_tail":("string_source",0xF06A64C,0x194675B0,"e95fcf3f0a","jmp"),
 "string_fallback_tail":("string_source",0xF06A677,0xD8E1CB0,"e9347687fe","jmp"),
 "record_open_first":("record_reader",0x1016E417,0x1475C1D0,"e8b4dd5e04","call"),
 "record_check_cached":("record_reader",0x1016E45F,0x156A0000,"e89c1b5305","call"),
 "record_get_bytes":("record_reader",0x1016E4AC,0x6D8CF60,"e8afeac1f6","call"),
 "record_measure_bytes":("record_reader",0x1016E4BC,0x1112D90,"e8cf48faf0","call"),
}
MAX_PROBE=0x800
MAX_DECLARED_METHOD=0x20000


def git_blob(p:Path)->str:
    h=hashlib.sha1()
    h.update(f"blob {p.stat().st_size}\0".encode("ascii"))
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1048576),b""):h.update(b)
    return h.hexdigest()


def extract_prior(prior:Path)->dict:
    p=json.loads(prior.read_text(encoding="utf-8"))
    if (p["originalExeSha256"]!=PROFILE_71.exe_sha256
        or p["originalMetadataSha256"]!=PROFILE_71.metadata_sha256
        or p["originalMethodsGitBlob"]!="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"):
        raise ValueError("original 7.1 input-producing native study/source identity changed")
    owners=p["sourceNativePreParentReaderDirectCallees"]
    for name,func in OWNER_NAMES.items():
        row=owners[func]
        if row["sourceOriginalTargetRva"]!=f"0x{OWNER_RVAS[name]:X}" or row["sourceWindowSha256"]!=OWNER_SHAS[name]:
            raise ValueError("source original native producer method/window drift")
    for name,(owner,site,target,raw,mnemonic) in CALLEES.items():
        source=owners[OWNER_NAMES[owner]]
        if mnemonic=="call":
            matched=[x for x in source["sourceNativeDirectCalls"]
                     if x["rva"]==f"0x{site:X}" and x["targetRva"]==f"0x{target:X}" and x["bytes"]==raw]
        else:
            matched=[x for x in source["sourceOriginalEntryInstructions"]
                     if x["rva"]==f"0x{site:X}" and x["mnemonic"]=="jmp" and x["bytes"]==raw]
        if len(matched)!=1:raise ValueError(f"original source callee site proof drift: {name}")
    return owners


def inspect(exe:Path,methods:Path,prior:Path)->dict:
    owners=extract_prior(prior)
    if git_blob(methods)!="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a":
        raise ValueError("source original 7.1 generated methods.csv Git blob changed")
    require_sha256(exe,PROFILE_71.exe_sha256,label="exact original Global 7.1 EXE")
    starts,method_by=_load_method_starts(methods)
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    with PEImage(exe) as pe:
        for owner,addr in OWNER_RVAS.items():
            entry=owners[OWNER_NAMES[owner]]
            size=entry["sourceWindowSize"]
            src=pe.read_rva(addr,size)
            if hashlib.sha256(src).hexdigest()!=OWNER_SHAS[owner]:
                raise ValueError(f"source exact native producer bytes changed: {owner}")
        result={}
        for name,(owner,site,target,raw,mnemonic) in CALLEES.items():
            x=pe.read_rva(site,5)
            if x.hex()!=raw:raise ValueError(f"exact native original call/jump drift {name}")
            delta=int.from_bytes(x[1:5],"little",signed=True)
            if site+5+delta!=target or x[0]!=(0xE8 if mnemonic=="call" else 0xE9):
                raise ValueError(f"native source jump displacement control failed {name}")
            declared=method_by.get(target,[])
            next_ix=bisect_right(starts,target)
            next_start=starts[next_ix] if next_ix<len(starts) else None
            declared_len=next_start-target if declared and next_start else None
            if declared_len is not None and not 0<declared_len<=MAX_DECLARED_METHOD:
                raise ValueError("original method declaration source length exceeds bound")
            size=min(declared_len or MAX_PROBE,MAX_PROBE)
            data=pe.read_rva(target,size)
            if len(data)!=size:
                raise ValueError(f"source native target not file-backed: {name}")
            ins=list(md.disasm(data,pe.image_base+target))
            def row(i):
                r={"rva":f"0x{i.address-pe.image_base:X}","mnemonic":i.mnemonic,
                   "operands":i.op_str,"bytes":bytes(i.bytes).hex()}
                if i.mnemonic in ("call","jmp") and len(i.operands)==1 and i.operands[0].type==X86_OP_IMM:
                    r["targetRva"]=f"0x{i.operands[0].imm-pe.image_base:X}"
                return r
            result[name]={
                "sourceOriginalProducerMethodRva":f"0x{OWNER_RVAS[owner]:X}",
                "sourceOriginalInstructionSite":f"0x{site:X}",
                "sourceOriginalInstructionBytes":raw,
                "sourceOriginalDirectCallOrTailJump":mnemonic,
                "sourceExactTargetRva":f"0x{target:X}",
                "sourceExactMetadataMethodOwner":[{
                    "originalTypeName":r["type_name"],
                    "originalMethodName":r["method_name"],
                    "originalMethodIndex":int(r["method_index"]),
                    "originalTypeDefinitionIndex":int(r["type_definition_index"]),
                    "originalParameterTypes":r.get("parameter_types",""),
                } for r in declared],
                "sourceTargetIsOriginalDeclaredMethodStart":bool(declared),
                "sourceNativeProbeBytes":size,
                "sourceNativeProbeSha256":hashlib.sha256(data).hexdigest(),
                "sourceNativeLinearDecodedInstructions":len(ins),
                "sourceFirstInstructions":[row(i) for i in ins[:36]],
                "sourceDirectCallAndTailJumpTargets":[row(i) for i in ins
                  if i.mnemonic in ("call","jmp") and len(i.operands)==1 and i.operands[0].type==X86_OP_IMM][:48],
                "sourceIndirectCallInstructions":[row(i) for i in ins
                  if i.mnemonic=="call" and (len(i.operands)!=1 or i.operands[0].type!=X86_OP_IMM)][:20],
            }
    return {
        "schemaVersion":1,
        "status":"ORIGINAL_GLOBAL_7_1_SCENE_PARENT_DATA_INPUT_NATIVE_CALLEE_IDENTITIES_AND_CODE_WINDOWS__ASSET_NOT_BOUND",
        "originalExeSha256":PROFILE_71.exe_sha256,
        "originalMetadataSha256":PROFILE_71.metadata_sha256,
        "originalMethodsGitBlob":"a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a",
        "sourcePreviousOriginalInputMethodProof":str(prior),
        "sourceOriginalCalleePaths":result,
        "originalScenePoint13IndexedAssetsConnectedToNativeLoader":False,
        "originalWorldChestPlacementOrInstanceLevelProven":False,
        "limitations":[
            "An original method name or generic byte stream helper does not establish a Scene/Point file identity.",
            "Exact code windows are bounded and need not cover entire methods or complete CFG.",
            "Direct calls and tail jumps in the original methods are machine-code edges; transformed hash/filename runtime values are unresolved."
        ],
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for opt in ("exe","methods","prior","output"):
        p.add_argument("--"+opt,type=Path,required=True)
    a=p.parse_args()
    d=inspect(a.exe,a.methods,a.prior)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(d,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_71_PARENT_LOADER_CALLEES_BEGIN")
    print(json.dumps(d,ensure_ascii=False,indent=2))
    print("ORIGINAL_71_PARENT_LOADER_CALLEES_END")


if __name__=="__main__":main()
