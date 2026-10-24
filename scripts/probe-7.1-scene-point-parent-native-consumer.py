#!/usr/bin/env python3
"""Investigate original Global 7.1 KLLNG native caller of parent reader.

The original 0xF04F4B5 E8 call is source-aligned and belongs to original
KLLNGCPBLMM.NPBDNMOKJPE(uint32) at 0xF04F350. Read the original method
window, native inputs near the parser call and direct native callers to
this source owner. Do not assign resource-file paths or scene/Gadget semantics.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import importlib.util
import json
from pathlib import Path

from genshinre.callxref import scan_direct_call_xrefs, _load_method_starts
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

ROOT=Path(__file__).resolve().parents[1]
CALLER_SCRIPT=ROOT/"scripts/probe-7.1-point-reader-reverse-native-callers.py"
spec=importlib.util.spec_from_file_location("original_71_reverse_callers",CALLER_SCRIPT)
caller=importlib.util.module_from_spec(spec)
spec.loader.exec_module(caller)

PRIOR="versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-parent-reader-reverse-native-callers.json"
ORIGINAL_METHOD_RVA=0xF04F350
ORIGINAL_CALL_SITE=0xF04F4B5
ORIGINAL_PARENT_RVA=0xEE66B20
ORIGINAL_METHOD_INDEX=616020
ORIGINAL_DECLARING_TYPE="KLLNGCPBLMM"
SOURCE_CALL_PREFIX_SHA="c102f503ce85d16eb753fe4c54b8ac52c1c142265a61b9c61a8894c8a3090c9c"
MAX_METHOD_WINDOW=0x10000
MAX_CALLER_CANDIDATES=200


def verify_prior(path:Path):
    j=json.loads(path.read_text(encoding="utf-8"))
    parent=j["sourceOriginalCallCensus"]["parent_candidate_scene_point_reader"]
    matches=[x for x in parent["originalCallerCandidates"]
             if x["candidateCallSiteRva"]==f"0x{ORIGINAL_CALL_SITE:X}"]
    if (j["originalExeSha256"]!=PROFILE_71.exe_sha256
        or j["sourceMethodsGitBlob"]!=caller.METHODS_BLOB
        or parent["originalAlignedDeclaredMethodCallCount"]!=2
        or len(matches)!=1 or not matches[0]["aligned"]
        or matches[0]["exactOriginalCallerStartRva"]!=f"0x{ORIGINAL_METHOD_RVA:X}"
        or matches[0]["sourceNativePrefixSha256"]!=SOURCE_CALL_PREFIX_SHA
        or matches[0]["sourceOriginalCallerOwner"] != [{
         "typeName":ORIGINAL_DECLARING_TYPE,
         "methodName":"NPBDNMOKJPE",
         "methodIndex":ORIGINAL_METHOD_INDEX,
         "typeDefinitionIndex":74397,
         "parameterTypes":'["uint32"]'}]):
        raise ValueError("original source parent external native caller witness drift")


def inspect(exe:Path,methods:Path,prior:Path)->dict:
    verify_prior(prior)
    if caller.git_blob(methods)!=caller.METHODS_BLOB:
        raise ValueError("exact original methods.csv Git blob mismatch")
    require_sha256(exe,PROFILE_71.exe_sha256,label="exact Global 7.1 original exe")
    starts,owners=_load_method_starts(methods)
    orig=owners.get(ORIGINAL_METHOD_RVA,[])
    if (len(orig)!=1 or orig[0]["type_name"]!=ORIGINAL_DECLARING_TYPE
        or int(orig[0]["method_index"])!=ORIGINAL_METHOD_INDEX
        or orig[0]["method_name"]!="NPBDNMOKJPE"
        or orig[0]["parameter_types"]!='["uint32"]'):
        raise ValueError("source native original external parser caller owner changed")
    idx=bisect_right(starts,ORIGINAL_METHOD_RVA)
    if idx>=len(starts):
        raise ValueError("next original source method boundary not found")
    end=starts[idx]
    size=end-ORIGINAL_METHOD_RVA
    if not 0<size<=MAX_METHOD_WINDOW:
        raise ValueError("original external parser caller native window exceeds maximum")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86 import X86_OP_IMM
    with PEImage(exe) as pe:
        data=pe.read_rva(ORIGINAL_METHOD_RVA,size)
        if len(data)!=size or hashlib.sha256(data[:ORIGINAL_CALL_SITE+5-ORIGINAL_METHOD_RVA]).hexdigest()!=SOURCE_CALL_PREFIX_SHA:
            raise ValueError("original source parser caller native positive control mismatch")
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        md.detail=True
        ins=list(md.disasm(data,pe.image_base+ORIGINAL_METHOD_RVA))
        def row(x):
            v={"rva":f"0x{x.address-pe.image_base:X}","mnemonic":x.mnemonic,
                "operands":x.op_str,"bytes":bytes(x.bytes).hex()}
            if x.mnemonic=="call" and len(x.operands)==1 and x.operands[0].type==X86_OP_IMM:
                v["targetRva"]=f"0x{x.operands[0].imm-pe.image_base:X}"
            return v
        at=next((ix for ix,x in enumerate(ins) if x.address-pe.image_base==ORIGINAL_CALL_SITE
                 and x.mnemonic=="call"
                 and x.op_str.lower()==f"0x{pe.image_base+ORIGINAL_PARENT_RVA:x}"
                 and bytes(x.bytes).hex()=="e86676e1ff"),None)
        if at is None:raise ValueError("source original parent native call vanished")
        direct=[row(x) for x in ins if x.mnemonic=="call" and len(x.operands)==1 and x.operands[0].type==X86_OP_IMM]
        indirect=[row(x) for x in ins if x.mnemonic=="call" and (not x.operands or x.operands[0].type!=X86_OP_IMM)]
        hits=scan_direct_call_xrefs(exe,[ORIGINAL_METHOD_RVA],window=0)["matches"][f"0x{ORIGINAL_METHOD_RVA:X}"]
        if len(hits)>MAX_CALLER_CANDIDATES:
            raise ValueError("too many direct callers of original source external parent parser")
        aligned=[{
           "sourceCallRva":x["instruction_rva"],
           "sourceOriginalInstructionBytes":x["instruction_hex"],
           "sourcePESection":x["section"],
           **caller.verify_candidate(pe,starts,owners,int(x["instruction_rva"],16),
                                     x["instruction_hex"],ORIGINAL_METHOD_RVA)
        } for x in hits]
    return {
       "schemaVersion":1,
       "status":"EXACT_ORIGINAL_7_1_EXTERNAL_PARENT_READER_CONSUMER_NATIVE_INPUT_AND_CALLERS__SCENE_POINT_LOADER_UNVERIFIED",
       "originalExeSha256":PROFILE_71.exe_sha256,
       "originalMethodsGitBlob":caller.METHODS_BLOB,
       "sourcePriorReverseReaderCallGraph":PRIOR,
       "originalNativeMethodOwner":ORIGINAL_DECLARING_TYPE,
       "originalNativeMethodName":"NPBDNMOKJPE",
       "originalNativeMethodIndex":ORIGINAL_METHOD_INDEX,
       "originalNativeMethodParameterTypes":'["uint32"]',
       "originalNativeMethodStartRva":f"0x{ORIGINAL_METHOD_RVA:X}",
       "sourceNextOriginalMethodStartRva":f"0x{end:X}",
       "sourceOriginalMethodWindowBytes":size,
       "sourceOriginalMethodWindowSha256":hashlib.sha256(data).hexdigest(),
       "sourceOriginalPreParentCallSha256":SOURCE_CALL_PREFIX_SHA,
       "sourceOriginalLinearNativeInstructions":len(ins),
       "sourceOriginalMethodFirstNativeInstructions":[row(x) for x in ins[:90]],
       "sourceOriginalParentCallContext":[row(x) for x in ins[max(0,at-36):at+20]],
       "sourceOriginalNativeDirectCalls":direct[:160],
       "sourceOriginalNativeIndirectCalls":indirect[:60],
       "sourceOriginalNativeReturnCandidates":[row(x) for x in ins if x.mnemonic=="ret"][:25],
       "sourceOriginalE8CallersToConsumer":{
          "rawCandidateCount":len(hits),
          "alignedOriginalNativeCallCount":sum(x["aligned"] for x in aligned),
          "candidates":aligned
       },
       "originalScenePointPathLoaderOrFactoryVtableBindingProven":False,
       "originalChestPlacementOrLevelProven":False,
       "limits":[
          "A source-original uint32 argument and a buffer passed to the native parent parser do not identify the resource file name.",
          "Direct caller entries require instruction alignment; indirect calls or runtime method invocations are not included.",
          "Native linear disassembly of a method-size window is not a complete runtime execution trace.",
          "No Gadget/chest object semantics, original scene instance coordinates or level are implied."
       ]
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ("exe","methods","prior","output"):
        p.add_argument("--"+k,type=Path,required=True)
    a=p.parse_args()
    data=inspect(a.exe,a.methods,a.prior)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_71_POINT_PARENT_CONSUMER_BEGIN")
    print(json.dumps(data,indent=2,ensure_ascii=False))
    print("ORIGINAL_71_POINT_PARENT_CONSUMER_END")


if __name__=="__main__":main()
