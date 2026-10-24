#!/usr/bin/env python3
"""Original Global 7.1 native reverse-callers across Scene/Point-compatible readers.

Exactly original source EXE, metadata-derived original methods.csv and
previous exact native reader windows. Scan bounded direct E8 candidates and
verify instruction alignment from original method starts. This is deliberately
not a claim that these methods consume indexed Scene/Point resources.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path

from genshinre.callxref import scan_direct_call_xrefs, _load_method_starts
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

PRIOR_PARENT="versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-parent-mask-native-callchain.json"
PRIOR_FACTORY_CHAIN="versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-14-1-nldep-direct-reader-chain.json"
METHODS_BLOB="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
TARGETS={
  "parent_candidate_scene_point_reader":0xEE66B20,
  "intermediate_source_byte_reader":0x12498FE0,
  "nldep_one_arg_reader":0xAD22310,
  "nldep_two_arg_reader":0xAD23000,
  "factory_case_1_owner_reader":0x138B9390,
  "factory_case_14_owner_reader":0x8613440,
}
MAX_DIRECT_MATCHES_PER_TARGET=200
MAX_METHOD_PREFIX_BYTES=0x10000
SOURCE_PARENT_SHA="e27dc0d3a924a74963b34e8d8ff64d17ab3fe472b77dcc42b4cbe3c704a6e61a"
SOURCE_ONE_ARG_SHA="07658f6b1e8111e4629b50b6ac8d73721da69208c89d998df5abf58bb5c7a856"


def git_blob(p:Path)->str:
    h=hashlib.sha1()
    h.update(f"blob {p.stat().st_size}\0".encode("ascii"))
    with p.open("rb") as source:
        for block in iter(lambda:source.read(1<<20),b""):
            h.update(block)
    return h.hexdigest()


def validate_prior(parent:Path,chain:Path)->None:
    a=json.loads(parent.read_text(encoding="utf-8"))
    b=json.loads(chain.read_text(encoding="utf-8"))
    if (a["originalExeSha256"]!=PROFILE_71.exe_sha256
        or a["originalMethodsGitBlob"]!=METHODS_BLOB
        or a["nativeParentReader"]["nativeRva"]!="0xEE66B20"
        or a["nativeParentReader"]["nativeSourceSha256"]!=SOURCE_PARENT_SHA
        or a["nativeParentReader"]["directCallAt"]!="0xEE66BF1"
        or a["nativeParentReader"]["directCallTargetToNestedArray"]!="0xAD23000"
        or b["originalExeSha256"]!=PROFILE_71.exe_sha256
        or b["sourceOneArgWindowSha256"]!=SOURCE_ONE_ARG_SHA
        or b["sourceFactoryToNLDEPDirectCallChain"]["nativeCalleeOneArgMethodRva"]!="0xAD22310"):
        raise ValueError("exact original 7.1 parent/factory native provenance drift")


def verify_candidate(pe:PEImage,starts:list[int],owners:dict,site:int,hex_bytes:str,target:int)->dict:
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    ix=bisect_right(starts,site)-1
    if ix<0:return {"aligned":False,"reason":"NO_PRIOR_SOURCE_METHOD_START"}
    start=starts[ix]
    next_start=starts[ix+1] if ix+1<len(starts) else None
    source_length=site+5-start
    if (source_length<5 or source_length>MAX_METHOD_PREFIX_BYTES
        or (next_start is not None and site+5>next_start)):
        return {"aligned":False,"reason":"OUTSIDE_BOUNDED_ORIGINAL_METHOD_PREFIX",
                "nearestDeclaredMethodStart":f"0x{start:X}"}
    data=pe.read_rva(start,source_length)
    if len(data)!=source_length:raise ValueError("original method source bytes truncated")
    ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(data,pe.image_base+start))
    found=next((i for i,x in enumerate(ins) if x.address-pe.image_base==site
                and x.mnemonic=="call" and x.op_str.lower()==f"0x{pe.image_base+target:x}"
                and bytes(x.bytes).hex()==hex_bytes),None)
    if found is None:
        return {"aligned":False,"reason":"NOT_AN_ALIGNED_E8_CALL_FROM_DECLARED_NATIVE_METHOD",
                "nearestDeclaredMethodStart":f"0x{start:X}"}
    ctx=ins[max(0,found-6):found+3]
    return {
        "aligned":True,
        "exactOriginalCallerStartRva":f"0x{start:X}",
        "sourceOriginalCallerOwner":[{
            "typeName":x["type_name"],"methodName":x["method_name"],
            "methodIndex":int(x["method_index"]),
            "typeDefinitionIndex":int(x["type_definition_index"]),
            "parameterTypes":x.get("parameter_types","")
        } for x in owners[start]],
        "sourceNativePrefixSha256":hashlib.sha256(data).hexdigest(),
        "sourceNativePrefixBytes":len(data),
        "sourceNativeContext":[{
           "rva":f"0x{x.address-pe.image_base:X}",
           "op":f"{x.mnemonic} {x.op_str}".strip(),"bytes":bytes(x.bytes).hex()
        } for x in ctx]
    }


def inspect(exe:Path,methods:Path,parent:Path,chain:Path)->dict:
    validate_prior(parent,chain)
    if git_blob(methods)!=METHODS_BLOB:
        raise ValueError("source original 7.1 methods.csv Git blob drift")
    require_sha256(exe,PROFILE_71.exe_sha256,label="exact Global 7.1 original executable")
    starts,owners=_load_method_starts(methods)
    expected={
      0xEE66B20:("IJNOFJEOMBD",171707),
      0x12498FE0:("CCPCOHEPGHC",173227),
      0xAD22310:("NLDEPJEOJGC",514422),
      0xAD23000:("NLDEPJEOJGC",514423),
      0x138B9390:("BHJILFMHGEE",436910),
      0x8613440:("NKJPPNFAEEF",527284),
    }
    for target,(name,idx) in expected.items():
        rows=owners.get(target,[])
        if len(rows)!=1 or rows[0]["type_name"]!=name or int(rows[0]["method_index"])!=idx:
            raise ValueError(f"original native target method/index {target:X} changed")
    with PEImage(exe) as pe:
        if (hashlib.sha256(pe.read_rva(0xEE66B20,864)).hexdigest()!=SOURCE_PARENT_SHA
            or hashlib.sha256(pe.read_rva(0xAD22310,0xCF0)).hexdigest()!=SOURCE_ONE_ARG_SHA
            or pe.read_rva(0xEE66BF1,5).hex()!="e80ac4ebfb"):
            raise ValueError("original native reader source binary positive control failed")
        raw=scan_direct_call_xrefs(exe,list(TARGETS.values()),window=0)
        rows={}
        for name,target in TARGETS.items():
            hits=raw["matches"][f"0x{target:X}"]
            if len(hits)>MAX_DIRECT_MATCHES_PER_TARGET:
                raise ValueError("original source call candidate count exceeds bound")
            recorded=[]
            for row in hits:
                site=int(row["instruction_rva"],16)
                v=verify_candidate(pe,starts,owners,site,row["instruction_hex"],target)
                recorded.append({
                  "candidateCallSiteRva":row["instruction_rva"],
                  "sourceOriginalCallBytes":row["instruction_hex"],
                  "sourcePESection":row["section"],
                  **v
                })
            rows[name]={
              "originalTargetRva":f"0x{target:X}",
              "originalTargetOwner":expected[target][0],
              "originalTargetMethodIndex":expected[target][1],
              "rawE8ShapedCandidateCount":len(hits),
              "originalAlignedDeclaredMethodCallCount":sum(x["aligned"] for x in recorded),
              "originalCallerCandidates":recorded,
            }
    return {
       "schemaVersion":1,
       "status":"EXACT_ORIGINAL_7_1_POINT_READER_PARENT_AND_HELPER_REVERSE_E8_CALL_CENSUS__ASSET_LOADER_UNVERIFIED",
       "originalExeSha256":PROFILE_71.exe_sha256,
       "sourceMethodsGitBlob":METHODS_BLOB,
       "sourceParentNativeProof":PRIOR_PARENT,
       "sourceFactoryHelperNativeProof":PRIOR_FACTORY_CHAIN,
       "sourceOriginalCallCensus":rows,
       "sourceOriginalReaderToScenePointAssetLoaderProven":False,
       "sourceOriginalChestCoordinatesOrLevelProven":False,
       "limits":[
         "Raw source E8-shaped candidate bytes are not calls until they align from the original metadata-declared method start.",
         "The reader can be invoked through a virtual slot, reflection or a generated delegate; absent direct E8 calls do not prove no callers.",
         "An aligned call is a source-code edge, not authenticated Scene/Point resource bytes or scene-instance semantics.",
         "Native caller prefix decoding is bounded and a method body can contain branches not linearized by Capstone."
       ]
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ("exe","methods","parent","chain","output"):
        p.add_argument("--"+arg,type=Path,required=True)
    a=p.parse_args()
    d=inspect(a.exe,a.methods,a.parent,a.chain)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(d,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_71_READER_REVERSE_CALLS_BEGIN")
    print(json.dumps({
      "targets":{k:{"rva":v["originalTargetRva"],"raw":v["rawE8ShapedCandidateCount"],
                   "aligned":v["originalAlignedDeclaredMethodCallCount"],
                   "callers":[{"site":x["candidateCallSiteRva"],"aligned":x["aligned"],
                   "owners":x.get("sourceOriginalCallerOwner",[])}
                   for x in v["originalCallerCandidates"]]}
                for k,v in d["sourceOriginalCallCensus"].items()}
    },ensure_ascii=False,indent=2))
    print("ORIGINAL_71_READER_REVERSE_CALLS_END")


if __name__=="__main__":
    main()
