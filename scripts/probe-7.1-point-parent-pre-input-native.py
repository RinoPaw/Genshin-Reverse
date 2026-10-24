#!/usr/bin/env python3
"""Source original Global 7.1 producer calls before 0xEE66B20 reader.

Inspect exact native targets called before KLLNGCPBLMM.NPBDNMOKJPE's
original parent-reader invocation: 0xF06A600 and 0x1016E3F0.
Distinguish original metadata exact method owners from protected/native
helpers. No named Unity API, file path, resource origin, scene ID, or chest
instance schema is inferred from opcodes or call order.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import importlib.util
import json
from pathlib import Path

from genshinre.callxref import _load_method_starts
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

ROOT=Path(__file__).resolve().parents[1]
PREVIOUS="versions/7.1.0-global/analyses/progression/world/7.1-original-point-parent-reader-kllng-consumer-native.json"
CALLER_SCRIPT=ROOT/"scripts/probe-7.1-point-reader-reverse-native-callers.py"
spec=importlib.util.spec_from_file_location("original_native_parent_reverse",CALLER_SCRIPT)
caller=importlib.util.module_from_spec(spec)
spec.loader.exec_module(caller)

SOURCE_OWNER_RVA=0xF04F350
SOURCE_OWNER_SHA="b8e3420373fd37e3a6e563c803413206093955b27311407199682e0234219b71"
SOURCE_OWNER_BYTES=608
CALLERS={
 "source_original_uint32_lookup": {
  "target":0xF06A600,
  "nativeSites":{"0xF04F3C7":"e834b20100","0xF04F40A":"e8f1b10100"},
 },
 "source_original_lookup_result_consumer":{
  "target":0x1016E3F0,
  "nativeSites":{"0xF04F3D4":"e817f01101","0xF04F417":"e8d4ef1101"},
 },
 "source_original_cache_search":{
  "target":0x172F5790,
  "nativeSites":{"0xF04F392":"e8f9632a08"},
 },
}
PREFIX=0x400
MAX_ORIGINAL_METHOD=0x10000


def verify_prior(path:Path)->dict:
    d=json.loads(path.read_text(encoding="utf-8"))
    if (d["originalExeSha256"]!=PROFILE_71.exe_sha256
        or d["originalMethodsGitBlob"]!=caller.METHODS_BLOB
        or d["originalNativeMethodStartRva"]!=f"0x{SOURCE_OWNER_RVA:X}"
        or d["sourceOriginalMethodWindowBytes"]!=SOURCE_OWNER_BYTES
        or d["sourceOriginalMethodWindowSha256"]!=SOURCE_OWNER_SHA
        or d["originalScenePointPathLoaderOrFactoryVtableBindingProven"]
        or d["originalChestPlacementOrLevelProven"]):
        raise ValueError("original source external parent reader consumer provenance drift")
    direct={x["rva"]:x for x in d["sourceOriginalNativeDirectCalls"]}
    for name,v in CALLERS.items():
        for site,bytes_ in v["nativeSites"].items():
            x=direct.get(site)
            if x is None or x.get("targetRva")!=f"0x{v['target']:X}" or x["bytes"]!=bytes_:
                raise ValueError("source original pre-parent-call direct callee identities drift")
    return d


def inspect(exe:Path,methods:Path,previous:Path)->dict:
    verify_prior(previous)
    if caller.git_blob(methods)!=caller.METHODS_BLOB:
        raise ValueError("original generated 7.1 methods.csv Git blob mismatch")
    require_sha256(exe,PROFILE_71.exe_sha256,label="exact original 7.1 global EXE")
    starts,by= _load_method_starts(methods)
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86 import X86_OP_IMM
    with PEImage(exe) as pe:
        owner=pe.read_rva(SOURCE_OWNER_RVA,SOURCE_OWNER_BYTES)
        if len(owner)!=SOURCE_OWNER_BYTES or hashlib.sha256(owner).hexdigest()!=SOURCE_OWNER_SHA:
            raise ValueError("original native caller exact method bytes drift")
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        md.detail=True
        original={x.address-pe.image_base:x for x in md.disasm(owner,pe.image_base+SOURCE_OWNER_RVA)}
        sites={}
        for name,v in CALLERS.items():
            calls=[]
            for s,raw in v["nativeSites"].items():
                site=int(s,16)
                ins=original.get(site)
                if (ins is None or ins.mnemonic!="call"
                    or ins.op_str!=f"0x{pe.image_base+v['target']:x}"
                    or bytes(ins.bytes).hex()!=raw):
                    raise ValueError(f"original pre-parent reader call source drift at {s}")
                calls.append({"rva":s,"targetRva":f"0x{v['target']:X}",
                              "exactOriginalBytes":raw})
            target=v["target"]
            rows=by.get(target,[])
            next_idx=bisect_right(starts,target)
            next_start=starts[next_idx] if next_idx<len(starts) else None
            method_span=(next_start-target if rows and next_start else None)
            if method_span is not None and not 0<method_span<=MAX_ORIGINAL_METHOD:
                raise ValueError("source-original native callee method-size sanity gate failed")
            probe_bytes=min(PREFIX,method_span) if method_span is not None else PREFIX
            source=pe.read_rva(target,probe_bytes)
            if len(source)!=probe_bytes:
                raise ValueError("source original call-target machine bytes are not file-backed")
            decoded=list(md.disasm(source,pe.image_base+target))
            def row(x):
                v={"rva":f"0x{x.address-pe.image_base:X}","mnemonic":x.mnemonic,
                   "operands":x.op_str,"bytes":bytes(x.bytes).hex()}
                if x.mnemonic=="call" and len(x.operands)==1 and x.operands[0].type==X86_OP_IMM:
                    v["targetRva"]=f"0x{x.operands[0].imm-pe.image_base:X}"
                return v
            sites[name]={
               "sourceOriginalDirectCallSites":calls,
               "sourceOriginalTargetRva":f"0x{target:X}",
               "sourceOriginalExactMethodStartOwners":[{
                "typeName":x["type_name"],"methodName":x["method_name"],
                "methodIndex":int(x["method_index"]),
                "typeDefinitionIndex":int(x["type_definition_index"]),
                "parameterTypes":x.get("parameter_types",""),
                "returnType":x.get("return_type","")
               } for x in rows],
               "sourceTargetIsExactOriginalMethodStart":bool(rows),
               "sourceNativeFollowingDeclaredMethodRva":None if next_start is None else f"0x{next_start:X}",
               "sourceWindowSize":probe_bytes,
               "sourceWindowSha256":hashlib.sha256(source).hexdigest(),
               "sourceLinearInstructions":len(decoded),
               "sourceOriginalEntryInstructions":[row(x) for x in decoded[:80]],
               "sourceNativeDirectCalls":[row(x) for x in decoded if x.mnemonic=="call" and
                    len(x.operands)==1 and x.operands[0].type==X86_OP_IMM][:50],
               "sourceNativeIndirectCalls":[row(x) for x in decoded if x.mnemonic=="call" and
                    (not x.operands or x.operands[0].type!=X86_OP_IMM)][:20],
               "sourceNativeRetCandidates":[row(x) for x in decoded if x.mnemonic=="ret"][:25],
            }
    return {
     "schemaVersion":1,
     "status":"EXACT_ORIGINAL_GLOBAL_7_1_PRE_PARENT_READER_INPUT_CALL_TARGET_NATIVE_PREFIXES__RESOURCE_LOADER_UNPROVEN",
     "originalExeSha256":PROFILE_71.exe_sha256,
     "originalMetadataSha256":PROFILE_71.metadata_sha256,
     "originalMethodsGitBlob":caller.METHODS_BLOB,
     "sourcePriorNativeConsumer":PREVIOUS,
     "sourceOriginalConsumerNativeRva":f"0x{SOURCE_OWNER_RVA:X}",
     "sourceOriginalConsumerNativeSha256":SOURCE_OWNER_SHA,
     "sourceNativePreParentReaderDirectCallees":sites,
     "sourceOriginalScenePointResourceLoaderIdentified":False,
     "sourceOriginalFileToParserByteProvenanceVerified":False,
     "sourceOriginalChestPositionsOrInstanceLevelVerified":False,
     "limits":[
       "Exact x64 native calls and named metadata owners do not authenticate Unity runtime API semantics.",
       "A bounded 0x400-byte native callee prefix is not its complete CFG.",
       "A method RVA without an exact generated metadata owner may belong to a helper not captured by methods.csv.",
       "The parent reader's data source and mapped official 7.1 Scene/Point resource path remain unproven."
     ]
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for a in ("exe","methods","previous","output"):p.add_argument("--"+a,type=Path,required=True)
    a=p.parse_args()
    d=inspect(a.exe,a.methods,a.previous)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(d,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("ORIGINAL_71_PRE_PARENT_INPUT_BEGIN")
    print(json.dumps(d,ensure_ascii=False,indent=2))
    print("ORIGINAL_71_PRE_PARENT_INPUT_END")


if __name__=="__main__":main()
