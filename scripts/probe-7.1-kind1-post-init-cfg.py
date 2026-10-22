#!/usr/bin/env python3
"""Reachable original Global 7.1 native IL2CPP post-type-resolution CFG.

The original 7.1 metadata usage kind-1 cache calls the type-resolver
0x50D9C0 and the post-resolution helper 0x512DB0. The previous report
only captured a 0x380-byte prefix of the latter without a return.
Walk original native *reachable* x64 instruction boundaries, retaining
all direct branches, calls and return sites. No original factory-case
class identity or Scene Point path is inferred.
"""
from __future__ import annotations

import argparse
from collections import Counter,deque
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

ROOT=0x512DB0
MAX_WINDOW=0x6000
PRIOR="versions/7.1.0-global/analyses/progression/world/7.1-original-metadata-kind1-type-resolver-30-case-native.json"
ORIGINAL_PREFIX_SHA="ed5bd32a72c08bfd40f2627bbfe49d22a9104bd77941ec4980107f514cd43cc1"
PREFIX_BYTES=0x380
MAX_INSTRUCTIONS=14000


def inspect_control_flow(data:bytes,image_base:int,*,start_rva:int=ROOT)->dict:
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    if len(data)<PREFIX_BYTES:
        raise ValueError("source original native method window truncated")
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    pending=deque([start_rva])
    visited={}
    return_sites=[]
    branch_edges=[]
    direct_calls=[]
    indirect_calls=[]
    terminal_jumps=[]
    unresolved=[]
    while pending:
        pc=pending.popleft()
        if pc in visited:continue
        offset=pc-start_rva
        if offset<0 or offset>=len(data):
            unresolved.append({"rva":f"0x{pc:X}","reason":"outside_bounded_source_window"})
            continue
        raw=data[offset:offset+15]
        decoded=list(md.disasm(raw,image_base+pc,count=1))
        if not decoded:
            unresolved.append({"rva":f"0x{pc:X}","reason":"undecodable_original_source_bytes"})
            continue
        ins=decoded[0]
        row={
            "rva":f"0x{pc:X}",
            "mnemonic":ins.mnemonic,
            "operands":ins.op_str,
            "bytes":bytes(ins.bytes).hex()
        }
        visited[pc]=row
        if len(visited)>MAX_INSTRUCTIONS:
            raise ValueError("source native control-flow instruction bound exceeded")
        next_rva=pc+ins.size
        m=ins.mnemonic
        if m in ("ret","retf","retfq"):
            return_sites.append(row)
            continue
        if m in ("ud2","int3","hlt"):
            terminal_jumps.append({**row,"reason":"terminal_fault"})
            continue
        if m=="call":
            if ins.op_str.startswith("0x"):
                target=int(ins.op_str,16)-image_base
                direct_calls.append({**row,"targetRva":f"0x{target:X}"})
            else:
                indirect_calls.append(row)
            pending.append(next_rva)
            continue
        if m=="jmp":
            if ins.op_str.startswith("0x"):
                target=int(ins.op_str,16)-image_base
                branch_edges.append({"fromRva":f"0x{pc:X}","toRva":f"0x{target:X}",
                                     "kind":"direct_unconditional"})
                if start_rva<=target<start_rva+len(data):
                    pending.append(target)
                else:
                    terminal_jumps.append({**row,"reason":"direct_tail_jump_outside_bounded_window",
                                           "targetRva":f"0x{target:X}"})
            else:
                unresolved.append({**row,"reason":"indirect_jump_target_unresolved"})
            continue
        if m.startswith("j") or m in ("loop","loope","loopne"):
            if ins.op_str.startswith("0x"):
                target=int(ins.op_str,16)-image_base
                branch_edges.append({"fromRva":f"0x{pc:X}","toRva":f"0x{target:X}",
                                     "kind":"conditional_taken"})
                if start_rva<=target<start_rva+len(data):
                    pending.append(target)
                else:
                    unresolved.append({**row,"reason":"conditional_branch_target_outside_window",
                                       "targetRva":f"0x{target:X}"})
            else:
                unresolved.append({**row,"reason":"unresolved_conditional_branch"})
            pending.append(next_rva)
            continue
        pending.append(next_rva)

    ordered=[visited[k] for k in sorted(visited)]
    return {
        "sourceNativeEntryRva":f"0x{start_rva:X}",
        "inspectedSourceWindowBytes":len(data),
        "sourceWindowSha256":hashlib.sha256(data).hexdigest(),
        "reachableDecodedOriginalInstructions":len(ordered),
        "originalDecodedReturnSites":return_sites,
        "returnCount":len(return_sites),
        "directCallCount":len(direct_calls),
        "directCalls":direct_calls,
        "indirectCallCount":len(indirect_calls),
        "indirectCalls":indirect_calls,
        "sourceBranchEdgeCount":len(branch_edges),
        "sourceBranchEdges":branch_edges,
        "terminalJumps":terminal_jumps,
        "unresolvedNativeBranchOrDecodeCount":len(unresolved),
        "unresolvedNativeBranchOrDecode":unresolved,
        "maxReachedRva":f"0x{max(visited):X}",
        "firstReachableInstructions":ordered[:60],
        "originalReachedNativeInstructions":ordered,
        "verifiedCompleteWithinWindow":bool(return_sites) and not unresolved,
    }


def investigate(exe:Path,prior:Path)->dict:
    j=json.loads(prior.read_text(encoding="utf-8"))
    source=j["originalPostResolutionClassInit"]
    caller=j["sourceNativeHelper"]
    if (j["originalGlobal71ExeSha256"]!=PROFILE_71.exe_sha256
        or j["originalMetadataSha256"]!=PROFILE_71.metadata_sha256
        or int(source["entryRva"],16)!=ROOT
        or source["sourceBoundedWindowBytes"]!=PREFIX_BYTES
        or source["sourceWindowSha256"]!=ORIGINAL_PREFIX_SHA
        or int(caller["originalRuntimePostResolutionInitRva"],16)!=ROOT):
        raise ValueError("original 7.1 post-type-resolution native provenance drift")
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 Windows client")
    with PEImage(exe) as pe:
        raw=pe.read_rva(ROOT,MAX_WINDOW)
        if len(raw)!=MAX_WINDOW or hashlib.sha256(raw[:PREFIX_BYTES]).hexdigest()!=ORIGINAL_PREFIX_SHA:
            raise ValueError("original source native class-init prefix SHA-256 mismatch")
        flow=inspect_control_flow(raw,pe.image_base)
    flow.pop("originalReachedNativeInstructions")
    flow["sourceExactOriginalPrefixSha256"]=ORIGINAL_PREFIX_SHA
    flow["sourceOriginalFileSHA256"]=PROFILE_71.exe_sha256
    flow["verificationNote"]="Reachable basic-block traversal includes fallthrough and direct branches, omits direct-call target bodies."
    return {
      "schemaVersion":1,
      "status":"EXACT_ORIGINAL_7_1_POST_TYPE_RESOLUTION_CLASS_INIT_CFG__FACTORY_TYPE_UNRESOLVED",
      "originalGlobal71ExeSha256":PROFILE_71.exe_sha256,
      "originalMetadataSha256":PROFILE_71.metadata_sha256,
      "sourcePriorKind1TypeResolverReport":PRIOR,
      "sourceNativePostResolutionHelperRva":f"0x{ROOT:X}",
      "sourceOriginalNativePostInitFlow":flow,
      "originalFactoryNumericCase1ClassTypeIdentified":False,
      "originalFactoryNumericCase14ClassTypeIdentified":False,
      "originalScenePointAssetLoaderVerified":False,
      "originalScenePointPositionsDecoded":False,
      "originalChestGadgetLocationsOrLevelProven":False,
      "limits":[
         "A file-backed executable native CFG can show returns and unresolved indirect branches; it is not original runtime behavior.",
         "The method's role in IL2CPP runtime post-resolution follows the exact previously source-verified call site; the source has no original gameplay semantic naming.",
         "A verified runtime class initializer does not bind factory numeric cases 1/14 to an Il2CppType or original scene resource payload.",
         "The consumer/protocol chain and original chest instance position authority remain unverified.",
      ]
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ("exe","prior","output"):p.add_argument("--"+arg,type=Path,required=True)
    a=p.parse_args()
    result=investigate(a.exe,a.prior)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    f=result["sourceOriginalNativePostInitFlow"]
    print("ORIGINAL_POST_INIT_CFG_BEGIN")
    print(json.dumps({
        "status":result["status"],
        "instructionCount":f["reachableDecodedOriginalInstructions"],
        "returnSites":f["originalDecodedReturnSites"],
        "directCalls":f["directCalls"],
        "indirectCalls":f["indirectCalls"],
        "unresolved":f["unresolvedNativeBranchOrDecode"],
        "terminalJumps":f["terminalJumps"],
        "firstInstructions":f["firstReachableInstructions"],
        "nativeWindowSha256":f["sourceWindowSha256"]
    },ensure_ascii=False,indent=2))
    print("ORIGINAL_POST_INIT_CFG_END")


if __name__=="__main__":
    main()
