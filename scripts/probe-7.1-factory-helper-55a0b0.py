#!/usr/bin/env python3
"""Inspect original Global 7.1 native helper 0x55A0B0 called by 0x529A10.

Exact original SHA-256 verified client and previously source-verified call
sites only. Linear native code and register observations are not an
authenticated semantic name, object-allocation contract or Scene/Point schema.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

PRIOR="versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-helper-529a10-native.json"
RVA=0x55A0B0
WINDOW=0x800
FUNCTION_PADDING_RVA=0x55A1E8
SOURCE_FALLBACK_CALLEE_RVA=0x55A1F0
SOURCE_ORIGINAL_RET_RVA=0x55A19E
OLD_SOURCE_SHA="efaaef4a2f37f1aa56278c1f8981aa4b05b788ae0cbf42956e5f678a17080868"


def verify_prior(path:Path)->dict:
    p=json.loads(path.read_text(encoding="utf-8"))
    if (p["originalExecutableSha256"]!=PROFILE_71.exe_sha256 or
        p["originalMetadataSha256"]!=PROFILE_71.metadata_sha256 or
        p["originalSourceNativeWindowSha256"]!=OLD_SOURCE_SHA or
        p["sharedNativeHelperRva"]!="0x529A10" or
        p["originalReturnInstructionRvas"]!=["0x529B5A"] or
        not p["originalDataFlowVia55A0B0ReturnRdiToRaxVerified"]):
        raise ValueError("original 7.1 factory helper prior evidence drift")
    calls=[x for x in p["sourceCallSites"] if x["sourceDirectTargetRva"]==f"0x{RVA:X}"]
    if [x["rva"] for x in calls]!=["0x529ABC","0x529B28"]:
        raise ValueError("original native helper call sites changed")
    return p


def inspect(exe:Path,prior:Path)->dict:
    verify_prior(prior)
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 native executable")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86 import X86_OP_IMM
    with PEImage(exe) as pe:
        data=pe.read_rva(RVA,WINDOW)
        if len(data)!=WINDOW:
            raise ValueError("native 0x55A0B0 source window not file backed")
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        md.detail=True
        instructions=list(md.disasm(data,pe.image_base+RVA))
        if not instructions or instructions[0].address-pe.image_base!=RVA:
            raise ValueError("original native 0x55A0B0 entry undecodable")
        all_by_rva={x.address-pe.image_base:x for x in instructions}
        if (FUNCTION_PADDING_RVA not in all_by_rva or
            all_by_rva[FUNCTION_PADDING_RVA].mnemonic!="int3" or
            SOURCE_FALLBACK_CALLEE_RVA not in all_by_rva or
            all_by_rva[SOURCE_FALLBACK_CALLEE_RVA].mnemonic!="push"):
            raise ValueError("original 0x55A0B0 source function boundary drift")
        instructions=[x for x in instructions if x.address-pe.image_base<FUNCTION_PADDING_RVA]
        by_rva={x.address-pe.image_base:x for x in instructions}
        if [x.address-pe.image_base for x in instructions if x.mnemonic=="ret"]!=[SOURCE_ORIGINAL_RET_RVA]:
            raise ValueError("original 0x55A0B0 return boundary drift")
        original_witnesses={
            0x55A0B5:("mov","r9, rdx"),
            0x55A0B8:("mov","r10, rcx"),
            0x55A0BB:("cmp","rdx, 0x8000"),
            0x55A114:("mov","rcx, qword ptr [r10 + rcx + 0x28]"),
            0x55A119:("mov","rsi, qword ptr [rcx + 0x20]"),
            0x55A11D:("test","rsi, rsi"),
            0x55A120:("je",f"0x{pe.image_base+0x55A1C7:x}"),
            0x55A126:("lock inc","word ptr [rcx + 0x10]"),
            0x55A12B:("mov","rax, qword ptr [rsi]"),
            0x55A12E:("mov","qword ptr [rcx + 0x20], rax"),
            0x55A139:("mov","qword ptr [rsi], rax"),
            0x55A196:("mov","rax, rsi"),
            0x55A19E:("ret",""),
            0x55A1B9:("mov","rcx, r10"),
            0x55A1BC:("mov","rdx, r8"),
            0x55A1D5:("jmp",f"0x{pe.image_base+SOURCE_FALLBACK_CALLEE_RVA:x}"),
        }
        for addr,(mnemonic,operands) in original_witnesses.items():
            x=by_rva.get(addr)
            if x is None or (x.mnemonic,x.op_str)!=(mnemonic,operands):
                raise ValueError(f"exact original 55A0B0 register-chain witness drift at 0x{addr:X}")
        def row(x):
            return {"rva":f"0x{x.address-pe.image_base:X}",
                    "mnemonic":x.mnemonic,"operands":x.op_str,
                    "bytes":bytes(x.bytes).hex()}
        ins=[row(x) for x in instructions]
        transfers=[]
        for x in instructions:
            if x.mnemonic!="call" and not x.mnemonic.startswith("j"):
                continue
            r=row(x)
            if len(x.operands)==1 and x.operands[0].type==X86_OP_IMM:
                r["nativeDirectTargetRva"]=f"0x{x.operands[0].imm-pe.image_base:X}"
            else:
                r["nativeDirectTargetRva"]=None
            transfers.append(r)
        jump_target=None
        first=instructions[0]
        if first.mnemonic=="jmp" and len(first.operands)==1 and first.operands[0].type==X86_OP_IMM:
            jump_target=first.operands[0].imm-pe.image_base
        redirect=None
        if jump_target is not None:
            original=pe.read_rva(jump_target,0x100)
            if len(original)!=0x100:
                raise ValueError("redirected original target is not file backed")
            redirect={
                "sourceNativeJumpRva":f"0x{jump_target:X}",
                "sourceOriginalSha256":hashlib.sha256(original).hexdigest(),
                "sourceFirstInstructions":[row(x) for x in
                    list(md.disasm(original,pe.image_base+jump_target))[:50]]
            }
    return {
        "schemaVersion":1,
        "status":"ORIGINAL_GLOBAL_7_1_SHARED_FACTORY_55A0B0_SOURCE_NATIVE__ALLOCATOR_UNVERIFIED",
        "sourceOriginalExecutableSha256":PROFILE_71.exe_sha256,
        "sourceOriginalMetadataSha256":PROFILE_71.metadata_sha256,
        "priorOriginalNativeEvidence":PRIOR,
        "originalHelperRva":f"0x{RVA:X}",
        "originalSampleWindowBytes":WINDOW,
        "sourceOriginalSampleSha256":hashlib.sha256(data).hexdigest(),
        "sourceNativeDecodedLinearInstructions":len(instructions),
        "originalFunctionPaddingBoundaryRva":f"0x{FUNCTION_PADDING_RVA:X}",
        "originalFallbackNativeEntryRva":f"0x{SOURCE_FALLBACK_CALLEE_RVA:X}",
        "originalNativeReturnRva":f"0x{SOURCE_ORIGINAL_RET_RVA:X}",
        "sourceVerifiedListHeadPopAndReturnedPointerFlow":True,
        "sourceOriginalListPointerChain":[row(by_rva[addr]) for addr in original_witnesses],
        "sourceNativeFirstInstructions":ins[:155],
        "sourceNativeTransfers":transfers[:100],
        "sourceNativeReturnCandidates":[r for r in ins if r["mnemonic"]=="ret"][:30],
        "sourceOriginalFirstInstructionJumpThunk":jump_target is not None,
        "sourceJumpRedirectIfPresent":redirect,
        "sourceRuntimeAllocationSemanticsProven":False,
        "originalConcreteFactoryCaseClassSlotTypeDefinitionProven":False,
        "sourceVirtualReaderPlusF8OwnerProven":False,
        "originalScenePointLoaderAndChestPositionOrLevelProven":False,
        "limitations":[
            "Source EXE and metadata identity and two native callers are required.",
            "Linear disassembly may include adjacent functions and is not a reachable CFG or runtime trace.",
            "Native helper behavior must be attributed only after proving its original branch and argument/return semantics.",
            "No old private-server data or community SDK names are accepted.",
        ],
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("exe","prior","output"):
        parser.add_argument("--"+name,required=True,type=Path)
    a=parser.parse_args()
    out=inspect(a.exe,a.prior)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_HELPER_55A0B0_BEGIN")
    print(json.dumps(out,indent=2,ensure_ascii=False))
    print("ORIGINAL_HELPER_55A0B0_END")


if __name__=="__main__":
    main()
