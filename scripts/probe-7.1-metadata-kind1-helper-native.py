#!/usr/bin/env python3
"""Inspect original Global 7.1 internal metadata kind-1 native resolver RVA 0x524E80.

Exact SHA-256 client EXE source gate and original call-site proof; inspect a
bounded native region ending at a later *known native helper* 0x525D40.
The bound is NOT asserted as this helper's exact size. Decode native RET,
calls, branches, data reads/writes and nearby candidate functions without
inventing runtime class identity, TypeDefinitionIndex or Scene Point assets.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

PRIOR="versions/7.1.0-global/analyses/progression/world/7.1-original-metadata-usage-native-kind-array-writes.json"
HELPER_RVA=0x524E80
BOUND_RVA=0x525D40
INIT_CALL_RVA=0x523647
WINDOW=BOUND_RVA-HELPER_RVA
ORIGINAL_INIT_WINDOW_SHA="d0157c1fab8626c3b28e880e600913841b57d898bef7c5033a7ecff74f30813e"


def validate_prior(path:Path)->dict:
    j=json.loads(path.read_text(encoding="utf-8"))
    rel=j["authenticatedSourceNativeRelationships"]
    if (j["originalExecutableSha256"]!=PROFILE_71.exe_sha256 or
        j["nativeInitializer"]["sourceNativeWindowSha256"]!=ORIGINAL_INIT_WINDOW_SHA or
        int(rel["sourceNativeKind1CreationTargetRva"],16)!=HELPER_RVA or
        int(rel["sourceNativeKind1CreationCallRva"],16)!=INIT_CALL_RVA or
        rel["sourceNativeKind1RuntimeArrayMemberOffset"]!="0x30"):
        raise ValueError("original 7.1 kind1 helper prior source drift")
    return j


def inspect(exe:Path,prior:Path)->dict:
    validate_prior(prior)
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 executable")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86 import X86_OP_MEM,X86_REG_RIP
    with PEImage(exe) as pe:
        callsite=pe.read_rva(INIT_CALL_RVA,5)
        if len(callsite)!=5 or callsite[0]!=0xE8 or INIT_CALL_RVA+5+int.from_bytes(callsite[1:],"little",signed=True)!=HELPER_RVA:
            raise ValueError("original native source call into helper target drift")
        blob=pe.read_rva(HELPER_RVA,WINDOW)
        if len(blob)!=WINDOW:raise ValueError("original bounded native helper window not file-backed")
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        md.detail=True
        instructions=[]
        direct_calls=[]
        indirect_calls=[]
        rip_refs=[]
        returns=[]
        branches=[]
        for ins in md.disasm(blob,pe.image_base+HELPER_RVA):
            rva=ins.address-pe.image_base
            row={"rva":f"0x{rva:X}","mnemonic":ins.mnemonic,"operands":ins.op_str,
                 "sourceBytes":bytes(ins.bytes).hex()}
            instructions.append(row)
            if ins.mnemonic=="call":
                if ins.op_str.startswith("0x"):
                    direct_calls.append({**row,"targetRva":f"0x{int(ins.op_str,16)-pe.image_base:X}"})
                else:indirect_calls.append(row)
            if ins.mnemonic.startswith("ret"):returns.append(row)
            if ins.mnemonic.startswith("j"):branches.append(row)
            for operand in ins.operands:
                if operand.type==X86_OP_MEM and operand.mem.base==X86_REG_RIP:
                    rip_refs.append({**row,"nativeReferencedRva":f"0x{rva+ins.size+operand.mem.disp:X}"})
        first=[r for r in instructions if int(r["rva"],16)<HELPER_RVA+0x250]
        return {
            "schemaVersion":1,
            "status":"EXACT_ORIGINAL_7_1_INTERNAL_KIND1_HELPER_NATIVE_WINDOW__CLASS_SEMANTICS_UNVERIFIED",
            "originalExeSha256":PROFILE_71.exe_sha256,
            "priorNativeInitializerSourceSha256":ORIGINAL_INIT_WINDOW_SHA,
            "nativeCallsiteRva":f"0x{INIT_CALL_RVA:X}",
            "nativeSourceCallBytes":callsite.hex(),
            "nativeHelperRva":f"0x{HELPER_RVA:X}",
            "nativeNextKnownHelperRva":f"0x{BOUND_RVA:X}",
            "sourceWindowNotProvenExactMethodSize":True,
            "nativeWindowSizeBytes":WINDOW,
            "nativeWindowSha256":hashlib.sha256(blob).hexdigest(),
            "decodedInstructionCount":len(instructions),
            "nativeReturnInstructions":returns,
            "nativeDirectCalls":direct_calls,
            "nativeIndirectCalls":indirect_calls,
            "nativeRipRelativeReferences":rip_refs,
            "nativeJumpInstructions":branches,
            "nativePrefixInstructions":first,
            "fullOriginalNativeInstructionSequence":instructions,
            "originalFunctionReturnClassTypeDefinitionIndexProven":False,
            "sourceNativeFactoryCase1Or14ClassSlotLinkProven":False,
            "originalScenePointLoaderOrChestCoordinatesProven":False,
            "limits":[
             "Bounded window ends at 0x525D40, another source-verified call target; native internal function sizes are not inferred from generated methods.csv.",
             "Original x64 source code, call targets and RIP references do not independently name a specific Il2CppClass TypeDefinitionIndex.",
             "The metadata usage kind 1 path is distinct from the 31-case Scene Point-compatible array element factory's numeric case 1.",
             "No original Scene Point loader or chest placement/level/server authority is established by this internal runtime helper."
            ]
        }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ("exe","prior","output"):p.add_argument("--"+k,type=Path,required=True)
    a=p.parse_args()
    j=inspect(a.exe,a.prior)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(j,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("ORIGINAL_524E80_BEGIN")
    print(json.dumps({k:v for k,v in j.items() if k not in
       ("fullOriginalNativeInstructionSequence","nativeJumpInstructions","nativePrefixInstructions",
        "nativeRipRelativeReferences","nativeReturnInstructions","nativeDirectCalls","nativeIndirectCalls")}
       |{"nativePrefixInstructions":j["nativePrefixInstructions"],
         "nativeReturnInstructions":j["nativeReturnInstructions"],
         "nativeDirectCalls":j["nativeDirectCalls"],
         "nativeIndirectCalls":j["nativeIndirectCalls"],
         "nativeRipRelativeReferences":j["nativeRipRelativeReferences"][:100],
         "nativeJumpInstructions":j["nativeJumpInstructions"][:120]},
       ensure_ascii=False,indent=2))
    print("ORIGINAL_524E80_END")

if __name__=="__main__":main()
