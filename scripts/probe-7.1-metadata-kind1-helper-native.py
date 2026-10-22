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
HELPER_FLOW_END_RVA=0x524F30
HELPER_FLOW_BYTES=HELPER_FLOW_END_RVA-HELPER_RVA
NESTED_CALLEES=((0x50D9C0,0x480),(0x512DB0,0x380))
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
        exact={int(x["rva"],16):x for x in instructions}
        witnesses={
          0x524E94:("cmp","ecx, -1"),
          0x524E99:("mov","rax, qword ptr [rip + 0x55b0430]"),
          0x524EA0:("movsxd","rdi, ecx"),
          0x524EA3:("mov","rsi, qword ptr [rax + rdi*8]"),
          0x524EA7:("test","rsi, rsi"),
          0x524EAC:("mov","rax, qword ptr [rip + 0x55b03ed]"),
          0x524EB3:("mov","rcx, rdi"),
          0x524EB6:("shl","rcx, 4"),
          0x524EBA:("add","rcx, qword ptr [rax + 0x48]"),
          0x524EBE:("call",f"0x{pe.image_base+0x50D9C0:x}"),
          0x524ECB:("test","byte ptr [rax + 0xc9], 0x10"),
          0x524EF0:("mov","rcx, rsi"),
          0x524EF3:("call",f"0x{pe.image_base+0x512DB0:x}"),
          0x524F05:("mov","rax, qword ptr [rip + 0x55b03c4]"),
          0x524F0C:("mov","qword ptr [rax + rdi*8], rsi"),
          0x524F14:("mov","rax, rsi"),
          0x524F1E:("ret",""),
          0x524F1F:("mov","rax, qword ptr [rip + 0x55b03aa]"),
          0x524F26:("mov","rsi, qword ptr [rax + rdi*8]"),
          0x524F2A:("jmp",f"0x{pe.image_base+0x524F14:x}"),
          0x524F30:("mov","qword ptr [rsp + 0x10], rdx"),
        }
        for address,(mnemonic,ops) in witnesses.items():
            i=exact.get(address)
            if not i or (i["mnemonic"],i["operands"])!=(mnemonic,ops):
                raise ValueError(f"original kind1 native helper instruction drift at 0x{address:X}")
        if exact[0x524F1E]["mnemonic"]!="ret" or any(
             x["mnemonic"]=="call" for x in instructions
             if 0x524F1F<=int(x["rva"],16)<HELPER_FLOW_END_RVA):
            raise ValueError("source native kind1 resolver tail boundary changed")
        helper_flow=pe.read_rva(HELPER_RVA,HELPER_FLOW_BYTES)
        if len(helper_flow)!=HELPER_FLOW_BYTES:
            raise ValueError("source original kind1 native core flow inaccessible")
        original_flow=[x for x in instructions if int(x["rva"],16)<HELPER_FLOW_END_RVA]
        nested=[]
        for target,win_size in NESTED_CALLEES:
            window=pe.read_rva(target,win_size)
            if len(window)!=win_size:raise ValueError("source original type resolution callee not file-backed")
            ops=list(md.disasm(window,pe.image_base+target))
            rows=[{"rva":f"0x{x.address-pe.image_base:X}","mnemonic":x.mnemonic,
                   "operands":x.op_str,"sourceBytes":bytes(x.bytes).hex()} for x in ops]
            native_direct=[{**row,"sourceNativeTargetRva":f"0x{int(row['operands'],16)-pe.image_base:X}"}
                for row in rows if row["mnemonic"]=="call" and row["operands"].startswith("0x")]
            nested.append({
              "sourceOriginalCalleeRva":f"0x{target:X}",
              "boundedWindowBytes":win_size,
              "windowSha256":hashlib.sha256(window).hexdigest(),
              "nativeDecodedInstructions":len(rows),
              "nativeFirstReturnRva":next((x["rva"] for x in rows if x["mnemonic"]=="ret"),None),
              "nativeDirectCalls":native_direct[:100],
              "nativeIndirectCalls":[x for x in rows if x["mnemonic"]=="call" and not x["operands"].startswith("0x")][:100],
              "nativePrefixInstructions":rows[:160],
              "boundedWindowIsExactMethodSizeProven":False,
            })
        source_type_resolver=next(x for x in nested if x["sourceOriginalCalleeRva"]=="0x50D9C0")
        type_rows={int(x["rva"],16):x for x in source_type_resolver["nativePrefixInstructions"]}
        type_positive_controls={
          0x50D9C9:("movsx","ecx, byte ptr [rcx + 0xa]"),
          0x50D9CF:("dec","ecx"),
          0x50D9D1:("cmp","ecx, 0x1d"),
          0x50D9DA:("lea","rsi, [rip + 0x26f]"),
          0x50D9E1:("movsxd","rcx, dword ptr [rsi + rcx*4]"),
          0x50D9E5:("add","rcx, rsi"),
          0x50D9E8:("jmp","rcx"),
        }
        for rva,(mnemonic,operands) in type_positive_controls.items():
            row=type_rows.get(rva)
            if row is None or (row["mnemonic"],row["operands"])!=(mnemonic,operands):
                raise ValueError(f"source original 7.1 runtime type-kind resolver drift at 0x{rva:X}")
        table_rva=0x50DC50
        original_table=pe.read_rva(table_rva,30*4)
        if len(original_table)!=30*4:
            raise ValueError("original native IL2CPP type kind table not file-backed")
        from struct import unpack_from
        original_cases=[]
        for index in range(30):
            rel=unpack_from("<i",original_table,index*4)[0]
            target=table_rva+rel
            if not 0x50D9C0<=target<table_rva:
                raise ValueError(f"original kind-dispatch target outside native body for {index+1}")
            original_cases.append({
              "originalRawRuntimeTypeKindByte":index+1,
              "nativeRelativeJumpOffset":rel,
              "originalNativeBranchRva":f"0x{target:X}",
              "sourceNativeAlignedWithinPrefix":target in type_rows,
              "originalSemanticIL2CPPTypeKindNameProven":False,
            })
        if not all(x["sourceNativeAlignedWithinPrefix"] for x in original_cases):
            raise ValueError("source-original 30-way runtime type kind jump table instruction alignment drift")
        type_kind_dispatch={
            "originalResolverRva":"0x50D9C0",
            "sourceWindowSha256":source_type_resolver["windowSha256"],
            "originalTypeTagByteObjectOffset":"0xA",
            "sourceKindByteSignExtension":True,
            "sourceKindTagLowerBound":1,
            "sourceKindTagUpperBound":30,
            "sourceTypeCaseJumpTableRva":f"0x{table_rva:X}",
            "sourceTypeCaseJumpTableSha256":hashlib.sha256(original_table).hexdigest(),
            "sourceTypeCaseJumpTableBytesHex":original_table.hex(),
            "originalTypeKindCases":original_cases,
            "sourceKindDecodeControlInstructions":[type_rows[k] for k in type_positive_controls],
            "originalSemanticIl2CppTypeKindLabelsProven":False,
            "originalConcreteFactoryCase1Or14Proven":False,
        }
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
            "sourceOriginalKind1CoreFlow":{
                "firstRva":f"0x{HELPER_RVA:X}",
                "nextNativeCodeEntryRva":f"0x{HELPER_FLOW_END_RVA:X}",
                "coreFlowSpanBytes":HELPER_FLOW_BYTES,
                "coreFlowSha256":hashlib.sha256(helper_flow).hexdigest(),
                "sourceOriginalCoreInstructions":original_flow,
                "sourceVerifiedControlInstructionWitnesses":[exact[a] for a in witnesses],
                "sourceArgumentKind":"original decoded runtime type source index passed in ECX",
                "sourceCacheGlobalRva":"0x5AD52D0",
                "sourceCacheLookupAndWriteIndexRegister":"rdi",
                "sourceCacheEntryStrideBytes":8,
                "sourceMetadataRegistrationGlobalRva":"0x5AD52A0",
                "sourceMetadataIndexedRecordStrideBytes":16,
                "sourceMetadataRecordTablePointerOffset":"0x48",
                "sourceNativeClassMaterializationCalleeRva":"0x50D9C0",
                "sourceNativeClassInitCheckByteOffset":"0xC9",
                "sourcePostMaterializationInitCalleeRva":"0x512DB0",
                "sourceReturnRva":"0x524F1E",
                "sourceColdCacheReadBlockRva":"0x524F1F",
                "sourceColdBlockTailJumpRva":"0x524F2A",
                "sourceOriginalIl2CppTypeDefinitionIndexProven":False,
            },
            "originalDirectNativeTypeResolverSubcalls":nested,
            "sourceOriginalRuntimeTypeKindDispatch":type_kind_dispatch,
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
         "sourceOriginalKind1CoreFlow":{k:v for k,v in j["sourceOriginalKind1CoreFlow"].items() if k not in ("sourceOriginalCoreInstructions","sourceVerifiedControlInstructionWitnesses")},
         "originalDirectNativeTypeResolverSubcalls":j["originalDirectNativeTypeResolverSubcalls"],
         "sourceOriginalRuntimeTypeKindDispatch":j["sourceOriginalRuntimeTypeKindDispatch"],
         "sourceControlWitnesses":j["sourceOriginalKind1CoreFlow"]["sourceVerifiedControlInstructionWitnesses"],
         "nativeRipRelativeReferences":j["nativeRipRelativeReferences"][:100],
         "nativeJumpInstructions":j["nativeJumpInstructions"][:120]},
       ensure_ascii=False,indent=2))
    print("ORIGINAL_524E80_END")

if __name__=="__main__":main()
