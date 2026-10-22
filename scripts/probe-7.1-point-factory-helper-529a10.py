#!/usr/bin/env python3
"""Audit the exact original Global 7.1 factory's shared native 0x529A10 helper.

The two original factory paths pass their distinct runtime class-pointer slots
to this native callee before calling original type-specific constructors.
Investigate native input/output and transfers without importing a name such
as object_new from community SDKs or assuming protected thunk semantics.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

PRIOR = "versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-case-1-14-local-native-paths.json"
HELPER_RVA = 0x529A10
WINDOW = 0x400
ORIGINAL_RET_RVA = 0x529B5A
ORIGINAL_FUNCTION_PADDING_RVA = 0x529BB4
TARGET_CASES = (1,14)


def prior_controls(path: Path) -> dict:
    report = json.loads(path.read_text(encoding="utf-8"))
    if (report["originalExeSha256"] != PROFILE_71.exe_sha256
        or report["originalMetadataSha256"] != PROFILE_71.metadata_sha256
        or report["sourceNativeWindowSha256"] !=
            "78a9930eef271eae79f9b4fdcc60a49e86ae95a8cc01d87181691c88fd365f06"
        or [r["numericFactoryCase"] for r in report["caseSlices"]] != list(TARGET_CASES)):
        raise ValueError("source-original factory path provenance mismatch")
    required = {1:("0x57C37B0","BHJILFMHGEE",54542),
                14:("0x57C1970","NKJPPNFAEEF",65289)}
    for row in report["caseSlices"]:
        expected_slot,name,idx = required[row["numericFactoryCase"]]
        path_steps = row["sourceDirectJumpFollow"]["sourceSteps"]
        calls = [x for x in path_steps if x["mnemonic"]=="call"]
        if (row["originalClassSlotRva"] != expected_slot
            or len(calls) != 2
            or calls[0]["directTargetRva"] != f"0x{HELPER_RVA:X}"
            or calls[1]["exactOriginalMethodStartOwners"][0]["typeName"] != name
            or calls[1]["exactOriginalMethodStartOwners"][0]["typeDefinitionIndex"] != idx
            or path_steps[-1]["mnemonic"] != "ret"):
            raise ValueError("previous exact native case helper/ctor chain drift")
    return report


def inspect(exe: Path, prior: Path) -> dict:
    old = prior_controls(prior)
    require_sha256(exe, PROFILE_71.exe_sha256, label="exact original Global 7.1 executable")
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM

    with PEImage(exe) as pe:
        source = pe.read_rva(HELPER_RVA, WINDOW)
        if len(source) != WINDOW:
            raise ValueError("original native shared helper is not file-backed")
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        ins = list(md.disasm(source, pe.image_base + HELPER_RVA))
        if not ins or ins[0].address - pe.image_base != HELPER_RVA:
            raise ValueError("native helper entry did not decode")
        all_aligned = {x.address - pe.image_base:x for x in ins}
        if (ORIGINAL_RET_RVA not in all_aligned
            or all_aligned[ORIGINAL_RET_RVA].mnemonic != "ret"
            or ORIGINAL_FUNCTION_PADDING_RVA not in all_aligned
            or all_aligned[ORIGINAL_FUNCTION_PADDING_RVA].mnemonic != "nop"):
            raise ValueError("original 0x529A10 native return/padding boundary drift")
        ins = [x for x in ins if x.address - pe.image_base < ORIGINAL_FUNCTION_PADDING_RVA]
        if [x.address - pe.image_base for x in ins if x.mnemonic=="ret"] != [ORIGINAL_RET_RVA]:
            raise ValueError("unexpected native helper return before source padding")
        def record(x):
            return {"rva":f"0x{x.address-pe.image_base:X}", "mnemonic":x.mnemonic,
                    "operands":x.op_str, "bytes":bytes(x.bytes).hex()}
        all_instructions = [record(x) for x in ins]
        calls = []
        transfers = []
        for x in ins:
            if x.mnemonic != "call" and not x.mnemonic.startswith("j"):
                continue
            row=record(x)
            if len(x.operands)==1 and x.operands[0].type==X86_OP_IMM:
                target=x.operands[0].imm-pe.image_base
                row["sourceDirectTargetRva"]=f"0x{target:X}"
            else:
                row["sourceDirectTargetRva"]=None
            transfers.append(row)
            if x.mnemonic=="call": calls.append(row)
        by_rva = {x.address - pe.image_base:x for x in ins}
        expected_flow = {
            0x529A24:("mov","rsi, rcx"),
            0x529A27:("test","byte ptr [rcx + 0xc9], 0x10"),
            0x529A4F:("call",f"0x{pe.image_base + 0x512DB0:x}"),
            0x529A6C:("call",f"0x{pe.image_base + 0x51CD50:x}"),
            0x529AD4:("call",f"0x{pe.image_base + 0x50D9C0:x}"),
            0x529ABC:("call",f"0x{pe.image_base + 0x55A0B0:x}"),
            0x529B28:("call",f"0x{pe.image_base + 0x55A0B0:x}"),
            0x529B2D:("mov","rdi, rax"),
            0x529B48:("mov","rcx, rsi"),
            0x529B4B:("call",f"0x{pe.image_base + 0x51C180:x}"),
            0x529B50:("mov","rax, rdi"),
            0x529B5A:("ret",""),
        }
        for rva,(mnemonic,operands) in expected_flow.items():
            insn = by_rva.get(rva)
            if insn is None or (insn.mnemonic,insn.op_str)!=(mnemonic,operands):
                raise ValueError(f"original factory helper native data-flow witness drift at 0x{rva:X}")
        first = ins[0]
        thunk = first.mnemonic=="jmp" and len(first.operands)==1 and first.operands[0].type==X86_OP_IMM
        redirected=None
        if thunk:
            target=first.operands[0].imm-pe.image_base
            sample=pe.read_rva(target,0x100)
            if len(sample)!=0x100:
                raise ValueError("original shared helper thunk target not source-file-backed")
            redirected={
                "originalRedirectRva":f"0x{target:X}",
                "originalRedirectWindowBytes":len(sample),
                "sourceRedirectSha256":hashlib.sha256(sample).hexdigest(),
                "sourceRedirectPrefix": [record(x) for x in
                    list(md.disasm(sample,pe.image_base+target))[:60]],
            }
    return {
        "schemaVersion":1,
        "status":"SOURCE_GLOBAL_7_1_FACTORY_SHARED_529A10_NATIVE_INSPECTION__RUNTIME_ALLOCATION_UNVERIFIED",
        "originalExecutableSha256":PROFILE_71.exe_sha256,
        "originalMetadataSha256":PROFILE_71.metadata_sha256,
        "originalFactoryPathEvidence":PRIOR,
        "sourceOriginalCasesUsingTarget":list(TARGET_CASES),
        "sharedNativeHelperRva":f"0x{HELPER_RVA:X}",
        "originalFileBackedWindowBytes":WINDOW,
        "originalSourceNativeWindowSha256":hashlib.sha256(source).hexdigest(),
        "originalFirstInstructions":all_instructions[:130],
        "sourceDecodedLinearInstructionCount":len(ins),
        "originalSourcePaddingBoundaryRva":f"0x{ORIGINAL_FUNCTION_PADDING_RVA:X}",
        "originalSourceWitnessedSharedHelperDataFlow":[record(by_rva[rva]) for rva in expected_flow],
        "originalDataFlowVia55A0B0ReturnRdiToRaxVerified":True,
        "source55A0B0ActualAllocationSemanticsVerified":False,
        "originalReturnInstructionRvas":[x["rva"] for x in all_instructions if x["mnemonic"].startswith("ret")],
        "sourceDirectAndIndirectTransfers":transfers[:100],
        "sourceCallSites":calls[:80],
        "originalFirstInstructionIsDirectJumpThunk":thunk,
        "sourceRedirectIfThunk":redirected,
        "originalNativeHelperProvenObjectAllocator":False,
        "sourceFactoryCaseClassPointerToTypeDefinitionResolved":False,
        "originalScenePointLoaderOrChestPositionLevelProven":False,
        "limits":[
            "The shared call target 0x529A10 and its two original callers are source-authenticated by a previous independent run.",
            "Linear decoding from a method entry does not prove full reachable CFG or runtime execution.",
            "This probe does not assign object allocator semantics from a well-known helper RVA or source-blind function name.",
            "No independent original scene Point resource path-to-reader edge or original chest coordinates/level is proven.",
        ],
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for field in ("exe","prior","output"):
        p.add_argument("--"+field,required=True,type=Path)
    x=p.parse_args()
    result=inspect(x.exe,x.prior)
    x.output.parent.mkdir(parents=True,exist_ok=True)
    x.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_HELPER_529A10_BEGIN")
    print(json.dumps(result,indent=2,ensure_ascii=False))
    print("ORIGINAL_HELPER_529A10_END")


if __name__=="__main__":
    main()
