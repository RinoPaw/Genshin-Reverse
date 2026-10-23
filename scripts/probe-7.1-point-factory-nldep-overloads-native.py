#!/usr/bin/env python3
"""Original Global 7.1 factory case reader chain into NLDEPJEOJGC.

Verify original source native case14 -> case1 -> NLDEPJEOJGC one-argument
GMENPOPMKAA, then inspect that one-argument native reader. The separately
authenticated two-argument array parser is a distinct method until an exact
native invocation is shown. Never infer Scene/Point loading or chest fields.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

PRIOR = "versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-case-1-14-ctor-owner-reader-native.json"
ARRAY_PRIOR = "versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-array-element-factory-native-evidence.json"
OWNER = "NLDEPJEOJGC"
TYPE_DEF = 63768
ONE_ARG_METHOD_INDEX = 514422
ONE_ARG_RVA = 0xAD22310
TWO_ARG_METHOD_INDEX = 514423
TWO_ARG_RVA = 0xAD23000
ONE_ARG_WINDOW = TWO_ARG_RVA - ONE_ARG_RVA
TWO_ARG_SAMPLE_SIZE = 0x620
TWO_ARG_SOURCE_SHA = "6319613278adf382bf7ce513d1d875ef98b318d5f5f3bc9c423b72caebd7c0ad"


def provenance(previous: Path, array: Path) -> dict:
    p=json.loads(previous.read_text(encoding="utf-8"))
    a=json.loads(array.read_text(encoding="utf-8"))
    if (p["sourceOriginalExeSha256"]!=PROFILE_71.exe_sha256
        or p["sourceOriginalMetadataSha256"]!=PROFILE_71.metadata_sha256
        or a["originalExeSha256"]!=PROFILE_71.exe_sha256
        or a["originalMetadataSha256"]!=PROFILE_71.metadata_sha256):
        raise ValueError("exact original 7.1 native provenance drift")
    cases=p["originalCaseOwnerDeclarations"]
    if [x["originalFactoryNumericCase"] for x in cases]!=[1,14]:
        raise ValueError("original numeric factory case report drift")
    one=cases[0]["sourceOriginalGMENPOPMKAANativeMethod"]
    fourteen=cases[1]["sourceOriginalGMENPOPMKAANativeMethod"]
    if (one["sourceOriginalMethodRva"]!="0x138B9390"
        or fourteen["sourceOriginalMethodRva"]!="0x8613440"
        or not any(x["rva"]=="0x138B93B9" and x["mnemonic"]=="call"
                   and x["operands"]==f"0x{0x140000000+ONE_ARG_RVA:x}"
                   and x["bytes"]=="e8528f46f7" for x in one["sourceNativeCalls"])
        or p["sourceExactCase14ReaderDirectCallToCase1Reader"] != {
            "rva":"0x8613469","mnemonic":"call",
            "operands":"0x1538b9390","bytes":"e8225f2a0b"}):
        raise ValueError("source native factory-to-one-arg-reader direct calls drift")
    methods=a["originalArrayNativeReader"]["originalClassMethods"]
    expected={(ONE_ARG_METHOD_INDEX,ONE_ARG_RVA,("FNIAHJGHFAK",)),
              (TWO_ARG_METHOD_INDEX,TWO_ARG_RVA,("FNIAHJGHFAK","kind_0x15"))}
    observed=set()
    for item in methods:
        if item["rva"] not in ("0xAD22310","0xAD23000"):
            continue
        observed.add((int(item["index"]),int(item["rva"],16),
                      tuple(json.loads(item["parameterTypes"]))))
        if (item["originalTypeName"],item["typeDefinitionIndex"],item["name"]) != (
            OWNER, TYPE_DEF, "GMENPOPMKAA"):
            raise ValueError("exact original NLDEP method owner drift")
    if observed!={(i,r,tuple(p)) for i,r,p in expected}:
        raise ValueError("distinct original one- and two-arg NLDEP method signatures drift")
    if a["originalArrayNativeReader"]["nativeSourceWindowSha256"]!=TWO_ARG_SOURCE_SHA:
        raise ValueError("original 7.1 two-arg source reader window hash drift")
    return {"originalCase14NativeCallRva":"0x8613469",
            "originalCase1NativeCallRva":"0x138B93B9",
            "nativeCalleeOneArgMethodRva":f"0x{ONE_ARG_RVA:X}"}


def inspect(exe:Path,previous:Path,array:Path)->dict:
    chain=provenance(previous,array)
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 EXE")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86 import X86_OP_IMM
    with PEImage(exe) as pe:
        data=pe.read_rva(ONE_ARG_RVA,ONE_ARG_WINDOW)
        second=pe.read_rva(TWO_ARG_RVA,TWO_ARG_SAMPLE_SIZE)
        if len(data)!=ONE_ARG_WINDOW or len(second)!=TWO_ARG_SAMPLE_SIZE:
            raise ValueError("one-arg or two-arg original native window not backed")
        if hashlib.sha256(second).hexdigest()!=TWO_ARG_SOURCE_SHA:
            raise ValueError("original 7.1 two-arg native positive control drift")
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        md.detail=True
        original=list(md.disasm(data,pe.image_base+ONE_ARG_RVA))
        if not original or original[0].address-pe.image_base!=ONE_ARG_RVA:
            raise ValueError("source original one-arg reader entry did not decode")
        def witness(x):
            return {"rva":f"0x{x.address-pe.image_base:X}",
                    "mnemonic":x.mnemonic,"operands":x.op_str,
                    "bytes":bytes(x.bytes).hex()}
        direct=[]
        indirect=[]
        for ins in original:
            if ins.mnemonic!="call":
                continue
            w=witness(ins)
            if len(ins.operands)==1 and ins.operands[0].type==X86_OP_IMM:
                w["targetRva"]=f"0x{ins.operands[0].imm-pe.image_base:X}"
                direct.append(w)
            else:indirect.append(w)
        two_arg_calls=[x for x in direct if x["targetRva"]==f"0x{TWO_ARG_RVA:X}"]
    return {
        "schemaVersion":1,
        "status":"ORIGINAL_GLOBAL_7_1_FACTORY_14_TO_1_TO_NLDEP_ONE_ARG_NATIVE_READER__POINT_LOADER_UNVERIFIED",
        "originalExeSha256":PROFILE_71.exe_sha256,
        "originalMetadataSha256":PROFILE_71.metadata_sha256,
        "previousFactoryConstructorReaderEvidence":PRIOR,
        "previousNLDEPArrayReaderEvidence":ARRAY_PRIOR,
        "sourceFactoryToNLDEPDirectCallChain":chain,
        "originalOneArgReaderOwner":OWNER,
        "originalOneArgReaderTypeDefinitionIndex":TYPE_DEF,
        "originalOneArgReaderMethodIndex":ONE_ARG_METHOD_INDEX,
        "originalTwoArgArrayReaderMethodIndex":TWO_ARG_METHOD_INDEX,
        "originalOneArgReaderNativeRva":f"0x{ONE_ARG_RVA:X}",
        "originalTwoArgArrayReaderNativeRva":f"0x{TWO_ARG_RVA:X}",
        "sourceOneArgWindowBytes":ONE_ARG_WINDOW,
        "sourceOneArgWindowSha256":hashlib.sha256(data).hexdigest(),
        "sourceTwoArgPositiveControlSha256":hashlib.sha256(second).hexdigest(),
        "sourceOneArgDecodedLinearInstructions":len(original),
        "sourceOneArgNativeFirstInstructions":[witness(x) for x in original[:80]],
        "sourceOneArgNativeDirectCalls":direct[:100],
        "sourceOneArgNativeIndirectCalls":indirect[:60],
        "sourceOneArgNativeReturnCandidates":[witness(x) for x in original
                                               if x.mnemonic=="ret"][:30],
        "sourceOneArgDirectCallsIntoTwoArgNativeReader":two_arg_calls,
        "sourceFactoryVirtualReaderF8TargetProven":False,
        "sourcePointAssetLoaderToNativeChainProven":False,
        "originalChestCoordinatesAndLevelProven":False,
        "limits":[
            "The two overloads share an original declaring type and method token, but remain distinct native methods.",
            "Instruction-aligned direct calls prove code-reference edges, not a loader-file association or virtual dispatch binding.",
            "Linear disassembly stops at the next original declared RVA and is not a full runtime CFG.",
            "No official Scene/Point asset row semantics, Gadget/chest position, level or server authority follows."
        ],
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ("exe","previous","array","output"):
        p.add_argument("--"+arg,type=Path,required=True)
    x=p.parse_args()
    out=inspect(x.exe,x.previous,x.array)
    x.output.parent.mkdir(parents=True,exist_ok=True)
    x.output.write_text(json.dumps(out,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("ORIGINAL_71_FACTORY_NLDEP_NATIVE_BEGIN")
    print(json.dumps(out,ensure_ascii=False,indent=2))
    print("ORIGINAL_71_FACTORY_NLDEP_NATIVE_END")


if __name__=="__main__":
    main()
