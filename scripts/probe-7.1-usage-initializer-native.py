#!/usr/bin/env python3
"""Original Global 7.1 native metadata-usage initializer disassembly.

Read original SHA-256 verified executable and the original methods.csv
metadata; constrain method window by the next original method entry.
Capture original x86-64 bytes, branch/call edges and RIP-relative references
to registration global at 0x5AD52A8. Never infer target pointer contents,
usage destination semantics, type identity or chest placement.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
from genshinre.callxref import _load_method_starts
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

ROOT_RVA=0x5AD52A8
INITIALIZER_RVA=0x523400
MAX_WINDOW=0x3000
METHODS_BLOB="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
PRIOR="versions/7.1.0-global/analyses/progression/world/7.1-original-point-factory-metadata-usage-table-boundary.json"


def git_blob(path:Path)->str:
    h=hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""):h.update(b)
    return h.hexdigest()


def inspect(exe:Path,methods:Path,prior:Path)->dict:
    if git_blob(methods)!=METHODS_BLOB:raise ValueError("original generated metadata methods source drift")
    p=json.loads(prior.read_text(encoding="utf-8"))
    if (p["originalExecutableSha256"]!=PROFILE_71.exe_sha256 or
       p["originalMetadataSha256"]!=PROFILE_71.metadata_sha256 or
       p["sourceOriginalUsageLayout"]["originalCandidateListCount"]!=311730):
        raise ValueError("original previous metadata usage evidence drift")
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 executable")
    starts,owners=_load_method_starts(methods)
    pos=bisect_right(starts,INITIALIZER_RVA)
    pre=bisect_right(starts,INITIALIZER_RVA)-1
    if pos>=len(starts):raise ValueError("no next original metadata method RVA")
    predecessor=starts[pre] if pre>=0 else None
    successor=starts[pos]
    end=min(INITIALIZER_RVA+MAX_WINDOW,successor)
    if end<=INITIALIZER_RVA+0x30:raise ValueError("original native initializer too short")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86 import X86_OP_MEM,X86_REG_RIP
    with PEImage(exe) as pe:
        data=pe.read_rva(INITIALIZER_RVA,end-INITIALIZER_RVA)
        if len(data)!=end-INITIALIZER_RVA:raise ValueError("original native initializer not fully file-backed")
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        md.detail=True
        native=list(md.disasm(data,pe.image_base+INITIALIZER_RVA))
        if len(native)<20:raise ValueError("initializer fails native source decode")
        instructions=[]
        direct_calls=[]
        other_calls=[]
        root_references=[]
        jumps=[]
        for x in native:
            rva=x.address-pe.image_base
            row={"rva":f"0x{rva:X}","mnemonic":x.mnemonic,"operands":x.op_str,"originalBytes":bytes(x.bytes).hex()}
            instructions.append(row)
            if x.mnemonic=="call":
                if x.op_str.startswith("0x"):
                    dest=int(x.op_str,16)-pe.image_base
                    direct_calls.append({**row,"originalTargetRva":f"0x{dest:X}",
                        "originalExactMethodOwners":[{
                          "typeName":o["type_name"],"name":o["method_name"],
                          "methodIndex":int(o["method_index"])}
                          for o in owners.get(dest,[])]})
                else:other_calls.append(row)
            if x.mnemonic.startswith("j"):jumps.append(row)
            for operand in x.operands:
                if operand.type==X86_OP_MEM and operand.mem.base==X86_REG_RIP:
                    target=rva+x.size+operand.mem.disp
                    if target==ROOT_RVA:
                        root_references.append({**row,"nativeTargetRva":f"0x{target:X}"})
        root_init_raw=pe.read_rva(ROOT_RVA,8)
    return {
        "schemaVersion":1,
        "status":"SOURCE_EXACT_GLOBAL_7_1_NATIVE_METADATA_INITIALIZER_CONTROL_FLOW__USAGE_DESTINATION_SLOT_UNRESOLVED",
        "originalExecutableSha256":PROFILE_71.exe_sha256,
        "originalMethodsGitBlob":METHODS_BLOB,
        "originalInitializerRva":f"0x{INITIALIZER_RVA:X}",
        "nearestOriginalMethodAtOrBeforeRva":None if predecessor is None else f"0x{predecessor:X}",
        "nextOriginalMethodStartRva":f"0x{successor:X}",
        "nativeWindowTruncatedByLimit":end<successor,
        "nativeWindowBytes":len(data),
        "originalNativeWindowSha256":hashlib.sha256(data).hexdigest(),
        "sourceNativeInstructionsDecoded":len(instructions),
        "originalMetadataMethodOwnersAtStart":[{
            "typeName":o["type_name"],"methodName":o["method_name"],
            "methodIndex":int(o["method_index"])}
            for o in owners.get(INITIALIZER_RVA,[])],
        "originalRegisterGlobalRva":f"0x{ROOT_RVA:X}",
        "sourceRegistrationGlobalFileBackedBytes":root_init_raw.hex() if len(root_init_raw)==8 else None,
        "nativeRIPReferencesToRegistrationGlobal":root_references,
        "nativeDirectCallCount":len(direct_calls),
        "nativeDirectCalls":direct_calls,
        "nativeIndirectCalls":other_calls,
        "nativeBranchInstructions":jumps,
        "originalInstructionRows":instructions,
        "metadataUsagePairDestinationToClassSlotMapped":False,
        "originalFactoryConcreteClassesMapped":False,
        "originalScenePointAssetLoaderMapped":False,
        "chestPositionsAndLevelProven":False,
        "limits":[
         "Original instructions are decoded in a file-backed RVA window capped by the next original generated method pointer and MAX_WINDOW.",
         "This RVA precedes the earliest generated IL2CPP method pointer when predecessor is null; native IL2CPP runtime helpers are not generated-method entries.",
         "A source pointer slot RVA does not imply a usable static runtime class object or a direct metadata usage destination mapping.",
         "Original gadget, chest, coordinates, levels and original client/server placement authority remain unresolved."
        ]
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ("exe","methods","prior","output"):p.add_argument("--"+k,type=Path,required=True)
    a=p.parse_args()
    r=inspect(a.exe,a.methods,a.prior)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(r,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_USAGE_INIT_BEGIN")
    print(json.dumps({
       k:r[k] for k in ("status","originalInitializerRva","nearestOriginalMethodAtOrBeforeRva",
        "nextOriginalMethodStartRva","nativeWindowTruncatedByLimit","nativeWindowBytes",
        "originalNativeWindowSha256","sourceNativeInstructionsDecoded",
        "originalMetadataMethodOwnersAtStart","sourceRegistrationGlobalFileBackedBytes",
        "nativeRIPReferencesToRegistrationGlobal","nativeDirectCalls","nativeIndirectCalls",
        "nativeBranchInstructions")
    } | {"firstNativeInstructions":r["originalInstructionRows"][:200]},indent=2,ensure_ascii=False))
    print("ORIGINAL_USAGE_INIT_END")

if __name__=="__main__":main()
