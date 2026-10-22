#!/usr/bin/env python3
"""Source-authenticated original Global 7.1 factory class-slot native xrefs.

The factory's exact 31 source IL2CPP class pointer slot addresses are
retrieved from the retained original native jump-table evidence. Scan only
file-backed x64 RIP-relative MOV/LEA candidate instructions in executable
sections. Re-disassemble each candidate from a known original method start
before attributing any source method owner. Distinct method xrefs are not a
proof of the class slot's concrete type. In particular a factory allocator
and class metadata registration may reference many other types.
"""
from __future__ import annotations
import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256
from genshinre.callxref import _load_method_starts

ORIGINAL_FACTORY_REPORT = "versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-array-element-factory-native-evidence.json"
EXPECTED_METHODS_GIT_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
EXPECTED_FACTORY_SHA = "78a9930eef271eae79f9b4fdcc60a49e86ae95a8cc01d87181691c88fd365f06"
TARGET_CASES = (1, 14)
MAX_ALIGN_SPAN = 0x4000
MAX_XREFS_PER_SLOT = 300
MAX_REPORT_OWNERS = 100
# MOV/LEA r32/r64, [rip+disp32], with optional REX.W prefixes.
PREFIXES = tuple(
    bytes((rex, opcode, modrm))
    for rex in (0x48, 0x4C)
    for opcode in (0x8B, 0x8D)
    for modrm in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D)
)
EXECUTABLE_SECTION = 0x20000000


def git_blob(path: Path) -> str:
    h=hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""):
            h.update(b)
    return h.hexdigest()


def source_factory_slots(path: Path) -> list[dict]:
    j=json.loads(path.read_text(encoding="utf-8"))
    fac=j["originalFactory"]
    if (j["originalExeSha256"]!=PROFILE_71.exe_sha256
        or j["originalMethodsGitBlob"]!=EXPECTED_METHODS_GIT_BLOB
        or fac["originalSourceWindowSha256"]!=EXPECTED_FACTORY_SHA
        or fac["exactAlignedNativeJumpCaseCount"]!=31):
        raise ValueError("source original 7.1 polymorphic element factory evidence drift")
    cases=fac["sourceCases"]
    if [x["originalNumericCaseId"] for x in cases]!=list(range(31)):
        raise ValueError("original 7.1 factory case IDs changed")
    if any(x["nativeRuntimeClassSlotRva"] is None for x in cases):
        raise ValueError("original native class slot missing")
    return cases


def scan(exe:Path,methods:Path,factory:Path)->dict:
    if git_blob(methods)!=EXPECTED_METHODS_GIT_BLOB:
        raise ValueError("source original 7.1 methods.csv Git blob changed")
    cases=source_factory_slots(factory)
    slots={int(c["nativeRuntimeClassSlotRva"],16):c["originalNumericCaseId"] for c in cases}
    if len(slots)!=31:raise ValueError("original factory class slots contain duplicates")
    require_sha256(exe,PROFILE_71.exe_sha256,label="Global 7.1 original client")
    methods_by_rva=[]
    owners_by_rva={}
    starts,owners_by_rva=_load_method_starts(methods)
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    candidates=defaultdict(list)
    sections=[]
    with PEImage(exe) as pe:
        for section in pe.sections:
            if not(section.characteristics&EXECUTABLE_SECTION):continue
            data=pe.read_rva(section.virtual_address,section.raw_size)
            sections.append({"name":section.name,
                             "virtualAddress":f"0x{section.virtual_address:X}",
                             "rawBytes":len(data)})
            for prefix in PREFIXES:
                pos=0
                while True:
                    idx=data.find(prefix,pos)
                    if idx<0:break
                    pos=idx+1
                    if idx+7>len(data):continue
                    rva=section.virtual_address+idx
                    disp=int.from_bytes(data[idx+3:idx+7],"little",signed=True)
                    target=rva+7+disp
                    if target not in slots:continue
                    entries=candidates[target]
                    if len(entries)>=MAX_XREFS_PER_SLOT:
                        raise ValueError(f"too many source original xrefs to slot 0x{target:X}")
                    entries.append({"candidateRva":rva,
                                    "candidateOpcodeHex":data[idx:idx+7].hex(),
                                    "section":section.name})
        output={}
        for slot,kind in sorted(slots.items(),key=lambda x:x[1]):
            recs=[]
            for candidate in candidates.get(slot,[]):
                site=candidate["candidateRva"]
                idx=bisect_right(starts,site)-1
                if idx<0:
                    recs.append({**candidate,"verifiedNativeInstruction":False,"reason":"NO_METHOD_START"})
                    continue
                start=starts[idx]
                span=site+7-start
                nextstart=starts[idx+1] if idx+1<len(starts) else None
                if span>MAX_ALIGN_SPAN or span<7 or nextstart is not None and site>=nextstart:
                    recs.append({**candidate,"verifiedNativeInstruction":False,"reason":"OUTSIDE_BOUNDED_ORIGINAL_METHOD","nearestOriginalMethodStartRva":f"0x{start:X}"})
                    continue
                data=pe.read_rva(start,span)
                ins=None
                for x in md.disasm(data,pe.image_base+start):
                    if x.address-pe.image_base==site:
                        ins=x
                        break
                if ins is None or bytes(ins.bytes).hex()!=candidate["candidateOpcodeHex"]:
                    recs.append({**candidate,"verifiedNativeInstruction":False,"reason":"UNALIGNED_ORIGINAL_DISASSEMBLY"})
                    continue
                rip_ops=[v for v in ins.operands if v.type==X86_OP_MEM and v.mem.base==X86_REG_RIP]
                if len(rip_ops)!=1 or (ins.address-pe.image_base+ins.size+rip_ops[0].mem.disp)!=slot:
                    recs.append({**candidate,"verifiedNativeInstruction":False,"reason":"RIP_POINTER_SEMANTICS_MISMATCH"})
                    continue
                owners=[{"originalTypeName":o["type_name"],
                          "originalMethodName":o["method_name"],
                          "originalMethodIndex":int(o["method_index"]),
                          "originalTypeDefinitionIndex":int(o["type_definition_index"])}
                        for o in owners_by_rva.get(start,[])]
                recs.append({**candidate,
                             "verifiedNativeInstruction":True,
                             "originalMethodStartRva":f"0x{start:X}",
                             "sourceAlignedInstruction":f"{ins.mnemonic} {ins.op_str}",
                             "exactOriginalMethodOwners":owners})
            matching=[r for r in recs if r["verifiedNativeInstruction"]]
            unique_types=Counter(o["originalTypeName"] for r in matching for o in r["exactOriginalMethodOwners"])
            output[str(kind)]={
                "originalNumericFactoryCaseId":kind,
                "nativeClassSlotRva":f"0x{slot:X}",
                "factoryNativeBranchRva":cases[kind]["nativeBranchRva"],
                "nativeRIPRelativeByteCandidates":len(recs),
                "verifiedNativeInstructions":len(matching),
                "originalExactTypeOwnerFrequency":dict(unique_types.most_common(MAX_REPORT_OWNERS)),
                "verifiedXrefs":matching,
                "unverifiedXrefs":[r for r in recs if not r["verifiedNativeInstruction"]],
                "nativeClassSlotTypeDefinitionIndexProven":False,
                "nativeClassSlotVtableReaderProven":False,
            }
    return {
      "schemaVersion":1,
      "status":"EXACT_7_1_ORIGINAL_FACTORY_CLASS_SLOT_NATIVE_XREFS__CONCRETE_TYPE_UNRESOLVED",
      "originalExeSha256":PROFILE_71.exe_sha256,
      "originalMetadataSha256":PROFILE_71.metadata_sha256,
      "originalMethodsGitBlob":EXPECTED_METHODS_GIT_BLOB,
      "sourceOriginalFactoryReport":ORIGINAL_FACTORY_REPORT,
      "sourceFactoryMethodSha256":EXPECTED_FACTORY_SHA,
      "sourceOriginalExecutableSections":sections,
      "factoryNumericCaseCount":31,
      "targetFactoryCases":list(TARGET_CASES),
      "allFactoryCases":output,
      "originalScenePointAssetLoaderLinkedToFactory":False,
      "case1RuntimeClassProven":False,
      "case14RuntimeClassProven":False,
      "case1And14OriginalElementReaderVtableProven":False,
      "originalChestGadgetPlacementOrLevelProven":False,
      "limitations":[
        "Only exact Global 7.1 original executable RIP-relative MOV/LEA native instructions are considered; immediate address patterns and non-file-backed runtime registration are excluded.",
        "A native xref declared in an original method of type X is not proof the referenced slot's concrete class is X.",
        "No original Scene/Point file loader or row parser was verified by this static pointer cross-reference scan.",
        "No recovered Gadget/chest instance location, level, server authority, reward contents or emulator semantics follow from a class-slot address."
      ]
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("exe","methods","factory","output"):
        p.add_argument("--"+key,type=Path,required=True)
    args=p.parse_args()
    r=scan(args.exe,args.methods,args.factory)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(r,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_CLASS_SLOT_XREFS_BEGIN")
    print(json.dumps({
      "status":r["status"],
      "cases":{key:{"slot":val["nativeClassSlotRva"],
                      "candidateCount":val["nativeRIPRelativeByteCandidates"],
                      "alignedCount":val["verifiedNativeInstructions"],
                      "ownerFrequency":val["originalExactTypeOwnerFrequency"],
                      "witnesses":val["verifiedXrefs"][:50]}
                for key,val in r["allFactoryCases"].items() if int(key) in TARGET_CASES}
    },indent=2,ensure_ascii=False))
    print("ORIGINAL_CLASS_SLOT_XREFS_END")

if __name__=="__main__":main()
