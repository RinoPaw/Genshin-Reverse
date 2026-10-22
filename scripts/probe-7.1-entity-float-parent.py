#!/usr/bin/env python3
"""Pin and inspect original Global 7.1 native parent/child entity parser paths.

Input identity is checked against the exact official Global 7.1 EXE and the
already source-authenticated metadata reports. A child field's class type
is verified from original metadata; a native pointer at a nearby RVA does
not prove that field's runtime object identity without a type/field link.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

PARENT_RVA=0xB43A2A0
PARENT_SIZE=0xCD0
PARENT_SHA256="b9daf495a99150725dcadff1d6ba717e9a6edf1461b764ebd13b7f3905eb0c9e"
CHILD_RVA=0x11B25D70
CHILD_SIZE=0x1600
CHILD_SHA256="f9b555f094537c2660d50eddb71cf38629df5ba47fbd310071a0d0da941ddb32"
PARENT_TYPE="KFOLLNPEMHH"
CHILD_TYPE="ABOOLMJBDKE"
FIELD_TOKEN="DLOEKFLGJCG"
ELEMENT_FIELD_INDEX=423371
KNOWN_WIRE2_COMPARE=0xB43A328
KNOWN_WIRE2_STORE=0xB43A342
FLOAT_STORES={
  0x11B25DD4:"dword ptr [rdi + 0x20], xmm0",
  0x11B25E26:"dword ptr [rdi + 0x1c], xmm0",
  0x11B25EA8:"dword ptr [rdi + 0x18], xmm0",
}
MAX_CONTEXT_ROWS=1000

def decode(md, raw, base):
    return [{"rva":f"0x{ins.address-base:X}",
             "mnemonic":ins.mnemonic,
             "operands":ins.op_str,
             "opcode":bytes(ins.bytes).hex()}
            for ins in md.disasm(raw,base)]

def verify_priors(element:dict,nested:dict)->dict:
    if element["originalExeSha256"]!=PROFILE_71.exe_sha256 or nested["originalExeSha256"]!=PROFILE_71.exe_sha256:
        raise ValueError("original native source SHA identity drift")
    if element["elementTypeDefinitionIndex"]!=85506 or element["elementTypeObfuscatedName"]!=PARENT_TYPE:
        raise ValueError("wrong original entity-element native class")
    found=[r for r in element["metadata"]["elementFields"] if r["originalFieldIndex"]==ELEMENT_FIELD_INDEX]
    if len(found)!=1 or found[0]["originalObfuscatedToken"]!=FIELD_TOKEN or found[0]["originalType"]!=CHILD_TYPE:
        raise ValueError("native typed child-field record changed")
    if nested["typeCensus"]["sourceNativeTypes"][CHILD_TYPE]["typeDefinitionIndex"]!=47833:
        raise ValueError("native child type definition identity drift")
    if nested["floatNestedTypeReaders"][CHILD_TYPE]["readerMethodRva"]!=f"0x{CHILD_RVA:X}":
        raise ValueError("wrong independently authenticated child reader")
    return found[0]

def context(rows,index,before=5,after=9):
    return rows[max(index-before,0):index+after+1]

def probe(exe:Path,element_path:Path,nested_path:Path)->dict:
    element=json.loads(element_path.read_text(encoding="utf-8"))
    nested=json.loads(nested_path.read_text(encoding="utf-8"))
    child_field=verify_priors(element,nested)
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 executable")
    with PEImage(exe) as pe:
        from capstone import Cs,CS_ARCH_X86,CS_MODE_64
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        raw_parent=pe.read_rva(PARENT_RVA,PARENT_SIZE)
        raw_child=pe.read_rva(CHILD_RVA,CHILD_SIZE)
        if len(raw_parent)!=PARENT_SIZE or len(raw_child)!=CHILD_SIZE:
            raise ValueError("original 7.1 native function source is not file-backed")
        if hashlib.sha256(raw_parent).hexdigest()!=PARENT_SHA256 or hashlib.sha256(raw_child).hexdigest()!=CHILD_SHA256:
            raise ValueError("original 7.1 native parent/child source hash changed")
        parent=decode(md,raw_parent,pe.image_base+PARENT_RVA)
        child=decode(md,raw_child,pe.image_base+CHILD_RVA)
    parent_by={int(x["rva"],16):x for x in parent}
    child_by={int(x["rva"],16):x for x in child}
    if parent_by[KNOWN_WIRE2_COMPARE]["operands"]!="eax, 0x10" or parent_by[KNOWN_WIRE2_STORE]["operands"]!="dword ptr [r12 + 0x98], eax":
        raise ValueError("original parent verified field2 control changed")
    for address,expected in FLOAT_STORES.items():
        if child_by[address]["mnemonic"]!="movss" or child_by[address]["operands"]!=expected:
            raise ValueError("original child three-float writer changed")
    parent_access=[]
    for i,row in enumerate(parent):
        op=row["operands"]
        # Do not equate a register/offset load with the typed field unless
        # a verified class/field owner edge also supplies that relationship.
        if re.search(r"\[(?:r12|rdi|rbx|r13|r14) \+ 0x[0-9a-f]+\]",op):
            if len(parent_access)>=MAX_CONTEXT_ROWS: raise ValueError("unbounded source pointer access")
            parent_access.append({"at":row,"context":context(parent,i,3,5)})
    child_calls={0x11B25D60:"native-child-ctor",CHILD_RVA:"native-child-reader",0x11B252C0:"native-child-CopyFrom"}
    direct_calls=[]
    for i,row in enumerate(parent):
        if row["mnemonic"]!="call": continue
        target=int(row["operands"],16) if re.fullmatch(r"0x[0-9a-f]+",row["operands"]) else None
        if target is None: continue
        rva_target=target-0x140000000 if target>=0x140000000 else target
        direct_calls.append({"rva":row["rva"],"targetRva":f"0x{rva_target:X}",
                             "isDirectChildReaderCall":rva_target==CHILD_RVA,
                             "isDirectChildConstructorCall":rva_target==0x11B25D60,
                             "context":context(parent,i,4,3)})
    # The full child reader's native instructions have been source-pinned;
    # only the relevant three stores and surrounding branches are retained.
    child_float_context=[{"storeRva":f"0x{at:X}","context":context(child,next(i for i,x in enumerate(child) if int(x["rva"],16)==at),16,6)}
                         for at in FLOAT_STORES]
    typed_offsets=[int(x["rva"],16) for x in parent if x["mnemonic"]=="mov" and re.search(r"qword ptr \[r12 \+ 0x[0-9a-f]+\]",x["operands"])]
    return {
       "schemaVersion":1,
       "status":"ORIGINAL_GLOBAL_7_1_ENTITY_ELEMENT_FLOAT_CHILD_PARENT_NATIVE_BRANCHES__CHILD_FIELD_OFFSET_UNPROVEN",
       "originalExeSha256":PROFILE_71.exe_sha256,
       "originalMetadataSha256":PROFILE_71.metadata_sha256,
       "parent":{"obfuscatedType":PARENT_TYPE,"readerRva":f"0x{PARENT_RVA:X}",
          "windowSha256":PARENT_SHA256,"decodedInstructionCount":len(parent),
          "rawParentPointerAccessSites":parent_access,
          "directCallSites":direct_calls,
          "pointerReadWitnessRvas":[f"0x{x:X}" for x in typed_offsets]},
       "child":{"obfuscatedType":CHILD_TYPE,"typeDefinitionIndex":47833,
          "readerRva":f"0x{CHILD_RVA:X}","readerWindowSha256":CHILD_SHA256,
          "originalField":child_field,
          "floatStoreContexts":child_float_context},
       "originalPacketDirectionVerified":False,
       "originalChestPlacementOwnershipVerified":False,
       "nativeFieldMemberOffsetToChildVerified":False,
       "nativeReaderDirectChildCallFound":any(x["isDirectChildReaderCall"] for x in direct_calls),
       "nativeReaderDirectChildCtorFound":any(x["isDirectChildConstructorCall"] for x in direct_calls),
       "limitations":[
         "IL2CPP metadata links DLOEKFLGJCG to ABOOLMJBDKE but does not supply the runtime object field offset.",
         "Direct native call targets might be generic protobuf helpers or constructors, not proof of the typed child assignment.",
         "The original three-float reader is not an authenticated position, rotation, scene chest or Gadget semantic source.",
       ],
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("exe","element","nested","output"):
        p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    r=probe(a.exe,a.element,a.nested)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(r,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("ORIGINAL_ENTITY_FLOAT_PARENT_BEGIN")
    print(json.dumps(r,ensure_ascii=False,indent=2))
    print("ORIGINAL_ENTITY_FLOAT_PARENT_END")

if __name__=="__main__":
    main()
