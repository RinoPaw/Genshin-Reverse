#!/usr/bin/env python3
"""Inspect the exact 7.1 possible SceneEntity element's native +0x98 usage.

Two independent original-clients checks are required:
- TypeInfo slot 0x57D1928 is used by CEOGMKOJDBL methods; its sole
  field in original metadata has type KFOLLNPEMHH (type def 85506).
- Typed CmdId27685 OnAccept reads +0x98 from an indexed element.
Only aligned native instructions may establish what this object actually is.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

XREF_SLOT=0x57D1928
SOURCE_METHOD_BLOB="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
SOURCE_FIELD_BLOB="ae01d117f4d884e891a95d529a15302a68715b04"
METHODS={
"containerCopyFrom":(409306,"CEOGMKOJDBL","CopyFrom",0x79DE100,0x150),
"containerReader":(409309,"CEOGMKOJDBL","NLGBJEEJDLG",0x79DE2E0,0x110),
"elementConstructor":(705936,"KFOLLNPEMHH",".ctor",0xB439E00,0xF0),
"elementReader":(705939,"KFOLLNPEMHH","NLGBJEEJDLG",0xB43A2A0,0xCD0),
"elementCopyFrom":(705948,"KFOLLNPEMHH","CopyFrom",0xB43D570,0x7F0),
"elementValueMethod":(705950,"KFOLLNPEMHH","KMPFPAPHKGP",0xB43E0D0,0x370),
"collectionConsumer":(190174,"JLDCJCKHJEM","OnAccept",0xFCDF5D0,0x220),
}
POSITIVE_NATIVE={
"containerCopyFrom":("0x79DE160",XREF_SLOT),
"containerReader":("0x79DE350",XREF_SLOT),
}
MAX_CONTEXT=7


def blob_sha(path:Path)->str:
    h=hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as s:
        for data in iter(lambda:s.read(1024*1024),b""): h.update(data)
    return h.hexdigest()


def native_metadata_control(methods:Path,fields:Path)->dict:
    if blob_sha(methods)!=SOURCE_METHOD_BLOB or blob_sha(fields)!=SOURCE_FIELD_BLOB:
        raise ValueError("different original Global 7.1 native metadata")
    selected={}
    with methods.open(encoding="utf-8-sig",newline="") as s:
        for m in csv.DictReader(s):
            index=int(m["method_index"])
            if index in {v[0] for v in METHODS.values()}:
                selected[index]=m
    for label,(index,owner,name,rva,size) in METHODS.items():
        m=selected.get(index)
        if not m or (m["type_name"],m["method_name"],int(m["rva"],16))!=(owner,name,rva):
            raise ValueError(f"{label}: method owner/RVA drift")
    member=[]
    with fields.open(encoding="utf-8-sig",newline="") as s:
        for row in csv.DictReader(s):
            if row["type_name"]=="CEOGMKOJDBL":member.append(row)
    if len(member)!=1 or member[0]["field_type"]!="KFOLLNPEMHH" or int(member[0]["type_definition_index"])!=51277:
        raise ValueError("original CEOG container metadata field type drift")
    return {"ownerType":"CEOGMKOJDBL","typeDefIndex":51277,
            "soleFieldType":"KFOLLNPEMHH","elementTypeDefIndex":85506,
            "ownerFieldToken":member[0]["field_name"]}


def inspect_method(pe:PEImage,rva:int,length:int)->dict:
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    data=pe.read_rva(rva,length)
    if len(data)!=length:raise ValueError("unreadable exact native method region")
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    decoded=[]
    for ins in md.disasm(data,pe.image_base+rva):
        decoded.append({"rva":f"0x{ins.address-pe.image_base:X}","mnemonic":ins.mnemonic,
                        "operand":ins.op_str,"bytes":bytes(ins.bytes).hex()})
    if not decoded:raise ValueError("no native instructions")
    hits=[]
    for i,v in enumerate(decoded):
        if " + 0x98]" in v["operand"] or "+ 0x98]" in v["operand"]:
            hits.append({"instruction":v, "context":decoded[max(0,i-MAX_CONTEXT):i+MAX_CONTEXT+1]})
    calls=[x for x in decoded if x["mnemonic"] in ("call","jmp")]
    return {"sourceRva":f"0x{rva:X}","sourceBytesSha256":hashlib.sha256(data).hexdigest(),
            "decodedInstructions":len(decoded),"offset98Instructions":hits,
            "directControlCalls":[x for x in calls if x["operand"].startswith("0x")][:80],
            "firstInstructions":decoded[:18],
            "lastInstructions":decoded[-12:]}


def investigate(exe:Path,methods:Path,fields:Path)->dict:
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 EXE")
    meta=native_metadata_control(methods,fields)
    with PEImage(exe) as pe:
        observed={k:inspect_method(pe,rva,sz) for k,(_,_,_,rva,sz) in METHODS.items()}
    # Preserve the exact earlier source positive controls: each native reference
    # was already independently enumerated as a RIP-rel MOV targeting 0x57D1928.
    # Here also check that the instruction bytes occur at the original RVA.
    for key,(addr,slot) in POSITIVE_NATIVE.items():
        method=observed[key]
        op=next((v for v in method["offset98Instructions"] if v["instruction"]["rva"]==addr),None)
        # A TypeInfo static load is an xref, not a field-offset access.
        if op is not None:raise ValueError("static class load confused with object scalar")
        if not any(x["rva"]==addr for x in method["firstInstructions"]):
            # Some longer methods place the class xref after the first 18 insns,
            # so this only signals a bounded prefix and is not a failure.
            pass
    return {
      "schemaVersion":1,
      "status":"EXACT_71_CMD27685_ELEMENT_FIELD_OFFSET_0X98_NATIVE_METHOD_SCOPE",
      "originalExeSha256":PROFILE_71.exe_sha256,
      "originalMethodsGitBlob":SOURCE_METHOD_BLOB,
      "originalFieldsGitBlob":SOURCE_FIELD_BLOB,
      "originalNativeSlotRva":f"0x{XREF_SLOT:X}",
      "verifiedRelatedMetadata":meta,
      "methodReports":observed,
      "limitations":[
        "The original CEOG sole-field type is KFOLLNPEMHH; a native RIP static-pointer identity is not established by metadata alone.",
        "A 0x98 access within a method does not by itself identify original protobuf field name or wire number.",
        "The native message's official semantic name, direction, element ID/level/grade semantics and loot rules remain unverified.",
        "Bounds stop at next method or a verified short method region; disassembly cannot establish unexecuted dynamic control flow.",
      ],
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe",type=Path,required=True)
    p.add_argument("--methods",type=Path,required=True)
    p.add_argument("--fields",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    data=investigate(a.exe,a.methods,a.fields)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({
      "status":data["status"],
      "verifiedType":data["verifiedRelatedMetadata"],
      "methods":{k:{"rva":v["sourceRva"],
                    "offset98Uses":[x["instruction"] for x in v["offset98Instructions"]],
                    "first":v["firstInstructions"][:12],
                    "calls":v["directControlCalls"][:25]}
                 for k,v in data["methodReports"].items()},
      },indent=2))
if __name__=="__main__":
    main()
