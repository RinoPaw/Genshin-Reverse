#!/usr/bin/env python3
"""Source-pin original 7.1 array element virtual dispatch and class metadata.

The generic reader NLDEPJEOJGC.GMENPOPMKAA is source-authenticated at
0xAD23000 with a four-byte XOR count. Its indirect call site at 0xAD230BB
requires a concrete vtable target before any semantic field assignment.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path
from genshinre.callxref import _load_method_starts
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

SOURCE_SHA="6319613278adf382bf7ce513d1d875ef98b318d5f5f3bc9c423b72caebd7c0ad"
RVA=0xAD23000
SIZE=0x620
INDIRECT_RVA=0xAD230BB
METHODS_BLOB="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
FIELDS_BLOB="ae01d117f4d884e891a95d529a15302a68715b04"
OWNER="NLDEPJEOJGC"
PARENT="IJNOFJEOMBD"
PRIOR="versions/7.1.0-global/analyses/progression/world/7.1-original-scene-point-cb-one-byte-native-proof.json"


def git_blob(p:Path)->str:
    h=hashlib.sha1()
    h.update(f"blob {p.stat().st_size}\0".encode("ascii"))
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""):h.update(b)
    return h.hexdigest()


def metadata_members(p:Path,kind:str)->dict:
    if git_blob(p)!=(METHODS_BLOB if kind=="method" else FIELDS_BLOB):
        raise ValueError("source original client metadata Git blob drift")
    out={OWNER:[],PARENT:[]}
    with p.open(encoding="utf-8-sig",newline="") as f:
        for r in csv.DictReader(f):
            if r.get("type_name") not in out:continue
            row={"originalTypeName":r["type_name"],
                 "typeDefinitionIndex":int(r["type_definition_index"])}
            if kind=="method":
                row.update(index=int(r["method_index"]),name=r["method_name"],
                           rva=r.get("rva"),parameterTypes=r.get("parameter_types"),
                           returnType=r.get("return_type"))
            else:
                row.update(index=int(r["field_index"]),name=r["field_name"],
                           memberType=r["field_type"],runtimeTypeIndex=int(r["field_type_index"]))
            out[r["type_name"]].append(row)
            if len(out[r["type_name"]])>300:raise ValueError("source member bound exceeded")
    return out


def inspect(exe:Path,methods:Path,fields:Path,prior:Path)->dict:
    p=json.loads(prior.read_text(encoding="utf-8"))
    if p["originalExeSha256"]!=PROFILE_71.exe_sha256 or not p["originalNativeConditionalReadProof"]["sourceNativeHelperConsumesExactlyOneByteFor0xCB"]:
        raise ValueError("original source one-byte helper proof drift")
    starts,index=_load_method_starts(methods)
    owners=index.get(RVA,[])
    if len(owners)!=1 or (owners[0]["type_name"],owners[0]["method_name"],
                           int(owners[0]["method_index"]))!=(OWNER,"GMENPOPMKAA",514423):
        raise ValueError("source original array reader owner identity drift")
    m=metadata_members(methods,"method")
    f=metadata_members(fields,"field")
    require_sha256(exe,PROFILE_71.exe_sha256,label="original 7.1 client EXE")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    with PEImage(exe) as pe:
        data=pe.read_rva(RVA,SIZE)
        if len(data)!=SIZE or hashlib.sha256(data).hexdigest()!=SOURCE_SHA:
            raise ValueError("source original generic array method byte hash drift")
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        ins=[{"rva":f"0x{x.address-pe.image_base:X}",
              "mnemonic":x.mnemonic,"operands":x.op_str,
              "bytes":bytes(x.bytes).hex()} for x in md.disasm(data,pe.image_base+RVA)]
        at=next((i for i,x in enumerate(ins) if x["rva"]==f"0x{INDIRECT_RVA:X}"),None)
        if at is None or ins[at]["mnemonic"]!="call" or ins[at]["operands"]!="rbx":
            raise ValueError("original element indirect call anchor moved")
        if not any(x["rva"]=="0xAD23066" and x["operands"]=="ebx, 0xc14b813c" for x in ins):
            raise ValueError("original count XOR source positive control missing")
        direct=[]
        indirect=[]
        for i,x in enumerate(ins):
            if x["mnemonic"]!="call":continue
            around=ins[max(i-12,0):min(i+7,len(ins))]
            if x["operands"].startswith("0x"):
                va=int(x["operands"],16)
                target=va-pe.image_base
                direct.append({"site":x["rva"],"targetRva":f"0x{target:X}",
                  "exactOriginalOwners":[{"typeName":v["type_name"],"methodName":v["method_name"],
                   "index":int(v["method_index"])} for v in index.get(target,[])]})
            else:
                indirect.append({"site":x["rva"],"opcode":x["bytes"],
                    "operand":x["operands"],"context":around})
    return {
       "schemaVersion":1,
       "status":"EXACT_7_1_NATIVE_ARRAY_ELEMENT_INDIRECT_DISPATCH__CONCRETE_READER_UNVERIFIED",
       "originalExeSha256":PROFILE_71.exe_sha256,
       "originalMetadataSha256":PROFILE_71.metadata_sha256,
       "originalMethodsGitBlob":METHODS_BLOB,
       "originalFieldsGitBlob":FIELDS_BLOB,
       "originalNativeMethod":f"{OWNER}.GMENPOPMKAA",
       "nativeMethodRva":f"0x{RVA:X}",
       "nativeSourceSha256":SOURCE_SHA,
       "nativeMethodBytes":SIZE,
       "nativeDecodedInstructionCount":len(ins),
       "nativeElementCallRva":f"0x{INDIRECT_RVA:X}",
       "nativeElementCallContext":ins[max(0,at-42):at+16],
       "allSourceNativeDirectCalls":direct,
       "allSourceNativeIndirectCalls":indirect,
       "exactOriginalMethodClasses":m,
       "exactOriginalFieldClasses":f,
       "originalConcreteElementReaderLinked":False,
       "originalScenePointAssetLoaderLinked":False,
       "originalScenePointRowsDecoded":False,
       "originalChestPlacementOrLevelProven":False,
       "limits":[
         "An indirect call cannot be resolved from a numeric match or method declaration order.",
         "Original class/member names are obfuscated and semantic names must come from source-backed code paths.",
         "Client Scene Point root-loader binding, row consumption and chest instance coordinates remain unresolved."
       ]
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("exe","methods","fields","prior","output"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args()
    r=inspect(a.exe,a.methods,a.fields,a.prior)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(r,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("ORIGINAL_ARRAY_ELEMENT_BEGIN")
    print(json.dumps({
      "status":r["status"],"methodRva":r["nativeMethodRva"],
      "methodSha":r["nativeSourceSha256"],
      "decodedInstructionCount":r["nativeDecodedInstructionCount"],
      "elementCallContext":r["nativeElementCallContext"],
      "directCalls":r["allSourceNativeDirectCalls"],
      "indirectCalls":r["allSourceNativeIndirectCalls"],
      "methods":r["exactOriginalMethodClasses"],
      "fields":r["exactOriginalFieldClasses"]
    },ensure_ascii=False,indent=2))
    print("ORIGINAL_ARRAY_ELEMENT_END")

if __name__=="__main__":
    main()
