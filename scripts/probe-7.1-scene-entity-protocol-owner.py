#!/usr/bin/env python3
"""Inspect exact Global 7.1 native CmdId 27685 owner and method code.

AstaPS 7.1 labels CmdId 27685 SceneEntityAppearNotify; current-client native
registry proves only CmdId↔obfuscated type. Recover native owner fields and
method callers, then a bounded disassembly for each owner method. No
current-client semantic promotion without independent consumer evidence.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

METHODS_SHA="a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
FIELDS_SHA="ae01d117f4d884e891a95d529a15302a68715b04"
CMD=27685
OWNER="KIIKIELOHOG"
OWNER_INDEX=65670
CMD_GETTER_RVA=0xC16BDD0
CONTROLS={9369:("DMMJNICDOHM",84249),22899:("ONKOPMILDMF",87483)}
MAX_FIELDS=128
MAX_METHODS=80
MAX_DISASM_BYTES=0x500
CODE_ONLY_INSNS=64


def git_blob(path:Path)->str:
    sha=hashlib.sha1()
    sha.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1<<20),b""):
            sha.update(block)
    return sha.hexdigest()


def require_registry(path:Path)->dict:
    targets={CMD,*CONTROLS}
    rows={}
    with path.open(encoding="utf-8-sig",newline="") as stream:
        for row in csv.DictReader(stream):
            cmd=int(row["cmd_id"])
            if cmd in targets:
                if cmd in rows:raise ValueError("duplicate original CmdId registry row")
                rows[cmd]=row
    if set(rows)!=targets:raise ValueError("original 7.1 registry controls missing")
    if (rows[CMD]["type_name"],int(rows[CMD]["type_definition_index"]),
        int(rows[CMD]["get_cmd_id_rva"],16))!=(OWNER,OWNER_INDEX,CMD_GETTER_RVA):
        raise ValueError("original target registry owner identity changed")
    for cmd,(name,idx) in CONTROLS.items():
        row=rows[cmd]
        if (row["type_name"],int(row["type_definition_index"]))!=(name,idx):
            raise ValueError(f"original registry control {cmd} changed")
    return rows


def owner_members(methods:Path,fields:Path)->dict:
    if git_blob(methods)!=METHODS_SHA or git_blob(fields)!=FIELDS_SHA:
        raise ValueError("original Global 7.1 metadata CSV SHA-1 Git blob mismatch")
    data={"methods":[],"fields":[]}
    with methods.open(encoding="utf-8-sig",newline="") as stream:
        for row in csv.DictReader(stream):
            if row["type_definition_index"]!=str(OWNER_INDEX):continue
            if row["type_name"]!=OWNER:raise ValueError("native method owner token mismatch")
            if len(data["methods"])>=MAX_METHODS:raise ValueError("unexpected method count")
            data["methods"].append({
                "methodIndex":int(row["method_index"]),
                "name":row["method_name"],
                "rva":row["rva"],
                "returnType":row.get("return_type",""),
                "parameterTypes":row.get("parameter_types",""),
                "parameterCount":row.get("parameter_count",""),
            })
    with fields.open(encoding="utf-8-sig",newline="") as stream:
        for row in csv.DictReader(stream):
            if row["type_definition_index"]!=str(OWNER_INDEX):continue
            if row["type_name"]!=OWNER:raise ValueError("native field owner token mismatch")
            if len(data["fields"])>=MAX_FIELDS:raise ValueError("unexpected field count")
            data["fields"].append({
                "index":int(row["field_index"]),
                "obfuscatedFieldName":row["field_name"],
                "runtimeTypeIndex":row.get("field_type_index"),
                "typeLabel":row.get("field_type"),
                "nativeObjectOffset":row.get("offset"),
            })
    if not data["methods"] or not data["fields"]:raise ValueError("original packet owner members absent")
    if not any(m["name"]=="AEGNNPENLNM" and int(m["rva"] or "0",0)==CMD_GETTER_RVA
               for m in data["methods"]):
        raise ValueError("original owner GetCmdId native RVA not in its metadata methods")
    return data


def inspect_native(exe:Path, methods:list[dict])->dict:
    require_sha256(exe,PROFILE_71.exe_sha256,label="Global 7.1 original client")
    with PEImage(exe) as pe:
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        out={}
        for method in methods:
            rva=int(method["rva"] or "0",0)
            if not rva:continue
            raw=pe.read_rva(rva,MAX_DISASM_BYTES)
            if len(raw)!=MAX_DISASM_BYTES:
                raise ValueError(f"unreadable original native method RVA 0x{rva:X}")
            first=[]
            for ins in md.disasm(raw,pe.image_base+rva):
                if len(first)>=CODE_ONLY_INSNS:break
                first.append({
                    "rva":f"0x{ins.address-pe.image_base:X}",
                    "mnemonic":ins.mnemonic,
                    "operands":ins.op_str,
                    "bytes":bytes(ins.bytes).hex()
                })
                if ins.mnemonic=="ret":break
            out[str(method["methodIndex"])]={
                "rva":f"0x{rva:X}",
                "sourceBytesSha256":hashlib.sha256(raw).hexdigest(),
                "firstInstructions":first,
                "boundedDecodedInstructions":len(first),
                "wholeMethodVerified":False,
            }
        get_cmd=[m for m in methods if m["name"]=="AEGNNPENLNM" and int(m["rva"] or "0",0)==CMD_GETTER_RVA]
        if len(get_cmd)!=1 or str(get_cmd[0]["methodIndex"]) not in out:
            raise ValueError("source-pinned native GetCmdId method not found")
        return out


def inspect(registry:Path,fields:Path,methods:Path,exe:Path)->dict:
    registry_rows=require_registry(registry)
    data=owner_members(methods,fields)
    native=inspect_native(exe,data["methods"])
    cmd_row=registry_rows[CMD]
    return {
        "schemaVersion":1,
        "status":"ORIGINAL_71_CMD27685_NUMERIC_TYPE_OWNER_AND_METHODS__SCENE_LEVEL_UNRESOLVED",
        "source":{
            "sample":PROFILE_71.identity,
            "exeSha256":PROFILE_71.exe_sha256,
            "metadataSha256":PROFILE_71.metadata_sha256,
            "methodsGitBlob":METHODS_SHA,"fieldsGitBlob":FIELDS_SHA,
        },
        "nativeRegistry":{
            "cmdId":CMD,"typeName":OWNER,"typeDefinitionIndex":OWNER_INDEX,
            "getCmdIdRva":f"0x{CMD_GETTER_RVA:X}",
            "registryIndex":int(cmd_row["index"]),
            "typeSlotRva":cmd_row["type_slot_rva"],
            "registryDirection":cmd_row["direction"] or "UNRESOLVED",
            "registrySemanticName":cmd_row["semantic_name"] or None,
            "status":cmd_row["status"],
        },
        "positiveControls":[{"cmdId":k,"typeName":row["type_name"],
                             "typeDefinitionIndex":int(row["type_definition_index"])}
                            for k,row in registry_rows.items() if k in CONTROLS],
        "ownerFields":data["fields"],"ownerMethods":data["methods"],
        "boundedNativeMethods":native,
        "outsideNativeHypothesis":{
            "forkAstaPSCmdId":CMD,"forkSemanticName":"SceneEntityAppearNotify",
            "forkOriginalSceneObjectLevelProven":False,
            "isOriginalNativeSemanticClaim":False,
        },
        "limits":[
            "Numeric original registry ownership and original source code are verified, but fork CmdId label is only a semantic hypothesis.",
            "This scan does not reconstruct a protobuf message field graph or identify any SceneEntityInfo, GadgetInfo or PROP_LEVEL consumer.",
            "Method disassembly snapshots stop at a bounded prefix; absence of observed instruction is not evidence of absence in the full method.",
            "A packet entity level and a Lua scene-instance reward level need independent original-client/server proof.",
            "No chest reward, chest classification, level selector or payout semantics are inferred."
        ],
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--registry",type=Path,required=True)
    p.add_argument("--fields",type=Path,required=True)
    p.add_argument("--methods",type=Path,required=True)
    p.add_argument("--exe",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    report=inspect(a.registry,a.fields,a.methods,a.exe)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({
        "status":report["status"],"originalRegistry":report["nativeRegistry"],
        "fieldCount":len(report["ownerFields"]),"fields":report["ownerFields"],
        "methodCount":len(report["ownerMethods"]),
        "methods":report["ownerMethods"],
        "nativeDisassembledCount":len(report["boundedNativeMethods"]),
    },indent=2))


if __name__=="__main__":
    main()
