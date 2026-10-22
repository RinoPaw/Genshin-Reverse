#!/usr/bin/env python3
"""Original Global 7.1 CmdId 27685 native consumer method examination.

Inputs: exact original exe + original-metadata-derived handler-parameter audit.
The source-level semantic name SceneEntityAppearNotify is an AstaPS hypothesis.
Never convert a native method's English name (OnAccept) to packet direction
without an original call graph/dispatcher.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

EXPECTED={
    190070:("LCMBPJMEHMF","NKBEBHNPJAN",0xE478770),
    190137:("LCMBPJMEHMF","GOENLHBBGDO",0xE479220),
    190172:("JLDCJCKHJEM","FDABDLGEGOI",0xFCDF4B0),
    190174:("JLDCJCKHJEM","OnAccept",0xFCDF5D0),
}
TARGET=27685
SIZE=0x580
FIRST=110
MAX_EDGE=80


def verify_hits(source:dict)->list[dict]:
    if source["sample"]!=PROFILE_71.identity or source["exe_sha256"]!=PROFILE_71.exe_sha256:
        raise ValueError("untrusted original 7.1 client source")
    if source["metadata_sha256"]!=PROFILE_71.metadata_sha256 or not source["control_validation_passed"]:
        raise ValueError("original native protocol handler parameter controls failed")
    row=[x for x in source["rows"] if x["cmd_id"]==TARGET]
    if len(row)!=1 or row[0]["type_name"]!="KIIKIELOHOG":
        raise ValueError("original native packet identity mismatch")
    matches={int(q["method_index"]):q for q in row[0]["all_hits"] if q["owner_type"]!="KIIKIELOHOG"}
    if set(matches)!=set(EXPECTED) or row[0]["known_handler_owner_hit_count"]!=0:
        raise ValueError("original native cross-owner parameter references changed")
    for index,(owner,name,rva) in EXPECTED.items():
        x=matches[index]
        if (x["owner_type"],x["method_name"],int(x["method_rva"],16),
            x["parameter_ordinal"])!=(owner,name,rva,0):
            raise ValueError(f"original native method reference changed: {index}")
    return [matches[index] for index in EXPECTED]


def code_at(pe:PEImage, rva:int)->dict:
    raw=pe.read_rva(rva,SIZE)
    if len(raw)!=SIZE:raise ValueError("unreadable original executable method region")
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    decoded=[]
    for inst in md.disasm(raw,pe.image_base+rva):
        item={
            "rva":f"0x{inst.address-pe.image_base:X}",
            "mnemonic":inst.mnemonic,"operands":inst.op_str,
            "bytes":bytes(inst.bytes).hex(),
        }
        decoded.append(item)
        if len(decoded)>=FIRST:break
        if inst.mnemonic=="ret":break
    calls=[x for x in decoded if x["mnemonic"] in ("call","jmp")]
    mem=[x for x in decoded if "[rcx + 0x" in x["operands"]
                              or "[rdx + 0x" in x["operands"]
                              or "[rsi + 0x" in x["operands"]]
    return {
        "methodRva":f"0x{rva:X}",
        "originalBytePrefixSha256":hashlib.sha256(raw).hexdigest(),
        "disassembledInstructionCount":len(decoded),
        "firstInstructionSnapshots":decoded[:60],
        "directControlEdges":calls[:MAX_EDGE],
        "nativeMemberAccessSamples":mem[:30],
        "wholeMethodVerified":False,
        "methodSemanticUnresolved":True,
    }


def analyze(exe:Path, source:dict)->dict:
    references=verify_hits(source)
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 game client")
    with PEImage(exe) as pe:
        data={str(k):code_at(pe,x[2]) for k,x in EXPECTED.items()}
    return {
        "schemaVersion":1,
        "status":"EXACT_71_CMD27685_FOUR_ORIGINAL_NATIVE_CONSUMER_METHODS__ENTITY_LEVEL_UNRESOLVED",
        "originalExeSha256":PROFILE_71.exe_sha256,
        "originalMetadataSha256":PROFILE_71.metadata_sha256,
        "verifiedNativeCmdId":TARGET,
        "verifiedNativeTypeName":"KIIKIELOHOG",
        "independentOriginalHandlerControls":source["control_validation"],
        "originalRuntimeTypeIndices":next(q["runtime_type_indices"] for q in source["rows"] if q["cmd_id"]==TARGET),
        "originalParameterReferences":references,
        "methodSources":data,
        "limitations":[
            "An OnAccept method accepting this message does not alone prove S2C direction or the SceneEntityAppearNotify semantic name.",
            "Bounded native opcode prefixes are source-scoped and not complete methods; negative results cannot exclude a field consumer later in the method.",
            "No original SceneEntityInfo.PropPair, PROP_LEVEL, 4001, scene object instance level, chest-specific reward level, grade or type was proved.",
            "No original client or server game data is committed.",
        ],
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe",required=True,type=Path)
    p.add_argument("--handler-audit",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    d=analyze(a.exe,json.loads(a.handler_audit.read_text(encoding="utf-8")))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(d,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    for mid,info in d["methodSources"].items():
        print("ORIGINAL_METHOD",mid,"RVA",info["methodRva"],
              "DIRECT_EDGES",len(info["directControlEdges"]),
              "FIRST",info["firstInstructionSnapshots"][:15])


if __name__=="__main__":main()
