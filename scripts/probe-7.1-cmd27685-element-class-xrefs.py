#!/usr/bin/env python3
"""Original 7.1 CmdId 27685 element-class TypeInfo reference candidates.

RIP-relative static pointer loads are derived from original KIIKIELOHOG
constructor/static-initializer disassembly, SHA-pinned to the exact EXE.
This scan retains full reference evidence and original metadata owner labels.
Class-slot usage is NOT a proof of a concrete RepeatedField<T> argument
or the virtual type of the element accessed by OnAccept at +0x98.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.sampleidentity import require_sha256
from genshinre.xrefs import scan_rip_xrefs

ANCHORS = {
    "collectionAllocationTypeInfo": {
        "instructionRva": 0xC16BC49, "endRva": 0xC16BC50,
        "ripDisplacement": -0x69674B8, "load": "mov",
    },
    "collectionConstructorAuxiliaryTypeInfo": {
        "instructionRva": 0xC16BC58, "endRva": 0xC16BC5F,
        "ripDisplacement": -0x685EE2F, "load": "mov",
    },
    "repeatedElementStaticTypeInfo": {
        "instructionRva": 0xC16BF86, "endRva": 0xC16BF8D,
        "ripDisplacement": -0x699A665, "load": "mov",
    },
    "staticCodecAllocationTypeInfo": {
        "instructionRva": 0xC16BF96, "endRva": 0xC16BF9D,
        "ripDisplacement": -0x693EB0D, "load": "mov",
    },
}
LABELS = {"KIIKIELOHOG", "HCDGGIDOEFA", "HEOLIIGOCNH", "JLDCJCKHJEM",
          "KFOLLNPEMHH", "CEOGMKOJDBL", "JMEFLKGCMFL", "MNNMLJFAMIL",
          "POLMCKBNLDF", "IDOJBDCIAAE", "NHFPOGNBPPE"}
MAX_MEMBER_ROWS = 512
MAX_XREFS_PER_SLOT = 200000


def target_rva(entry: dict) -> int:
    return entry["endRva"] + entry["ripDisplacement"]


def check_xrefs(report: dict) -> dict:
    result = {}
    for name, anchor in ANCHORS.items():
        t = target_rva(anchor)
        rows = report["matches"].get(f"0x{t:X}", [])
        if not any(int(row["instruction_rva"], 16) == anchor["instructionRva"]
                   and row["access"] == "read" and row["mnemonic"] == anchor["load"]
                   for row in rows):
            raise ValueError(f"{name}: exact source native static-pointer positive control missing")
        if len(rows) > MAX_XREFS_PER_SLOT:
            raise ValueError(f"{name}: source code static-slot references unexpectedly broad")
        counts = Counter((m.get("type_name",""),m.get("type_definition_index",""))
                         for row in rows for m in row.get("caller_methods", [])[:1])
        counts.pop(("", ""), None)
        result[name] = {
            "sourceLoadRva": f"0x{anchor['instructionRva']:X}",
            "sourceStaticSlotRva": f"0x{t:X}",
            "mightBeSharedStaticTablePointer": name == "messageStaticFieldsTypeInfo",
            "allAlignedRipReferences": len(rows),
            "originalOwnerTypeCounts": [
                {"typeName": k[0], "typeDefinitionIndex": k[1], "xrefs": n}
                for k,n in counts.most_common(35)],
            "sampleReferenceMethods": [{
                "loadInstructionRva": x["instruction_rva"],
                "hexBytes": x["instruction_hex"],
                "access": x["access"],
                "nearestOriginalMethods": [{
                    "methodIndex": m.get("method_index"),
                    "typeName": m.get("type_name"),
                    "typeDefinitionIndex": m.get("type_definition_index"),
                    "methodName": m.get("method_name"),
                    "methodRva": m.get("rva"),
                } for m in x.get("caller_methods", [])[:3]]
            } for x in rows[:70]],
            "actualRuntimeIl2CppClassIdentityVerified": False,
        }
    return result


def member_types(methods: Path, fields: Path) -> dict:
    result={name:{"methods":[],"fields":[]} for name in LABELS}
    for path,collection,limit in ((methods,"methods",MAX_MEMBER_ROWS),(fields,"fields",MAX_MEMBER_ROWS)):
        with path.open(encoding="utf-8-sig", newline="") as stream:
            for row in csv.DictReader(stream):
                name=row.get("type_name","")
                if name not in result:continue
                if len(result[name][collection]) >= limit:
                    raise ValueError(f"unbounded original 7.1 type members {name}")
                allowed=({"method_index","method_name","rva","type_definition_index","parameter_types"}
                         if collection=="methods" else
                         {"field_index","field_name","field_type_index","field_type","type_definition_index"})
                result[name][collection].append({k:v for k,v in row.items() if k in allowed})
    return result


def run(exe:Path, methods:Path, fields:Path)->dict:
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 executable")
    wanted = [target_rva(x) for x in ANCHORS.values()]
    if len(set(wanted)) != len(wanted):
        raise ValueError("original static slots overlap")
    xref = scan_rip_xrefs(exe,wanted,window=12,methods_csv=methods,
                         max_method_body=0x10000)
    return {
        "schemaVersion":1,
        "status":"EXACT_71_CMD27685_NATIVE_ELEMENT_CLASS_XREFS__RUNTIME_IDENTITY_UNPROVEN",
        "originalExeSha256":PROFILE_71.exe_sha256,
        "originalMetadataSha256":PROFILE_71.metadata_sha256,
        "msgNativeType":"KIIKIELOHOG",
        "msgTypeDefinitionIndex":65670,
        "typeInfoSlotXrefs":check_xrefs(xref),
        "excludedSharedStaticFieldsSlotRva":"0x57831E8",
        "excludedSharedStaticFieldsReason":"This metadata static-fields global is referenced more than 200,000 times; it does not constrain the repeated element class.",
        "associatedOriginalMetadataTypes":member_types(methods,fields),
        "limitations":[
            "All pointer slots are backed by original source RIP-relative aligned instructions from native .ctor/.cctor.",
            "Class static pointer references alone do not prove TypeInfo initialization, the collection generic argument or the indexed element concrete type.",
            "Nearest method-owner attribution is bounded and may include adjacent methods; independently re-disassemble candidate owners before promotion.",
            "No class field offset +0x98, original scene level, reward grade, chest type or original server reward was authenticated.",
        ],
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe",required=True,type=Path)
    p.add_argument("--methods",required=True,type=Path)
    p.add_argument("--fields",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    result=run(a.exe,a.methods,a.fields)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({
        "status":result["status"],
        "typeInfoSlots":{k:{"slot":v["sourceStaticSlotRva"],
            "refCount":v["allAlignedRipReferences"],
            "ownerSample":v["originalOwnerTypeCounts"][:8],
            "methodSample":v["sampleReferenceMethods"][:10]}
            for k,v in result["typeInfoSlotXrefs"].items()},
        "originalTypes":{k:{"methods":len(v["methods"]),"fields":len(v["fields"]),
           "fieldsSample":v["fields"][:12]}
           for k,v in result["associatedOriginalMetadataTypes"].items()},
    },indent=2))
if __name__=="__main__":
    main()
