#!/usr/bin/env python3
"""Trace exact original 7.1 Cmd27685 element's direct nested IL2CPP field types.

Type identities and member types are recovered only from original-client
generated metadata with two independent Git blob source guards. Same-type
membership, float components, and native read operations are observations,
not position, rotation, Gadget or chest semantic names.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256

FIELDS_BLOB = "ae01d117f4d884e891a95d529a15302a68715b04"
METHODS_BLOB = "a9c106a7fdd5fe97ad204d6f4641c1e2c8d5433a"
ELEMENT = "KFOLLNPEMHH"
ELEMENT_INDEX = 85506
REPEATED_TYPE = "HCDGGIDOEFA"
REPEATED_COUNT = 5
READER_TOKEN = "NLGBJEEJDLG"
READER_MAX_BYTES = 0x1600
MEMBER_CAP = 256


def git_blob(path: Path) -> str:
    digest = hashlib.sha1()
    digest.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def nested_type_names(element_fields: list[dict]) -> list[str]:
    assert len(element_fields) == 27
    if sum(f["originalType"] == REPEATED_TYPE for f in element_fields) != REPEATED_COUNT:
        raise ValueError("original nested type multiplicity drift")
    return sorted(set(f["originalType"] for f in element_fields)
                  - {"kind_0x15", "object", "string", "uint32"})


def member_census(types: Path, fields: Path, methods: Path, source_report: dict) -> dict:
    if git_blob(fields) != FIELDS_BLOB or git_blob(methods) != METHODS_BLOB:
        raise ValueError("original Global 7.1 fields/methods metadata source changed")
    if (source_report["originalExeSha256"] != PROFILE_71.exe_sha256
            or source_report["elementTypeDefinitionIndex"] != ELEMENT_INDEX
            or len(source_report["metadata"]["elementFields"]) != 27):
        raise ValueError("source authenticated Cmd27685 element report changed")
    originals = source_report["metadata"]["elementFields"]
    names = nested_type_names(originals)
    all_wanted = set(names + [ELEMENT])
    types_by_name = {}
    with types.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            name = row["type_name"]
            if name in all_wanted:
                types_by_name.setdefault(name, []).append(row)
    for name in all_wanted:
        if len(types_by_name.get(name, [])) != 1:
            raise ValueError(f"original type name not uniquely identified: {name}")
    type_by_index = {int(rows[0]["type_definition_index"]):name
                     for name, rows in types_by_name.items()}
    if int(types_by_name[ELEMENT][0]["type_definition_index"]) != ELEMENT_INDEX:
        raise ValueError("original element type definition identity changed")
    result = {
        name: {
            "typeDefinitionIndex": int(rows[0]["type_definition_index"]),
            "parentOriginalType": rows[0].get("parent_type"),
            "fields": [], "methods": [],
        }
        for name, rows in sorted(types_by_name.items())
    }
    for name, path in (("fields", fields), ("methods", methods)):
        with path.open(encoding="utf-8-sig", newline="") as stream:
            for row in csv.DictReader(stream):
                try: index = int(row["type_definition_index"])
                except (ValueError, KeyError) as e: raise ValueError("bad original metadata index") from e
                owner = type_by_index.get(index)
                if owner is None: continue
                if row["type_name"] != owner:
                    raise ValueError("original metadata class owner inconsistent")
                out = result[owner][name]
                if len(out) >= MEMBER_CAP:
                    raise ValueError("original metadata class member cap exceeded")
                if name == "fields":
                    out.append({
                        "index": int(row["field_index"]),
                        "token": row["field_name"],
                        "originalType": row["field_type"],
                        "runtimeTypeIndex": int(row["field_type_index"]),
                        "offset": row.get("offset", ""),
                    })
                else:
                    out.append({
                        "index": int(row["method_index"]),
                        "name": row["method_name"],
                        "rva": row.get("rva") or "",
                        "parameters": row.get("parameter_types", ""),
                    })
    observed = result[ELEMENT]["fields"]
    expected = [(x["originalFieldIndex"], x["originalObfuscatedToken"],
                 x["originalType"], x["originalRuntimeTypeIndex"])
                for x in originals]
    actual = [(x["index"], x["token"], x["originalType"], x["runtimeTypeIndex"])
              for x in observed]
    if observed != sorted(observed, key=lambda x:x["index"]) or expected != actual:
        raise ValueError("source matched exact 27 original element fields incorrectly")
    for name in names:
        obj = result[name]
        obj["fieldTypeHistogram"] = dict(sorted(Counter(
            r["originalType"] for r in obj["fields"]).items()))
        obj["declaredFloat32FieldCount"] = obj["fieldTypeHistogram"].get("float32", 0)
        obj["allDeclaredFieldsAreFloat32"] = bool(obj["fields"]) and all(
            f["originalType"] == "float32" for f in obj["fields"])
    return {"elementOwner":ELEMENT, "elementTypeDef":ELEMENT_INDEX,
            "distinctDirectNestedTypes":names,
            "sourceNativeTypes":result,
            "repeatedNestedType":REPEATED_TYPE,
            "repeatedNestedFieldTokens":[f["originalObfuscatedToken"]
                for f in originals if f["originalType"] == REPEATED_TYPE]}


def inspect_repeated_reader(exe:Path, census:dict) -> dict:
    require_sha256(exe, PROFILE_71.exe_sha256, label="original Global 7.1 EXE")
    proto = census["sourceNativeTypes"][REPEATED_TYPE]
    target = [m for m in proto["methods"] if m["name"] == READER_TOKEN and m["rva"]]
    if len(target) != 1:
        return {"originalReaderMethodUniquelyIdentified":False,
                "candidateReaderMethods":target,"runtimeSchemaProven":False}
    rva = int(target[0]["rva"], 0)
    if rva <= 0: raise ValueError("invalid original nested reader RVA")
    with PEImage(exe) as pe:
        data = pe.read_rva(rva,READER_MAX_BYTES)
        if len(data) != READER_MAX_BYTES:
            raise ValueError("unbacked original nested reader bytes")
        from capstone import Cs,CS_ARCH_X86,CS_MODE_64
        decoder = Cs(CS_ARCH_X86,CS_MODE_64)
        instructions = []
        for ins in decoder.disasm(data,pe.image_base+rva):
            row = {"rva":f"0x{ins.address-pe.image_base:X}",
                   "mnemonic":ins.mnemonic,"operands":ins.op_str,
                   "opcode":bytes(ins.bytes).hex()}
            instructions.append(row)
            # First RET is not proof of complete method, so retain scan boundary.
    if not instructions: raise ValueError("native nested reader unavailable")
    branches = [x for x in instructions if x["mnemonic"] in ("cmp","movss","movsd","cvtsi2ss","call")
                and len(x["operands"]) <= 120]
    return {
        "originalReaderMethodUniquelyIdentified":True,
        "readerMethodIndex":target[0]["index"],
        "readerMethodRva":f"0x{rva:X}",
        "readWindowBytes":len(data),
        "readWindowSha256":hashlib.sha256(data).hexdigest(),
        "decodedInstructionCount":len(instructions),
        "firstInstructions":instructions[:25],
        "candidateCompareAndFloatOperations":branches[:180],
        "candidateCompareAndFloatOperationCount":len(branches),
        "sourceWindowEntireMethodProven":False,
        "runtimeSchemaProven":False,
    }


def investigate(types:Path,fields:Path,methods:Path,prior:Path,exe:Path) -> dict:
    previous = json.loads(prior.read_text(encoding="utf-8"))
    census = member_census(types,fields,methods,previous)
    reader = inspect_repeated_reader(exe,census)
    return {
        "schemaVersion":1,
        "status":"ORIGINAL_GLOBAL_7_1_SCENE_ELEMENT_NESTED_TYPE_PROBE__POSITION_AND_SERVER_AUTHORITY_UNPROVEN",
        "originalClient":PROFILE_71.identity,
        "originalExeSha256":PROFILE_71.exe_sha256,
        "metadataFieldGitBlob":FIELDS_BLOB,
        "metadataMethodGitBlob":METHODS_BLOB,
        "previousSourceArtifactId":previous["evidence"]["artifactId"],
        "typeCensus":census,
        "repeatedNestedTypeReader":reader,
        "conclusions":{
            "directNestedFieldTypeProven":True,
            "coordinateSemanticProven":False,
            "rotationSemanticProven":False,
            "gadgetInstanceSemanticProven":False,
            "originalServerPacketDirectionProven":False,
            "clientStaticChestPlacementProven":False,
        },
        "limits":[
            "Original IL2CPP type/field/method identities are native metadata; repeated nested types do not prove a gameplay Vector or location.",
            "Native disassembly is bounded without claiming a complete method control-flow graph.",
            "A float-like field type would be structural evidence only, not proof of scene coordinates.",
            "No historical private-server Lua, public protocol labels or custom reward semantics were used.",
        ],
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("types","fields","methods","prior","exe","output"):
        p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args()
    report=investigate(a.types,a.fields,a.methods,a.prior,a.exe)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    summary={
        "status":report["status"],
        "names":report["typeCensus"]["distinctDirectNestedTypes"],
        "members":{k:{"fieldTypes":v["fieldTypeHistogram"],"fieldCount":len(v["fields"])}
                   for k,v in report["typeCensus"]["sourceNativeTypes"].items()
                   if "fieldTypeHistogram" in v},
        "repeatedNativeReader":report["repeatedNestedTypeReader"],
    }
    print("ORIGINAL_NESTED_OWNER_BEGIN")
    print(json.dumps(summary,indent=2,ensure_ascii=False))
    print("ORIGINAL_NESTED_OWNER_END")


if __name__=="__main__":
    main()
