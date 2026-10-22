#!/usr/bin/env python3
"""Original 7.1 JLDCJCKHJEM genericinst field source probe.

Inspect exact official native type-array bytes for owner typeDef 24767,
field type index 484299. Bound a comparison against the original
KIIKIELOHOG repeated-list generic type index 547328. A genericinst raw
low word is not a proven generic class index, and non-file-backed pointer
data must stay UNVERIFIED.
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
from genshinre.typearray import decode_type_entry, ENTRY_SIZE, is_valid_type_entry

FIELDS_BLOB="ae01d117f4d884e891a95d529a15302a68715b04"
TYPES={
 "collectorGenericinst":(24767,"JLDCJCKHJEM","AFGKAIPDLOH",484299),
 "messageRepeatedGenericinst":(65670,"KIIKIELOHOG","GEPFILACKKP",547328),
}
MAX_BACKED_BYTES=0x20


def git_blob(path:Path)->str:
    h=hashlib.sha1()
    h.update(f"blob {path.stat().st_size}\0".encode("ascii"))
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()


def scan_fields(fields:Path)->dict:
    if git_blob(fields)!=FIELDS_BLOB:
        raise ValueError("native original fields.csv SHA-1 mismatch")
    result={}
    with fields.open(encoding="utf-8-sig",newline="") as stream:
        for row in csv.DictReader(stream):
            for label,(owner_i,owner_name,token,type_i) in TYPES.items():
                if row["type_definition_index"]==str(owner_i) and row["field_name"]==token:
                    if label in result:raise ValueError("original duplicate genericinst field")
                    if (row["type_name"],int(row["field_type_index"]),row["field_type"])!=(
                        owner_name,type_i,"kind_0x15"):
                        raise ValueError("original genericinst metadata mismatch")
                    result[label]={"fieldName":token,"ownerType":owner_name,
                                  "ownerTypeDefinitionIndex":owner_i,
                                  "originalRuntimeTypeIndex":type_i}
    if set(result)!=set(TYPES):
        raise ValueError("original genericinst field owner missing")
    return result


def read_backed(pe:PEImage,va:int,n:int)->bytes:
    if not (pe.image_base<=va and 0<n<=MAX_BACKED_BYTES):
        return b""
    b=pe.read_rva(va-pe.image_base,n)
    return b if len(b)==n else b""


def inspect(exe:Path,fields:Path)->dict:
    require_sha256(exe,PROFILE_71.exe_sha256,label="official original Global 7.1 EXE")
    members=scan_fields(fields)
    with PEImage(exe) as pe:
        pt=pe.read_rva(PROFILE_71.type_array_pointer_rva,8)
        if len(pt)!=8:raise ValueError("original Il2CppType array pointer unreadable")
        base_va=int.from_bytes(pt,"little")
        if not read_backed(pe,base_va,16):
            raise ValueError("exact original type array pointer not file backed")
        for name,owner in members.items():
            idx=owner["originalRuntimeTypeIndex"]
            if not 0<=idx<PROFILE_71.runtime_type_count:
                raise ValueError("runtime Il2CppType index out of exact range")
            entry=read_backed(pe,base_va+idx*ENTRY_SIZE,ENTRY_SIZE)
            if not is_valid_type_entry(entry) or entry[0x0A]!=0x15:
                raise ValueError("exact original genericinst native kind changed")
            value=decode_type_entry(entry)
            data_u64=int.from_bytes(entry[:8],"little")
            candidate=read_backed(pe,data_u64,MAX_BACKED_BYTES)
            owner.update({
                "actualNativeKind":value["kind_name"],
                "originalNativeTypeEntryRva":f"0x{base_va-pe.image_base+idx*ENTRY_SIZE:X}",
                "originalNativeTypeEntryHex":entry.hex(),
                "nativeTypeDataLowU32":f"0x{value['data_u32']:X}",
                "rawDataU64":f"0x{data_u64:X}",
                "rawDataPointerFileBacked":bool(candidate),
                "rawDataCandidateBytesHex":candidate.hex() if candidate else None,
                "genericClassIndexVerified":False,
                "genericKeyTypeVerified":False,
                "genericValueTypeVerified":False,
            })
    return {
      "schemaVersion":1,
      "status":"EXACT_7_1_CMD27685_COLLECTOR_GENERICINST_TYPE_ARRAY_BYTES__GENERIC_ARGS_UNVERIFIED",
      "originalExeSha256":PROFILE_71.exe_sha256,
      "originalFieldsGitBlob":FIELDS_BLOB,
      "originalIl2CppTypeArrayPointerSourceRva":f"0x{PROFILE_71.type_array_pointer_rva:X}",
      "fields":members,
      "nativeGenericFieldAtCollectorPlus0x28FromFactory":True,
      "factoryBindingEvidence":"https://github.com/RinoPaw/Genshin-Reverse/actions/runs/39703359133",
      "limits":[
          "Native type-array kind genericinst and raw data bits are exact original bytes. Their low32 value is not a verified GenericClass array index.",
          "A file-backed raw Il2CppType.data pointer can be investigated structurally only after validating a known-positive native generic registration layout.",
          "The factory binds its second genericinst parameter to object +0x28; generic key/value type names and any field2 entity-id/level meaning remain unresolved.",
          "No reward amounts, chest grading semantics, scene Lua placement, drop tables, probabilities or contents are investigated."
      ],
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe",required=True,type=Path)
    p.add_argument("--fields",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    report=inspect(a.exe,a.fields)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps(report,indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
