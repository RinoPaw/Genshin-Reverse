#!/usr/bin/env python3
"""Probe original Global 7.1 IL2CPP generic class registration indices.

The manager fields have exact original kind_0x15 Il2CppType entries. Their
data low words could be generic class indices. Test that hypothesis against
the ORIGINAL metadata registration, including independent Scene manager
control indices. Do not relabel low words or row readers on a partial match.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import struct

from genshinre.nativeprofile import PROFILE_71
from genshinre.pe import PEImage
from genshinre.sampleidentity import require_sha256
from genshinre.typearray import decode_type_entry, is_valid_type_entry, ENTRY_SIZE

ROOT = Path(__file__).resolve().parents[1]
target=ROOT/"tools/resolve_7_1_field_offsets.py"
spec=importlib.util.spec_from_file_location("native_field_offsets",target)
offsets=importlib.util.module_from_spec(spec)
spec.loader.exec_module(offsets)

GENERIC_INDICES = {
    "GadgetPropManagerGenericField": 0x2B581,
    "GadgetInteractManagerGenericField": 0x2A6A4,
    "SceneTagManagerGenericFieldControl": 0x35C81,
    "SceneExcelManagerGenericFieldControl": 0x28AC3,
}
COUNT_ORDER=("genericClasses", "genericInsts", "genericMethodTable",
             "types", "methodSpecs", "fieldOffsets", "typeDefinitionsSizes")


def decode_registration(data: bytes) -> dict[str,dict]:
    if len(data) != 7*16:
        raise ValueError("metadata registration pair window needs seven 16-byte entries")
    result={}
    for i,name in enumerate(COUNT_ORDER):
        count,pointer=struct.unpack_from("<QQ",data,i*16)
        result[name]={"count":count,"pointerVa":f"0x{pointer:X}"}
    return result


def read_exact(pe: PEImage, va: int, size: int) -> bytes:
    if not pe.image_base <= va or size <= 0 or size > 80:
        return b""
    return pe.read_rva(va-pe.image_base,size)


def generic_index_probe(pe: PEImage, registration: dict, index: int) -> dict:
    data=registration["genericClasses"]
    count=int(data["count"])
    result={
        "genericClassIndexCandidate":index,
        "indexWithinRegisteredCount":bool(index < count),
        "genericClassTablePointerFileBacked":False,
        "genericClassObjectFileBacked":False,
        "genericContextFileBacked":False,
        "genericArgs":[],
        "genericClassTypeIdentityProven":False,
    }
    if not 0 <= index < count:
        return result
    ptr=int(data["pointerVa"],16)
    cell=read_exact(pe,ptr+index*8,8)
    if len(cell)!=8:
        return result
    result["genericClassTablePointerFileBacked"]=True
    object_va=int.from_bytes(cell,"little")
    result["objectVaCandidate"]=f"0x{object_va:X}"
    obj=read_exact(pe,object_va,32)
    if len(obj)!=32:
        return result
    result["genericClassObjectFileBacked"]=True
    result["rawGenericClassBytes"]=obj.hex()
    typedef=struct.unpack_from("<I",obj)[0]
    inst_va=struct.unpack_from("<Q",obj,8)[0]
    result["genericClassTypeDefinitionIndexCandidate"]=typedef
    result["genericClassTypeDefinitionIndexInRange"]=typedef<PROFILE_71.type_definition_count
    result["genericClassInstVaCandidate"]=f"0x{inst_va:X}"
    context=read_exact(pe,inst_va,16)
    if len(context)!=16:
        return result
    result["genericContextFileBacked"]=True
    argc=struct.unpack_from("<I",context)[0]
    argv_va=struct.unpack_from("<Q",context,8)[0]
    result["genericArgCountCandidate"]=argc
    result["genericArgArrayVaCandidate"]=f"0x{argv_va:X}"
    if argc>8:
        return result
    args=read_exact(pe,argv_va,argc*8) if argc else b""
    if len(args)!=argc*8:
        return result
    type_array=pe.read_rva(PROFILE_71.type_array_pointer_rva,8)
    type_array_va=int.from_bytes(type_array,"little") if len(type_array)==8 else 0
    for i in range(argc):
        type_va=struct.unpack_from("<Q",args,i*8)[0]
        raw=read_exact(pe,type_va,16)
        result_arg={
            "ordinal":i, "typeVaCandidate":f"0x{type_va:X}",
            "typeFileBacked":len(raw)==16
        }
        if len(raw)==16:
            item=decode_type_entry(raw)
            result_arg["kindName"]=item["kind_name"]
            result_arg["kind"]=f"0x{item['kind']:02X}"
            result_arg["rawNativeType"]=raw.hex()
            if type_array_va<=type_va:
                delta=type_va-type_array_va
                if delta%ENTRY_SIZE==0 and delta//ENTRY_SIZE<PROFILE_71.runtime_type_count:
                    result_arg["typeIndexInCanonicalArray"]=delta//ENTRY_SIZE
            if item["kind"] in (0x11,0x12) and item["data_u32"]<PROFILE_71.type_definition_count:
                result_arg["typeDefinitionIndexCandidate"]=item["data_u32"]
        result["genericArgs"].append(result_arg)
    result["genericClassTypeIdentityProven"] = (
        typedef<PROFILE_71.type_definition_count
        and 0<argc<=8 and all(x["typeFileBacked"] for x in result["genericArgs"]))
    return result


def count_marker_diagnostics(pe: PEImage) -> dict:
    """Find file-backed non-code count/pointer pairs without assuming layout."""
    observed={}
    for label, target in (("typeDefinitions", PROFILE_71.type_definition_count),
                          ("runtimeTypes", PROFILE_71.runtime_type_count)):
        matches=[]
        signature=struct.pack("<Q", target)
        for section in pe.sections:
            if section.characteristics & 0x20000000:
                continue
            blob=pe.read_rva(section.virtual_address, section.raw_size)
            search_at=0
            while (hit:=blob.find(signature,search_at))>=0:
                search_at=hit+1
                rva=section.virtual_address+hit
                if rva%8 or hit+16>len(blob):
                    continue
                va=struct.unpack_from("<Q",blob,hit+8)[0]
                linked=read_exact(pe,va,8)
                matches.append({
                    "countRva":f"0x{rva:X}","pointerVaCandidate":f"0x{va:X}",
                    "pointerFileBacked":len(linked)==8,
                    "section":section.name,
                })
                if len(matches)>256:
                    raise ValueError("unbounded original native count pair population")
        observed[label]={"searchedCount":target,"alignedQwordOccurrenceCount":len(matches),
                         "candidateCountPointerPairs":matches[:40]}
    return observed


def investigate(exe: Path) -> dict:
    require_sha256(exe,PROFILE_71.exe_sha256,label="original Global 7.1 EXE")
    with PEImage(exe) as pe:
        candidates=offsets.find_registration_field_offset_tables(
            pe,PROFILE_71.type_definition_count)
        if len(candidates)>8:
            raise ValueError("unbounded original metadata registration pair candidates")
        count_hints=count_marker_diagnostics(pe)
        reports=[]
        for c in candidates:
            signature=c["signature_rva"]
            # Count order at registration base -80 to field-offset signature.
            blob=pe.read_rva(signature-5*16,7*16)
            if len(blob)!=7*16:
                continue
            reg=decode_registration(blob)
            report={"fieldOffsetsSignatureRva":f"0x{signature:X}",
                    "registeredCountsAndPointers":reg,
                    "nativeTypesCountMatchesProfile":
                        reg["types"]["count"]==PROFILE_71.runtime_type_count,
                    "genericClassIndices":{
                        name:generic_index_probe(pe,reg,value)
                        for name,value in GENERIC_INDICES.items()}}
            reports.append(report)
    return {
        "schemaVersion":1,
        "status":"EXACT_7_1_GENERIC_CLASS_REGISTRATION_ORIGINAL_SOURCE_PROBE__VTABLE_IDENTITY_UNVERIFIED",
        "exeSha256":PROFILE_71.exe_sha256,
        "originalTypeDefinitionCount":PROFILE_71.type_definition_count,
        "runtimeTypeCount":PROFILE_71.runtime_type_count,
        "testedRawOriginalManagerGenericInstLow32Values":{
            key:f"0x{value:X}" for key,value in GENERIC_INDICES.items()},
        "metadataRegistrationPairSignatureCandidateCount":len(reports),
        "countMarkerDiagnostics":count_hints,
        "metadataRegistrationCandidates":reports,
        "limitations":[
            "The standard field-offsets/type-sizes pair signature may be absent from protected 7.1 metadata registration. Zero matches is a bounded negative scan, not proof of absent native metadata.",
            "The metadata registration layout and generic index interpretation are hypotheses checked against the pinned original EXE.",
            "An in-bounds table index and a plausible generic class object need validated layout and independent native callsite binding.",
            "If candidate generic arguments are decoded, original manager field type does not alone establish the row vtable +0xF0 target.",
            "No LootCSS grade, level, native chest classification, scene instance or reward values are inferred.",
        ],
    }


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    a=parser.parse_args()
    report=investigate(a.exe)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps(report,indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
