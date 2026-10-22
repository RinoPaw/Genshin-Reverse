#!/usr/bin/env python3
"""Exact-sample native parser/serializer controls for imported blossom packet leads."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from genshinre.pe import PEImage
from genshinre.nativeprofile import PROFILE_71
from genshinre.sampleidentity import require_profile_exe, require_profile_metadata

ROOT=Path("versions/7.1.0-global/windows-x64")
LEAD_IDS=(112,6743,6993,7051,20484,23101,24698,29702)
PARSER_METHOD_NAMES=("NLGBJEEJDLG","NKFCABIOGLE","CopyFrom","AEGNNPENLNM","IENGFLPCLNM")
def rows(path):
    with (ROOT/path).open(encoding="utf-8-sig",newline="") as f:
        yield from csv.DictReader(f)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--exe",type=Path,required=True)
    p.add_argument("--metadata",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    exe_sha=require_profile_exe(args.exe,PROFILE_71)
    meta_sha=require_profile_metadata(args.metadata,PROFILE_71)
    registry={int(x["cmd_id"]):x for x in rows("registry/registry.csv") if int(x["cmd_id"]) in LEAD_IDS}
    owners={r["type_name"]:int(r["cmd_id"]) for r in registry.values()}
    methods=[r for r in rows("metadata/methods.csv") if r["type_name"] in owners]
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    records=[]
    with PEImage(args.exe) as pe:
        for item in methods:
            if item["method_name"] not in PARSER_METHOD_NAMES:continue
            rva=int(item["rva"],0)
            # Limit disassembly to the next candidate owner's native method where possible.
            next_method=min((int(other["rva"],0) for other in methods
                             if other["type_name"]==item["type_name"]
                             and int(other["rva"],0)>rva),default=rva+0x450)
            size=max(16,min(0x450,next_method-rva))
            code=pe.read_rva(rva,size)
            instructions=[]
            for ins in md.disasm(code,pe.image_base+rva):
                instructions.append({"rva":f"0x{ins.address-pe.image_base:X}",
                    "op":ins.mnemonic,"args":ins.op_str,"bytes":bytes(ins.bytes).hex()})
            iwords=[x for x in instructions if x["op"] in ("cmp","test","shl","shr","and","or","mov")]
            record={"cmd_id":owners[item["type_name"]],"type_name":item["type_name"],
                "method_name":item["method_name"],"method_rva":item["rva"],
                "disassembly_size":size,"disassembled":len(instructions),
                "comparisons":[x for x in instructions if x["op"] in ("cmp","test")][:55],
                "first_instructions":instructions[:90]}
            records.append(record)
            print("METHOD",record["cmd_id"],record["type_name"],record["method_name"],
                record["method_rva"],"instructions",len(instructions),"comparisons",
                " | ".join(x["args"] for x in record["comparisons"][:22]),flush=True)
            if int(record["cmd_id"]) in (112,6743,20484,29702,23101):
                for ins in instructions[:60]:
                    print("  DISASM",ins["rva"],ins["op"],ins["args"],flush=True)
    # Independently recovered original-client receiver class. These typed
    # methods are C#-style handlers for the three co-list instances and
    # associated scene/owner blossom notifications. Preserve exact bytes.
    receiver_sites={
        "shared-list-handler":(0xC78CA80,0x570),
        "handler-6743":(0xC78C930,0x150),
        "handler-20484":(0xC790C00,0x260),
        "handler-23101":(0xC78D030,0x300),
        "handler-6993":(0xC78FA10,0x120),
        "handler-24698":(0xC792020,0x260),
    }
    from genshinre.typearray import decode_type_entry, is_valid_type_entry, ENTRY_SIZE
    with PEImage(args.exe) as pe:
        pointer=pe.read_rva(PROFILE_71.type_array_pointer_rva,8)
        if len(pointer)!=8:raise ValueError("missing exact native type-array")
        arr_va=int.from_bytes(pointer,"little")
        for field_idx in (505695,526432):
            type_rva=arr_va-pe.image_base+field_idx*ENTRY_SIZE
            blob=pe.read_rva(type_rva,ENTRY_SIZE)
            if len(blob)!=ENTRY_SIZE or not is_valid_type_entry(blob):
                raise ValueError("broken exact field genericinst type")
            rawptr=int.from_bytes(blob[:8],"little")
            target=pe.read_rva(rawptr-pe.image_base,32) if rawptr>=pe.image_base else b""
            print("ORIGINAL_GENERIC_INSTANCE",field_idx,
                  "rva",f"0x{type_rva:X}","type",decode_type_entry(blob),
                  "hex",blob.hex(),"data",f"0x{rawptr:X}",
                  "data_file_backed",len(target)==32,
                  "target_hex",target.hex() if len(target)==32 else "",flush=True)
    rva_targets={0xC78CA80,0x196411F0,0xC236080,0xFAA2010,0xC78C930,0xC790C00}
    matched_methods=[]
    with (ROOT/"metadata/methods.csv").open(encoding="utf-8-sig",newline="") as f:
        for row in csv.DictReader(f):
            value=row.get("rva","")
            if value and int(value,0) in rva_targets:
                matched_methods.append(row)
    print("NATIVE_METHOD_TARGETS",json.dumps(matched_methods),flush=True)
    receiver=[]
    with PEImage(args.exe) as pe:
        for label,(rva,size) in receiver_sites.items():
            code=pe.read_rva(rva,size)
            instructions=[{"rva":f"0x{ins.address-pe.image_base:X}",
                 "op":ins.mnemonic,"args":ins.op_str,"bytes":bytes(ins.bytes).hex()}
                 for ins in md.disasm(code,pe.image_base+rva)]
            receiver.append({"label":label,"method_rva":f"0x{rva:X}",
                "window_size":size,"instructions":instructions})
            print("RECEIVER",label,"rva",f"0x{rva:X}","instructions",len(instructions),flush=True)
            for ins in instructions[:125]:
                print("  RECEIVER_DISASM",ins["rva"],ins["op"],ins["args"],flush=True)
    result={"sample":PROFILE_71.identity,"exe_sha256":exe_sha,"metadata_sha256":meta_sha,
        "source":"original Global 7.1 IL2CPP executable; no semantic opcode assertions",
        "leads":[{"cmd_id":k,"type_name":v["type_name"],
                  "type_definition_index":v["type_definition_index"],
                  "type_slot_rva":v["type_slot_rva"],"get_cmd_id_rva":v["get_cmd_id_rva"]}
                 for k,v in sorted(registry.items())],
        "methods":records,"receiver_methods":receiver}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    print("REPORT",args.output,"method_count",len(records),flush=True)
if __name__=="__main__":
    main()
