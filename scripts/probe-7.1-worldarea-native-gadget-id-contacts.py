#!/usr/bin/env python3
"""Bounded direct-byte scan for original 7.1 Gadget ID references in the
original source-verified WorldArea containing MiHoYoBinData Unity block.

IDs are the 20 exact original-client GadgetExcelConfigData rows with
native literal names SceneObj_Chest_{Default,Locked,Bramble,Frozen}_Lv{1..5}.
Binary scanning for their little-endian uint32 representation is a
HEURISTIC, not verification of placement, instance schema, level or
official server authority. Original index and independent raw scene-area
asset act as positive source identity gates.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

from genshinre.nativeprofile import PROFILE_71

ROOT=Path(__file__).resolve().parents[1]
BUNDLE_SCRIPT=ROOT/"scripts/probe-7.1-world-area-bundle-object-types.py"
spec=importlib.util.spec_from_file_location("pinned_worldarea_71",BUNDLE_SCRIPT)
bundle=importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(bundle)

ORIGINAL_GADGET_REPORT=ROOT/"versions/7.1.0-global/analyses/progression/economy/7.1-native-gadget-field-vectors.json"
CONTROL_MAGIC=(0x134A8C01,0x134A8C02,0x134A8C03,0x134A8C04,
               0x134A8C05,0x134A8C06,0x134A8C07,0x134A8C08)
MAX_EXAMPLES=28
MAX_POSITIVE_FILES=60
EXPECTED_ROWS=30599


def native_gadget_ids(path:Path=ORIGINAL_GADGET_REPORT)->dict[int,str]:
    report=json.loads(path.read_text(encoding="utf-8"))
    if (report["source"]["exeSha256"]!=PROFILE_71.exe_sha256
        or report["source"]["rawSha256"]!="a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35"
        or report["controls"]["fullDecodedRows"]!=EXPECTED_ROWS):
        raise ValueError("original client GadgetExcel row evidence drift")
    rows=report["numeric26Records"]
    by_id={r["preWrapperKeyAt0x30"]:r["literalAt0x58"] for r in rows}
    return {
        gadget_id:f"SceneObj_Chest_{style}_Lv{level}"
        for level in range(1,6)
        for offset,style in enumerate(("Default","Locked","Bramble","Frozen"),1)
        for gadget_id in [70210000+level*10+offset]
        if by_id.get(gadget_id)==f"SceneObj_Chest_{style}_Lv{level}"
    }


def scan_bytes(payload:bytes,ids:dict[int,str],controls:tuple[int,...]=CONTROL_MAGIC)->dict:
    targets={key.to_bytes(4,"little"):("native",key) for key in ids}
    for control in controls:
        raw=control.to_bytes(4,"little")
        if raw in targets:raise ValueError("diagnostic byte pattern overlaps original gadget ID")
        targets[raw]=("diagnostic",control)
    regex=re.compile(b"|".join(re.escape(k) for k in targets))
    matched={"native":Counter(),"diagnostic":Counter()}
    aligned=Counter()
    offsets={"native":[],"diagnostic":[]}
    for m in regex.finditer(payload):
        name,key=targets[m.group()]
        matched[name][key]+=1
        aligned[name]+=int(m.start()%4==0)
        if len(offsets[name])<MAX_EXAMPLES:
            offsets[name].append({"hex":f"0x{key:X}","payloadOffset":m.start(),
                                  "alignedU32":m.start()%4==0})
    return {"counts":matched,"aligned":aligned,"samples":offsets}


def examine_block(block:Path,cli_dll:Path,export:Path,original_ids:dict[int,str])->dict:
    export.mkdir(parents=True,exist_ok=True)
    subprocess.run(["dotnet",str(cli_dll),str(block),str(export),
                   "--game","GI","--types","MiHoYoBinData",
                   "--export_type","Raw","--logger_flags","Error"],check=True)
    directory=export/"MiHoYoBinData"
    scene_file=directory/bundle.SCENE3_STEM
    if not scene_file.is_file() or hashlib.sha256(scene_file.read_bytes()).hexdigest()!=bundle.SCENE3_RAW_SHA:
        raise ValueError("original native scene3 WorldArea positive control absent or changed")
    aggregate={"native":Counter(),"diagnostic":Counter()}
    file_counts=Counter()
    aligned_totals=Counter()
    files=[]
    for file in sorted(directory.glob("*.dat")):
        raw=file.read_bytes()
        if len(raw)<4:raise ValueError("original MiHoYoBinData export too short")
        # Skip four-byte Raw exporter size, no presumption of the nested record schema.
        match=scan_bytes(raw[4:],original_ids)
        file_counts["allNativeBinDataFiles"]+=1
        for key in ("native","diagnostic"):
            aggregate[key].update(match["counts"][key])
            aligned_totals[key]+=match["aligned"][key]
            if match["counts"][key]:file_counts[key+"MatchFiles"]+=1
        if match["counts"]["native"]:
            file_counts["nativeMatchFilesWithTwoDistinctIds"]+=len(match["counts"]["native"])>=2
            if len(files)<MAX_POSITIVE_FILES:
                files.append({
                    "exportedHashedName":file.name,
                    "rawSize":len(raw),
                    "rawSha256":hashlib.sha256(raw).hexdigest(),
                    "matches":{f"0x{key:X}":{"nativeName":original_ids[key],"occurrences":count}
                              for key,count in match["counts"]["native"].items()},
                    "directMatchOffsetSamples":match["samples"]["native"][:MAX_EXAMPLES],
                    "dataSemanticsVerified":False,
                })
        file_counts["totalRawExportBytes"]+=len(raw)
    if file_counts["allNativeBinDataFiles"]!=167673:
        raise ValueError("original 7.1 WorldArea block object count differs from independent export")
    if file_counts["totalRawExportBytes"]!=415672040:
        raise ValueError("original 7.1 WorldArea block export size differs from independent export")
    return {
        "schemaVersion":1,
        "status":"ORIGINAL_7_1_WORLD_AREA_BINARY_GADGET_ID_BYTE_CONTACTS__INSTANCE_SCHEMA_UNVERIFIED",
        "originalClient":PROFILE_71.identity,
        "sourceBlock":"00/24230448.blk",
        "positiveWorldAreaRawSha256":bundle.SCENE3_RAW_SHA,
        "sourceBlockSha256":"71fbe2d10404655fa20e5d612daf5fa2f2336c1d6250ae209b722c894169aff7",
        "originalGadgetDefinitionRawSha256":"a35e3f3ed04f950cb6302099d12aa71e23ece21d8fe578950347d9318f769e35",
        "nativeGadgetIdRows":[{"originalGadgetId":key,"originalLiteral":value}
                              for key,value in sorted(original_ids.items())],
        "diagnosticBytePatterns":list(CONTROL_MAGIC),
        "files":dict(file_counts),
        "directLittleEndian32Occurrences":{
          kind:{f"0x{key:X}":n for key,n in sorted(counter.items())}
          for kind,counter in aggregate.items()
        },
        "alignedPayloadU32OccurrenceCount":dict(aligned_totals),
        "sampleNativeMatchingObjects":files,
        "originalInstanceLevelVerified":False,
        "nativeChestPrefabDefinitionPresentButPlacementUnverified":True,
        "limits":[
          "The 20 probe IDs are authenticated native GadgetExcel rows and their original literal names, not proven scene gadget IDs or reward levels.",
          "All byte occurrences can be unrelated scalar values; matching one or multiple little-endian u32 patterns does not decode a binary schema.",
          "Synthetic diagnostic values are byte-collision controls, not authoritative non-Gadget identifiers.",
          "This scan is confined to one exact WorldArea-containing original MiHoYoBinData block. It cannot rule out other original Unity blocks or server scene instances.",
          "No private-server drop tables, scene Lua, custom LootCSS fields, original reward probability or Gadget level semantics are inferred."
        ]
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--block",type=Path,required=True)
    p.add_argument("--cli-dll",type=Path,required=True)
    p.add_argument("--export",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    original_ids=native_gadget_ids()
    if len(original_ids)!=20:
        raise ValueError("expected exactly 20 pinned Gadget name rows")
    source=bundle.verify_manifest_and_fetch(args.block)
    result=examine_block(args.block,args.cli_dll,args.export,original_ids)
    result["verifiedOfficialBlockSource"]=source
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({
        "status":result["status"],
        "verifiedIdCount":len(original_ids),
        "files":result["files"],
        "occurrences":result["directLittleEndian32Occurrences"],
        "sample":result["sampleNativeMatchingObjects"][:MAX_EXAMPLES],
    },indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
