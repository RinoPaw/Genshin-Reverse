#!/usr/bin/env python3
"""Original Global 7.1 Scene/Point source-path and raw-payload census.

Use only source-SHA-gated original 7.1 design index and original
00/24230448.blk export. Verify the previously proved WorldArea scene3
positive-control bytes and original path-hash/block identities first.

A path/hash and opaque payload establish asset presence, *not* the
Gadget/chest instance schema or any official server scene ownership.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from genshinre.assetindex import parse_asset_index, query_asset_paths, unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71

INDEX_SHA="fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
WORLD_AREA3_RAW_SHA="e66d6ec832bed734e824714d345961715b01edbdce50f6115b07983ec205eda9"
WORLD_BLOCK=(0,24230448)
SCENES=(3,4,5,6,7,9,10,11,100,101,102,103,51195)
WORLD_AREA3="Data/_BinOutput/Scene/WorldArea/scene3_worldArea"
SCENE_POINT3="Data/_BinOutput/Scene/Point/scene3_point"
SCENE_POINT3_HASH="0xBC3AE3E1FD"
MAX_BYTES=32


def sha256(b:bytes)->str:
    return hashlib.sha256(b).hexdigest()


def candidate_paths()->list[str]:
    return [f"Data/_BinOutput/Scene/Point/scene{scene}_point" for scene in SCENES]


def is_utf8(payload:bytes)->bool:
    try:
        payload.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def analyze(index_bytes:bytes, export_dir:Path)->dict:
    if sha256(index_bytes)!=INDEX_SHA:
        raise ValueError("not the source-authenticated exact Global 7.1 original design index")
    index=parse_asset_index(index_bytes)
    if len(index.names)!=247073:
        raise ValueError("pinned original index name count changed")
    controls=query_asset_paths(index,[WORLD_AREA3,SCENE_POINT3])
    area,point=controls
    if (area["status"]!="HASH_RESOLVED" or
        (area["groupId"],area["blockId"])!=WORLD_BLOCK or
        area["exportedName"]!="0c934d1c"):
        raise ValueError("original WorldArea scene3 index source identity mismatch")
    if (point["status"]!="HASH_RESOLVED" or
        (point["groupId"],point["blockId"])!=WORLD_BLOCK or
        point["pathHash"]!=SCENE_POINT3_HASH or
        point["exportedName"]!="bc3ae3e1"):
        raise ValueError("original Scene/Point scene3 path-hash positive control drift")
    folder=export_dir/"MiHoYoBinData"
    if not folder.is_dir():
        raise ValueError("source exporter MiHoYoBinData directory unavailable")
    area_bytes=(folder/"0c934d1c.dat").read_bytes()
    if sha256(area_bytes)!=WORLD_AREA3_RAW_SHA:
        raise ValueError("source-original WorldArea scene3 Raw SHA256 control failed")
    # 32-bit exporter filename stems truncate the independently indexed 40-bit
    # path hash. Reject ambiguous short filenames instead of misassigning bytes.
    stem_counts=Counter(item.exported_name for item in index.names)
    results=[]
    for scene,path,row in zip(SCENES,candidate_paths(),
                              query_asset_paths(index,candidate_paths()),strict=True):
        out={
          "sceneId":scene,"candidateOriginalPath":path,
          "namePathHash":row["pathHash"],"indexStatus":row["status"],
          "originalBlockVerifiedAsWorldAreaBlock":False,
          "nativeScenePointRowSchemaDecoded":False,
          "chestGadgetInstanceProven":False,
        }
        if row["status"]=="HASH_RESOLVED":
            out["sourceGroupId"]=row["groupId"]
            out["sourceBlockId"]=row["blockId"]
            out["originalBlockVerifiedAsWorldAreaBlock"]=(
                (row["groupId"],row["blockId"])==WORLD_BLOCK)
            out["shortExportStem"]=row["exportedName"]
            if stem_counts[row["exportedName"]]>1:
                out["status"]="AMBIGUOUS_SHORT_EXPORT_STEM"
            elif not out["originalBlockVerifiedAsWorldAreaBlock"]:
                out["status"]="INDEX_RESOLVED_TO_DIFFERENT_SOURCE_BLOCK"
            else:
                file=folder/(row["exportedName"]+".dat")
                raw=file.read_bytes()
                payload=unwrap_mihoyo_bin_data(raw)
                if not payload:
                    raise ValueError(f"original scene {scene} Point payload is empty")
                out.update(
                    status="SOURCE_RAW_AND_FRAMING_VERIFIED",
                    rawExportBytes=len(raw),rawExportSha256=sha256(raw),
                    payloadBytes=len(payload),payloadSha256=sha256(payload),
                    unwrappedPayloadFirst32Hex=payload[:MAX_BYTES].hex(),
                    firstLittleEndianU32=(f"0x{struct.unpack_from('<I',payload)[0]:08X}"
                                          if len(payload)>=4 else None),
                    entirePayloadUtf8=is_utf8(payload),
                    trailingRawZeroBytes=len(raw)-len(payload)-4,
                )
        else:
            out["status"]=row["status"]
        results.append(out)
    status_counts=dict(sorted(Counter(x["status"] for x in results).items()))
    return {
      "schemaVersion":1,
      "status":"ORIGINAL_GLOBAL_7_1_SCENE_POINT_INDEX_AND_RAW_CENSUS__CHEST_PLACEMENT_UNPROVEN",
      "originalClient":PROFILE_71.identity,
      "exactOriginalExeSha256":PROFILE_71.exe_sha256,
      "exactOriginalDesignIndexRawSha256":INDEX_SHA,
      "originalWorldAreaBlock":"00/24230448.blk",
      "expectedOriginalWorldAreaBlockSha256":
          "71fbe2d10404655fa20e5d612daf5fa2f2336c1d6250ae209b722c894169aff7",
      "positiveControls":{
         "worldAreaScene3RawSha256":WORLD_AREA3_RAW_SHA,
         "scenePoint3OriginalPathHash":SCENE_POINT3_HASH,
         "scenePoint3ExportStem":"bc3ae3e1",
      },
      "scenesChecked":len(results),
      "statusCounts":status_counts,
      "assetRows":results,
      "originalScenePointCoordinateDecoded":False,
      "originalChestInstancePlacementProven":False,
      "originalChestLevelFieldProven":False,
      "originalServerInstanceOwnershipProven":False,
      "limitations":[
        "Original design-index membership and exact original Unity Raw export verify an asset's presence and bytes, not semantic content.",
        "A scene point file may encode any client-side point structures; it is not a validated chest/SceneGadget placement set.",
        "Asset names outside this finite Scene/Point path family, other original Unity blocks and server-only resources are not enumerated.",
        "The independent WorldArea scene3 SHA-256 proves this exporter block contains the original WorldArea, not that the Point row schema shares the polygon decoder.",
        "Do not derive original drop tags, chest grades, reward amounts, or scene-instance levels from these data."
      ],
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--index-raw",type=Path,required=True)
    p.add_argument("--worldarea-export",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    result=analyze(a.index_raw.read_bytes(),a.worldarea_export)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("ORIGINAL_SCENE_POINT_CENSUS_BEGIN")
    print(json.dumps(result,ensure_ascii=False,indent=2))
    print("ORIGINAL_SCENE_POINT_CENSUS_END")


if __name__=="__main__":
    main()
