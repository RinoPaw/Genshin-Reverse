#!/usr/bin/env python3
"""Inventory ORIGINAL Global 7.1 Unity classes in source-authenticated scene-area block.

Source block 00/24230448.blk is independently known to contain all 13
original Scene WorldArea MiHoYoBinData source assets, including scene 3
with raw sha e66d6ec8... . Original Sophon manifest identity, source
block MD5 + size, exporter SHA and positive exported asset hash are
checked. Unity class export counts do not establish original instance level.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
from genshinre.nativeprofile import PROFILE_71
from genshinre.samplefetch import download,decompress_zstd,parse_manifest,choose_file,reconstruct

MANIFEST_SHA="3383e77a832d0076e84b4bd441867c293ccb2eff13e4380a2ef0df5b4d087d66"
SOURCE_BLOCK_ID=24230448
BLOCK_SIZE=133699977
BLOCK_MD5="1ad9ee10633cf3154a27f87690b5008f"
BLOCK_PATH="GenshinImpact_Data/StreamingAssets/AssetBundles/blocks/00/24230448.blk"
SCENE3_STEM="0c934d1c.dat"
SCENE3_RAW_SHA="e66d6ec832bed734e824714d345961715b01edbdce50f6115b07983ec205eda9"
CLASS_TYPES=("MiHoYoBinData","TextAsset","MonoBehaviour")
EXTRACTOR_SHA="12e2dfb2ab35880eda4274fcd393091d47e204d4b6e4b5838421fa3b4d1720a1"
MAX_EXAMPLE_NAMES=36


def verify_manifest_and_fetch(source:Path,workers:int=8)->dict:
    raw=download(PROFILE_71.sophon_manifest_url)
    if hashlib.sha256(raw).hexdigest()!=MANIFEST_SHA:
        raise ValueError("original 7.1 manifest SHA-256 mismatch")
    rows=parse_manifest(decompress_zstd(raw))
    hit=choose_file(rows,BLOCK_PATH)
    if str(hit.get("filename","")).replace("\\","/")!=BLOCK_PATH:
        raise ValueError("original scene-area block path mismatch")
    if int(hit.get("size",0))!=BLOCK_SIZE or str(hit.get("md5","")).lower()!=BLOCK_MD5:
        raise ValueError("source block published size/MD5 anchor changed")
    if not source.is_file():
        source.parent.mkdir(parents=True,exist_ok=True)
        reconstruct(PROFILE_71.sophon_chunk_prefix,hit,source,workers)
    if source.stat().st_size!=BLOCK_SIZE:
        raise ValueError("original scene-area block size mismatch")
    md5=hashlib.md5()
    sha=hashlib.sha256()
    with source.open("rb") as stream:
        for data in iter(lambda:stream.read(1048576),b""):
            md5.update(data);sha.update(data)
    if md5.hexdigest()!=BLOCK_MD5:
        raise ValueError("original scene-area block MD5 mismatch")
    return {"originalPath":BLOCK_PATH,"sizeBytes":BLOCK_SIZE,"officialManifestMd5":BLOCK_MD5,
            "sha256":sha.hexdigest(),"manifestSha256":MANIFEST_SHA,
            "sophonChunks":len(hit["chunks"])}


def files_per_type(directory:Path)->dict:
    result={}
    for typ in CLASS_TYPES:
        folder=directory/typ
        files=sorted((p for p in folder.rglob("*") if p.is_file()),key=lambda x:str(x)) if folder.is_dir() else []
        tokens=("scene","group","gadget","chest","script","level")
        selected=[str(file.relative_to(directory)) for file in files
                  if any(token in str(file.relative_to(directory)).lower() for token in tokens)]
        result[typ]={"totalRawExports":len(files),"totalRawBytes":sum(p.stat().st_size for p in files),
                     "filenameMatchesAmongExports":selected[:MAX_EXAMPLE_NAMES],
                     "filenameMatchCount":len(selected),
                     "firstFileNames":[str(p.relative_to(directory)) for p in files[:MAX_EXAMPLE_NAMES]]}
    return result


def audit(block:Path,cli_dll:Path,export:Path,block_source:dict)->dict:
    export.mkdir(parents=True,exist_ok=True)
    subprocess.run(["dotnet",str(cli_dll),str(block),str(export),
                    "--game","GI","--types",",".join(CLASS_TYPES),
                    "--export_type","Raw","--logger_flags","Error"],check=True)
    positive=export/"MiHoYoBinData"/SCENE3_STEM
    if not positive.is_file():
        raise ValueError("source-backed original scene3 WorldArea asset is absent from raw export")
    raw=positive.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SCENE3_RAW_SHA:
        raise ValueError("source-backed original scene3 WorldArea raw SHA-256 mismatch")
    classes=files_per_type(export)
    if classes["MiHoYoBinData"]["totalRawExports"]<13:
        raise ValueError("original WorldArea export positive count unexpectedly absent")
    return {
        "schemaVersion":1,
        "status":"ORIGINAL_7_1_WORLD_AREA_BLOCK_UNITY_CLASS_INVENTORY__CHEST_INSTANCE_UNVERIFIED",
        "originalClient":PROFILE_71.identity,
        "sourceBlock":block_source,
        "sourceExporter":"EIHRTeam/AnimeStudio v1.0.0-CI linux-x64",
        "sourceExporterSha256":EXTRACTOR_SHA,
        "originalUnityExportRequestedTypes":list(CLASS_TYPES),
        "originalWorldAreaPositiveControl":{"sceneId":3,
          "originalSourceName":"Data/_BinOutput/Scene/WorldArea/scene3_worldArea",
          "originalRawName":SCENE3_STEM,"originalRawSha256":SCENE3_RAW_SHA},
        "observedExportedObjectTypes":classes,
        "limitations":[
            "Unity export type counts apply only to the one original world-area-containing AssetBundle block, not all 1,987 original .blk files.",
            "The original asset index's zero type-string count is not a declaration that all Unity objects are MiHoYoBinData.",
            "CLI-exported filename matches, Unity type counts and source hash alone do not recover the semantic schema or placement of scene gadget instances.",
            "Never infer original chest grade, level or server drop_tag from historical private-server Lua."
        ]
    }


def main()->None:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--block",required=True,type=Path)
    ap.add_argument("--cli-dll",required=True,type=Path)
    ap.add_argument("--export",required=True,type=Path)
    ap.add_argument("--output",required=True,type=Path)
    args=ap.parse_args()
    block_source=verify_manifest_and_fetch(args.block)
    report=audit(args.block,args.cli_dll,args.export,block_source)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":report["status"],"sourceBlockSha256":block_source["sha256"],
       "classes":report["observedExportedObjectTypes"]},ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()
