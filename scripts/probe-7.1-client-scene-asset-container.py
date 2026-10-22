#!/usr/bin/env python3
"""Classify exact original 7.1 client asset containers, including non-BinData types.

This checks the ORIGINAL official Sophon compressed manifest, then reads the
exact original 31049741 design index whose raw SHA-256 and producer were
separately verified. Nothing is inferred from historical server Lua names.
Directory prefixes and paired Unity type names are inventory only, not
evidence of a scene instance parser or its level field.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath
from genshinre.assetindex import parse_asset_index, unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71
from genshinre.samplefetch import download, decompress_zstd, parse_manifest

MANIFEST_ZSTD_SHA256="3383e77a832d0076e84b4bd441867c293ccb2eff13e4380a2ef0df5b4d087d66"
INDEX_RAW_SHA256="fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
TOKENS=("scene","script","lua","gadget","level","world","bundle","asset","data","config","unity","binoutput","excel")
FOCUSED=("scene","script","lua","gadget","level")
BLOCK_FOLDER="GenshinImpact_Data/StreamingAssets/AssetBundles/blocks/"
MAX_PATH_EXAMPLES=32


def summarize_manifest(manifest:list[dict])->dict:
    prefixes=Counter()
    extensions=Counter()
    size_by_prefix=Counter()
    focus={tag:[] for tag in FOCUSED}
    block_prefixes=Counter()
    for row in manifest:
        original=row.get("filename","")
        if not isinstance(original,str) or not original:
            raise ValueError("manifest file row missing filename")
        name=original.replace("\\","/")
        parts=PurePosixPath(name).parts
        prefix="/".join(parts[:min(4,len(parts))])
        prefixes[prefix]+=1
        size_by_prefix[prefix]+=int(row.get("size",0) or 0)
        extensions[PurePosixPath(name).suffix.lower() or "(none)"]+=1
        if name.lower().startswith(BLOCK_FOLDER.lower()):
            tail=name[len(BLOCK_FOLDER):].split("/")
            block_prefixes[tail[0] if tail else "(none)"]+=1
        for token in FOCUSED:
            if token in name.lower() and len(focus[token])<MAX_PATH_EXAMPLES:
                focus[token].append(name)
    return {
        "manifestFileCount":len(manifest),
        "topPrefixes":[{"path":k,"files":v,"sizeBytes":size_by_prefix[k]}
                       for k,v in prefixes.most_common(35)],
        "extensions":dict(extensions.most_common(30)),
        "assetBundleBlockSubdirectories":dict(block_prefixes.most_common(50)),
        "pathsContainingRelevantTokens":focus,
        "wholeManifestHasFileNameContainingScene":any("scene" in x.lower() for x in focus["scene"]),
        "wholeManifestSceneFileCount":sum(1 for r in manifest if "scene" in str(r["filename"]).lower()),
        "wholeManifestLuaFileCount":sum(1 for r in manifest if str(r["filename"]).lower().endswith(".lua")),
    }


def index_type_header(raw:bytes)->list[dict]:
    from genshinre.assetindex import _Reader
    payload=unwrap_mihoyo_bin_data(raw)
    reader=_Reader(payload)
    types=reader.u32()
    if types>100000:raise ValueError("unbounded original index type count")
    rows=[]
    for i in range(types):
        rows.append({"index":i,"firstOriginalName":reader.string(),
                     "secondOriginalName":reader.string()})
    if any(len(x["firstOriginalName"])+len(x["secondOriginalName"])>2000 for x in rows):
        raise ValueError("implausible original asset-index type string")
    return rows


def audit(raw_manifest:bytes,raw_index:bytes)->dict:
    if hashlib.sha256(raw_manifest).hexdigest()!=MANIFEST_ZSTD_SHA256:
        raise ValueError("original 7.1 Sophon compressed manifest SHA-256 mismatch")
    if hashlib.sha256(raw_index).hexdigest()!=INDEX_RAW_SHA256:
        raise ValueError("original 7.1 design index SHA-256 mismatch")
    manifest=parse_manifest(decompress_zstd(raw_manifest))
    index=parse_asset_index(raw_index)
    pairs=index_type_header(raw_index)
    if len(index.names)!=247073:
        raise ValueError("original design index controls changed")
    return {
        "schemaVersion":1,
        "status":"ORIGINAL_7_1_CLIENT_CONTAINER_INVENTORY__SCENE_INSTANCE_SCHEMA_UNVERIFIED",
        "originalClient":PROFILE_71.identity,
        "originalExeSha256":PROFILE_71.exe_sha256,
        "originalCompressedManifestSha256":MANIFEST_ZSTD_SHA256,
        "originalDesignIndexRawSha256":INDEX_RAW_SHA256,
        "manifest":summarize_manifest(manifest),
        "designIndex":{
            "pairedOriginalTypeStrings":pairs,
            "nameCount":len(index.names),
            "referencedBlockCount":len(index.block_groups),
            "assetBlockRefCount":len(index.block_refs),
            "groups":dict(Counter(str(v) for v in index.block_groups.values())),
        },
        "researchBoundary":[
            "File names in official Sophon manifest describe distributed client files only, not the content of each Unity AssetBundle object.",
            "The previously screened 805 MiHoYoBinData name hashes (including 672 server-style scene-group guesses) cover only that exact name/type suffix.",
            "An original index type table is a data-structure descriptor and does not prove a level or chest field.",
            "Whether original Unity TextAsset, MonoBehaviour or another AssetBundle asset contains scene instance config is not yet proven.",
            "Do not promote fork Lua, community JSON, historical Chinese drop_tag or any reward amounts to original-client authority."
        ]
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--index-raw",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    result=audit(download(PROFILE_71.sophon_manifest_url),a.index_raw.read_bytes())
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({"status":result["status"],
          "manifest":result["manifest"],
          "typePairs":result["designIndex"]["pairedOriginalTypeStrings"],
          "indexBlockCount":result["designIndex"]["referencedBlockCount"]},
        indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
