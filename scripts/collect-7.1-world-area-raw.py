#!/usr/bin/env python3
"""Validate exact 7.1 native WorldArea raw assets without guessing schemas."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.nativeprofile import PROFILE_71
from genshinre.assetindex import query_asset_paths, parse_asset_index

EXPECTED_SCENES = (3, 4, 5, 6, 7, 9, 10, 11, 100, 101, 102, 103, 51195)
INDEX_EXPORT_SHA256 = "fe1e1ce970e3aa72e764b0894d94a684b7a49edc9f3ae6a32c4d7f38d8a64712"
WORLD_BLOCK = (0, 24230448)


def inspect_assets(index_bytes: bytes, export_dir: Path) -> dict:
    if hashlib.sha256(index_bytes).hexdigest() != INDEX_EXPORT_SHA256:
        raise ValueError("7.1 official design-index export SHA256 mismatch")
    index = parse_asset_index(index_bytes)
    paths = [f"Data/_BinOutput/Scene/WorldArea/scene{sid}_worldArea"
             for sid in EXPECTED_SCENES]
    matches = query_asset_paths(index, paths)
    assets = []
    for scene, item in zip(EXPECTED_SCENES, matches, strict=True):
        if (item["status"] != "HASH_RESOLVED"
                or (item["groupId"], item["blockId"]) != WORLD_BLOCK):
            raise ValueError(f"official 7.1 scene {scene} moved or disappeared: {item}")
        filename = str(item["exportedName"]) + ".dat"
        raw_path = export_dir / "MiHoYoBinData" / filename
        if not raw_path.is_file():
            raise FileNotFoundError(f"asset is in index but not in exported block: {raw_path}")
        raw = raw_path.read_bytes()
        payload = unwrap_mihoyo_bin_data(raw)
        utf8 = None
        try:
            utf8 = payload.decode("utf-8")
        except UnicodeDecodeError:
            pass
        js = None
        if utf8 is not None and utf8.lstrip().startswith(("{", "[")):
            try:
                js = json.loads(utf8)
            except json.JSONDecodeError:
                pass
        assets.append({
            "sceneID": scene,
            "assetPath": item["path"],
            "pathHash": item["pathHash"],
            "exportedName": item["exportedName"],
            "blockId": item["blockId"],
            "groupId": item["groupId"],
            "rawSize": len(raw),
            "rawSha256": hashlib.sha256(raw).hexdigest(),
            "payloadSize": len(payload),
            "payloadSha256": hashlib.sha256(payload).hexdigest(),
            "payloadFirst32BytesHex": payload[:32].hex(),
            "payloadJsonDetected": js is not None,
            "payloadUtf8Detected": utf8 is not None,
        })
    return {
        "status": "EXACT_7_1_WORLD_AREA_RAW_ASSETS_EXPORTED__SCHEMA_UNVALIDATED",
        "client": PROFILE_71.identity,
        "officialIndexSha256": INDEX_EXPORT_SHA256,
        "officialBlock": {"groupId": WORLD_BLOCK[0], "blockId": WORLD_BLOCK[1]},
        "assetCount": len(assets),
        "assets": assets,
        "limitations": [
            "Raw export and exact identity do not prove the decoded WorldArea schema.",
            "Payload preview is hex-only; do not equate a matching file name with a field-level geometry comparison.",
            "No bundle bytes or proprietary original payloads retained in the committed report.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-raw", type=Path, required=True)
    parser.add_argument("--world-export", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = inspect_assets(args.index_raw.read_bytes(), args.world_export)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print("WORLD_AREA_NATIVE_RAW_EXPORT_BEGIN")
    print(json.dumps(report, indent=2))
    print("WORLD_AREA_NATIVE_RAW_EXPORT_END")


if __name__ == "__main__":
    main()
