#!/usr/bin/env python3
"""Verify the exact 7.1 original BigWorld sector-root bytes and lexical mesh link."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from genshinre.nativeprofile import PROFILE_71
from genshinre.sectorroot71 import parse_sector_root
from genshinre.worldsector71 import file_sha256


ROOT_SHA = "fc66bf16a444b60580dccae900ef96c45795c0032ea6c76717d62ad6afed3ebe"
ROOT_RAW_SHA = "829f92f3a0c8e2741e4d039dc8bed65eed2fd363a1297e1502321bbd155b62eb"
MESH_BLOCK_SHA = "01120b2bb6cf1b81de7bbd27f68309279f2ddd01064aa8cf56807def71a8c68c"
SECTOR_CONTROL = "BigWorld_-1_14"


def audit(exe: Path, root_block: Path, root_raw: Path,
          mesh_block: Path, mesh_asset_map: Path) -> dict:
    for path, sha in (
        (exe, PROFILE_71.exe_sha256),
        (root_block, ROOT_SHA),
        (root_raw, ROOT_RAW_SHA),
        (mesh_block, MESH_BLOCK_SHA),
    ):
        if file_sha256(path) != sha:
            raise ValueError(f"wrong original 7.1 input sample: {path.name}")
    raw = root_raw.read_bytes()
    root = parse_sector_root(raw)
    if (root.world_name, root.config_name, root.enabled, root.manual_load) != (
        "BigWorld", "BigWorldConfig", True, False
    ):
        raise ValueError("wrong 7.1 native BigWorld root identity")
    if len(root.sectors) != 1292 or SECTOR_CONTROL not in root.sectors:
        raise ValueError("original BigWorld sector list differs")
    if root.blacklisted_sectors:
        raise ValueError("original BigWorld blacklist unexpectedly populated")
    meshes = json.loads(mesh_asset_map.read_text(encoding="utf-8-sig"))["AssetEntries"]
    if len(meshes) != 212:
        raise ValueError("original terrain block asset inventory differs")
    matched = sorted(row["Name"] for row in meshes if
                     row["Type"] == "Mesh" and
                     row["Name"].startswith(SECTOR_CONTROL + "_TerrainMesh_"))
    if matched != [
        "BigWorld_-1_14_TerrainMesh_JJH_ERR_59_Lod1",
        "BigWorld_-1_14_TerrainMesh_JJH_ERR_59_Lod2",
    ]:
        raise ValueError("source terrain mesh control mismatch")
    return {
        "schemaVersion": 1,
        "target": "Genshin Impact Global 7.1 Windows x64",
        "exeSha256": PROFILE_71.exe_sha256,
        "source": {
            "sectorRootBlock": "AssetBundles/blocks/00/05825684.blk",
            "sectorRootBlockSha256": ROOT_SHA,
            "monoBehaviourRawExportSha256": ROOT_RAW_SHA,
            "monoBehaviourBytes": len(raw),
            "sourceMeshBlock": "AssetBundles/blocks/00/07207014.blk",
            "sourceMeshBlockSha256": MESH_BLOCK_SHA,
            "exporter": "EIHRTeam/AnimeStudio v1.0.0-CI (pinned)",
        },
        "root": {
            "worldName": root.world_name,
            "configName": root.config_name,
            "enabled": root.enabled,
            "manualLoad": root.manual_load,
            "scriptPathId": root.script_path_id,
            "sectorCount": len(root.sectors),
            "sectorNamesSha256": hashlib.sha256(
                "\n".join(root.sectors).encode("utf-8")
            ).hexdigest(),
            "numericGridSectorCount": sum(bool(re.fullmatch(
                r"BigWorld_-?\d+_-?\d+", name)) for name in root.sectors),
            "sectorNames": list(root.sectors),
        },
        "meshNameControl": {
            "originalSectorName": SECTOR_CONTROL,
            "originalTerrainMeshNames": matched,
            "status": "LEXICAL_NAME_CORRESPONDENCE_ONLY",
        },
        "limits": {
            "bigWorldRootAndSectorNames": "VERIFIED_ORIGINAL_CLIENT_BYTES",
            "terrainModelLocalGeometry": "VERIFIED_SEPARATE_ORIGINAL_SOURCE",
            "terrainWorldPlacement": "UNRESOLVED",
            "colliderEnabledOrSurfaceLayer": "UNRESOLVED",
            "serverWorldRaycastReady": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--root-block", type=Path, required=True)
    parser.add_argument("--root-raw", type=Path, required=True)
    parser.add_argument("--mesh-block", type=Path, required=True)
    parser.add_argument("--mesh-map", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = audit(args.exe, args.root_block, args.root_raw,
                   args.mesh_block, args.mesh_map)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("original BigWorld sector-root evidence differs from snapshot")
        print("PASS: original Global 7.1 BigWorld sector list and mesh-name control")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print("wrote", args.output)


if __name__ == "__main__":
    main()
