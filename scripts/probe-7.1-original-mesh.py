#!/usr/bin/env python3
"""Bounded Global 7.1 original Blb3 -> mesh provenance audit.

Use pinned AnimeStudio CLI on the local *original* 00/00000890.blk:
  --game GI --types Mesh:Both --map_op AssetMap --map_type JSON --map_name mesh
and separately:
  --game GI --types Mesh:Both --names _Col$ --export_type Convert
No source binaries or reconstructed meshes are stored in Git.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from genshinre.assetindex import parse_asset_index
from genshinre.worldmesh import WorldMesh

EXE_SHA = "08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d"
RESOURCE_INDEX_SHA = "24270a3c5b5388407d85ef0b20d91ea6808ba30c564071d378d4f23cb30ab3e6"
BLOCK_SHA = "95254088da900edd3b13aac6a6be1f0077e4160d6280075de3eeeb25a3c50ddb"
EXPORTER_ARCHIVE_SHA = "c94eddbe3fe46c5c400d050591a46eb297d71ededc8c2376d685c988774ed110"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(2**20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_hash(path: Path, expected: str) -> str:
    actual = sha256(path)
    if actual != expected:
        raise ValueError(f"wrong original source sample: {path.name} hash {actual}")
    return actual


def audit(client_exe: Path, resource_index_raw: Path, block: Path,
          mesh_map: Path, obj_dir: Path) -> dict:
    check_hash(client_exe, EXE_SHA)
    check_hash(resource_index_raw, RESOURCE_INDEX_SHA)
    check_hash(block, BLOCK_SHA)
    if block.name != "00000890.blk" or block.open("rb").read(4) != b"Blb\x03":
        raise ValueError("expected original 7.1 Blb3 block 00/00000890.blk")
    index = parse_asset_index(resource_index_raw.read_bytes())
    if len(index.names) != 896771 or len(index.block_groups) != 1447:
        raise ValueError("resource index layout differs from observed 7.1")
    records = json.loads(mesh_map.read_text(encoding="utf-8-sig"))["AssetEntries"]
    meshes = [row for row in records if row["Type"] == "Mesh"]
    collision_named = sorted(
        (r for r in meshes if r["Name"].endswith("_Col")),
        key=lambda r: r["Name"],
    )
    if len(meshes) != 101 or len(collision_named) != 17:
        raise ValueError("original Mesh inventory mismatch")
    if len({r["Name"] for r in collision_named}) != len(collision_named):
        raise ValueError("duplicate source mesh names")
    entries = []
    for row in collision_named:
        mesh_path = obj_dir / (row["Name"] + ".obj")
        mesh = WorldMesh.read(mesh_path)
        lower, upper = mesh.bounds()
        entries.append({
            "name": row["Name"],
            "originalPathId": row["PathID"],
            "exportedObjSha256": sha256(mesh_path),
            "vertexCount": len(mesh.vertices),
            "triangleCount": len(mesh.triangles),
            "localBoundsMin": [round(v, 6) for v in lower],
            "localBoundsMax": [round(v, 6) for v in upper],
        })
    return {
        "schemaVersion": 1,
        "target": "Genshin Impact 7.1.0 Global Windows x64",
        "source": {
            "exeSha256": EXE_SHA,
            "resourceIndexRawSha256": RESOURCE_INDEX_SHA,
            "block": "AssetBundles/blocks/00/00000890.blk",
            "blockSha256": BLOCK_SHA,
            "originalContainerMagic": "426c6203",
            "indexNameCount": len(index.names),
            "indexBlockCount": len(index.block_groups),
        },
        "exporter": {
            "project": "EIHRTeam/AnimeStudio",
            "release": "v1.0.0-CI",
            "archive": "AnimeStudio.CLI-1.0.0-CI-win-x64.zip",
            "archiveSha256": EXPORTER_ARCHIVE_SHA,
        },
        "meshAssetMapSha256": sha256(mesh_map),
        "meshAssetCount": len(meshes),
        "collisionNamedCandidateCount": len(entries),
        "candidates": entries,
        "status": {
            "sourceMeshGeometry": "VERIFIED",
            "collisionLayerBinding": "UNRESOLVED",
            "worldInstanceTransforms": "UNRESOLVED",
            "serverWorldRaycastReady": False,
            "notes": [
                "The _Col suffix is a source-verified name, not proof of an enabled MeshCollider.",
                "OBJ vertices are prefab-local; the original world-instance transform is not recovered.",
                "Neither game meshes nor reconstructed vertex data are committed to Git.",
            ],
        },
    }


def original_sample(block: Path, expected_sha: str, obj: Path,
                    expected_name: str, expected_counts: tuple[int,int]) -> dict:
    check_hash(block, expected_sha)
    if obj.stem != expected_name:
        raise ValueError("unexpected original named model export")
    mesh = WorldMesh.read(obj)
    if (len(mesh.vertices), len(mesh.triangles)) != expected_counts:
        raise ValueError("original mesh topology changed")
    lo, hi = mesh.bounds()
    return {
        "sourceBlock": "AssetBundles/blocks/00/" + block.name,
        "sourceBlockSha256": expected_sha,
        "mesh": obj.stem,
        "objSha256": sha256(obj),
        "vertexCount": len(mesh.vertices),
        "triangleCount": len(mesh.triangles),
        "localBoundsMin": [round(v, 6) for v in lo],
        "localBoundsMax": [round(v, 6) for v in hi],
        "localRayAtOriginY": mesh.raycast_down(0, 0),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-exe", type=Path, required=True)
    parser.add_argument("--resource-index-raw", type=Path, required=True)
    parser.add_argument("--block", type=Path, required=True)
    parser.add_argument("--mesh-map", type=Path, required=True)
    parser.add_argument("--obj-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    for name in ("terrain-block","terrain-obj","water-block","water-obj"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.client_exe, args.resource_index_raw,
                   args.block, args.mesh_map, args.obj_dir)
    report["additionalOriginalSamples"] = {
        "terrainMesh": original_sample(
            args.terrain_block,
            "01120b2bb6cf1b81de7bbd27f68309279f2ddd01064aa8cf56807def71a8c68c",
            args.terrain_obj,
            "BigWorld_-1_14_TerrainMesh_JJH_ERR_59_Lod1", (230,363),
        ),
        "flatColNamedWaterTile": original_sample(
            args.water_block,
            "e3a30035239e4bb4d43045e4905d86f0e8d61e61a81709bb8e9c1cbd17b2abe6",
            args.water_obj,
            "Level_NodKrai_LongPVP_4_0_0_Magma_1752853806_Sub0_IgnoreWaterTile_Col",
            (53,51),
        ),
    }
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != report:
            raise SystemExit("original model evidence differs from snapshot")
        print("PASS: pinned 7.1 Blb3 original geometry and derived manifest")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        print(f"wrote {args.output}: {len(report['candidates'])} original meshes")


if __name__ == "__main__":
    main()
