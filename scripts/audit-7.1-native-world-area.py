#!/usr/bin/env python3
"""Decode exact-original 7.1 WorldArea scenes; publish metadata only.

Original scene bytes are transient inputs in the hosted research workflow.
Errors stay explicit. Full decoded polygon arrays are never embedded in
the report, and successful parsing does not itself establish historical
field aliases or gameplay semantics.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.worldareabin import decode_world_area, WorldAreaBinError
from genshinre.worldareacompare import compare_scene

PINNED = Path(
    "versions/7.1.0-global/analyses/progression/world/"
    "7.1-native-world-area-raw-assets.json"
)


def audit_native(directory: Path, manifest_path: Path = PINNED,
                 community_root: Path | None = None) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    community_pins = None
    if community_root:
        pinned_coverage = Path(
            "versions/7.1.0-global/analyses/progression/world/"
            "7.1-all-world-area-scene-coverage.json"
        )
        community_pins = json.loads(
            pinned_coverage.read_text(encoding="utf-8")
        )["source_pins"]["geometry_blobs"]
    rows = []
    for scene in manifest["assets"]:
        sid = scene["sceneID"]
        name = scene["exportedName"] + ".dat"
        raw_file = directory / "MiHoYoBinData" / name
        native = raw_file.read_bytes()
        if hashlib.sha256(native).hexdigest() != scene["rawSha256"]:
            raise ValueError(f"scene {sid}: raw SHA256 differs from pinned original")
        decoded = unwrap_mihoyo_bin_data(native)
        if hashlib.sha256(decoded).hexdigest() != scene["payloadSha256"]:
            raise ValueError(f"scene {sid}: payload SHA256 differs from pinned original")
        try:
            tree = decode_world_area(decoded)
        except (ValueError, OverflowError, struct.error) as exc:
            rows.append({
                "sceneID": sid, "status": "DECODE_UNRESOLVED",
                "payloadSha256": scene["payloadSha256"],
                "reason": f"{type(exc).__name__}: {exc}"[:450],
            })
            continue
        records = [p["area_record"] for p in tree["parents"]]
        children = [
            (p["child_array"] or {}).get("values", []) for p in tree["parents"]
        ]
        def vertices(entry):
            shape = entry and entry.get("offset_0x10_shape")
            return (shape and shape.get("offset_0x18_vertices") or {}).get("count", 0)
        comparison = None
        if community_root is not None:
            filename = (
                scene["exportedName"] + ".json" if sid >= 100
                else f"scene{sid}_worldArea.json"
            )
            community_file = community_root / "BinOutput/Scene/WorldArea" / filename
            blob = subprocess.check_output(
                ["git", "hash-object", str(community_file)], text=True
            ).strip()
            if blob != community_pins[filename]:
                raise ValueError(
                    f"scene {sid}: community blob changed from pinned source: {blob}"
                )
            community_data = json.loads(community_file.read_text(encoding="utf-8"))
            comparison = compare_scene(tree, community_data, sid)
        rows.append({
            "sceneID": sid, "status": "RAW_BINARY_FULLY_CONSUMED",
            "communityComparison": comparison,
            "payloadSha256": scene["payloadSha256"],
            "bytesConsumed": tree["consumedBytes"],
            "rootRecordCount": tree["parentCount"],
            "decodedChildRecordCount": sum(len(c) for c in children),
            "decodedVertexCount": sum(vertices(p) for p in records) + sum(
                vertices(c) for cs in children for c in cs
            ),
            "firstParent": {
                "field18": records[0]["offset_0x18_u32"] if records[0] else None,
                "field1c": records[0]["offset_0x1C_u32"] if records[0] else None,
                "rootRecordMask": tree["parents"][0]["marker"],
                "firstParentChildCount": len(children[0]),
            } if records else None,
            "parentField18Values": [p["offset_0x18_u32"] if p else None for p in records],
            "childField18Field1cFirstFive": [
                [c["offset_0x18_u32"], c["offset_0x1C_u32"]]
                for cs in children for c in cs
            ][:5],
        })
    return {
        "status": (
            "EXACT_7_1_WORLD_AREA_BINARY_FULLY_CONSUMED"
            if all(x["status"] == "RAW_BINARY_FULLY_CONSUMED" for x in rows)
            else "PARTIAL_NATIVE_DECODER_UNRESOLVED"
        ),
        "source": "Pinned original 7.1 Sophon block 0/24230448; SHA-256 checked per object",
        "sceneCount": len(rows),
        "fullyConsumed": sum(x["status"] == "RAW_BINARY_FULLY_CONSUMED" for x in rows),
        "communitySourceChecked": community_root is not None,
        "comparisonTotals": ({
            "nativeVertices": sum(x["communityComparison"]["vertices"]["native7_1"]
                                  for x in rows if x["communityComparison"]),
            "communityVertices": sum(x["communityComparison"]["vertices"]["community"]
                                     for x in rows if x["communityComparison"]),
            "changedGeometryRecords": sum(x["communityComparison"]["changedGeometryCount"]
                                          for x in rows if x["communityComparison"]),
            "scenesWithIdDifferences": [
                x["sceneID"] for x in rows if x["communityComparison"] and
                not x["communityComparison"]["parentChildIdSequenceMatches"]
            ],
        } if community_root is not None else None),
        "scenes": rows,
        "limitations": [
            "Original binary field offsets are decoded without presuming historical community JSON names.",
            "Full parsed original geometry remains transient and is not redistributed.",
            "Decoded values cannot establish whether native gameplay uses all polygons until loader and priority are correlated.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--world-export", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--community-resources", type=Path,
                   help="Pinned MeChen618/AstaPS-Resource checkout; verified by Git blob")
    args = p.parse_args()
    report = audit_native(
        args.world_export, community_root=args.community_resources,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("WORLD_AREA_NATIVE_TREE_BEGIN")
    print(json.dumps({
        "status": report["status"],
        "fullyConsumed": report["fullyConsumed"],
        "comparisonTotals": report["comparisonTotals"],
        "scenes": [{k: x.get(k) for k in (
            "sceneID", "status", "reason", "rootRecordCount",
            "decodedChildRecordCount", "decodedVertexCount",
            "firstParent", "communityComparison")}
            for x in report["scenes"]],
    }, indent=2, ensure_ascii=False))
    print("WORLD_AREA_NATIVE_TREE_END")


if __name__ == "__main__":
    main()
