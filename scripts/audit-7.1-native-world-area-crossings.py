#!/usr/bin/env python3
"""Audit native 7.1 WorldArea parent/child polygon boundary crossings.

Works only on the thirteen SHA-256 pinned, fully consumed official 7.1
serialized scene payloads. Reuses the existing positive-witness edge splitter
without inheriting the community polygon coordinates.
"""
from __future__ import annotations

from collections import defaultdict
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.worldareabin import decode_world_area

ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "versions/7.1.0-global/analyses/progression/world"
GEOMETRY_AUDIT = ROOT / "scripts/audit-7.1-world-areas.py"
CLEARANCE = 0.25


def load_geometry_helpers():
    spec = importlib.util.spec_from_file_location("native_world_area_geometry_helpers", GEOMETRY_AUDIT)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def polygon(record: dict | None) -> list[dict]:
    shape = (record or {}).get("offset_0x10_shape") or {}
    points = (shape.get("offset_0x18_vertices") or {}).get("points") or []
    vertices = []
    for point in points:
        xyz = point["coordinates"]
        if xyz.get("x") is None or xyz.get("z") is None:
            raise ValueError("native world-area polygon vertex has absent X or Z; geometry unresolved")
        vertices.append({"_x": xyz["x"], "_z": xyz["z"]})
    return vertices


def scene_polygons(tree: dict) -> tuple[list[dict], list[dict], list[dict]]:
    parents = []
    children = []
    per_parent = []
    for row in tree["parents"]:
        parent = row["area_record"]
        if parent is None or parent.get("offset_0x18_u32") is None:
            raise ValueError("native parent row is missing areaID1")
        pid = parent["offset_0x18_u32"]
        parent_points = polygon(parent)
        parents.append({"id": pid, "points": parent_points})
        members = (row.get("child_array") or {}).get("values") or []
        per_parent.append({"areaID1": pid, "childRecords": len(members)})
        for c in members:
            if c.get("offset_0x18_u32") != pid or c.get("offset_0x1C_u32") is None:
                raise ValueError(f"native child missing ID or parent mismatch under {pid}")
            shape = (c or {}).get("offset_0x10_shape") or {}
            min_y = ((shape.get("offset_0x24_vector") or {}).get("coordinates") or {}).get("y")
            max_y = ((shape.get("offset_0x30_vector") or {}).get("coordinates") or {}).get("y")
            children.append({
                "areaID1": pid, "areaID2": c["offset_0x1C_u32"],
                "record_parent": pid, "points": polygon(c),
                "parent_points": parent_points,
                "minY": min_y, "maxY": max_y,
            })
    return parents, children, per_parent


def scan_tree(tree: dict, scene_id: int, helper=None) -> dict:
    helper = helper or load_geometry_helpers()
    parents, children, details = scene_polygons(tree)
    witnesses = helper.edge_interior_crossings(parents, children, clearance=CLEARANCE)
    by_key = defaultdict(list)
    for child in children:
        by_key[(child["areaID1"], child["areaID2"])].append(child)
    for w in witnesses:
        x, z = w["witness"]["x"], w["witness"]["z"]
        candidate_shapes = [
            c for c in by_key[(w["areaID1"], w["areaID2"])]
            if helper.contains(c["points"], x, z)
            and not helper.contains(c["parent_points"], x, z)
        ]
        if not candidate_shapes:
            raise ValueError("native positive witness has no matching decoded polygon")
        # A repeated areaID2 can own multiple polygons. Preserve ambiguity
        # instead of silently choosing the last matching ID's height range.
        lo, hi = candidate_shapes[0]["minY"], candidate_shapes[0]["maxY"]
        if len({(c["minY"], c["maxY"]) for c in candidate_shapes}) > 1:
            lo = hi = None
        w["matchingNativePolygonRecords"] = len(candidate_shapes)
        w["nativeChildMinY"] = lo
        w["nativeChildMaxY"] = hi
        w["inBoundsYTestValue"] = (lo + hi) / 2 if lo is not None and hi is not None else None
        x,z=w["witness"]["x"],w["witness"]["z"]
        first = next((p["id"] for p in parents if helper.contains(p["points"],x,z)),None)
        w["firstNativeParentAtWitness"] = first
        if first == w["areaID1"]:
            raise AssertionError("positive child-outside-parent witness unexpectedly selects own parent")
    return {
        "sceneID": scene_id,
        "nativeParentRecords": len(parents),
        "nativeChildRecords": len(children),
        "positiveCrossingRecords": len(witnesses),
        "positiveChildIds": sorted({c["areaID2"] for c in witnesses}),
        "witnesses": witnesses,
        "parentChildCounts": details,
    }


def audit(export: Path, manifest_path: Path, historical_path: Path | None = None) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    original = []
    for row in manifest["assets"]:
        scene=row["sceneID"]
        src=(export / "MiHoYoBinData" / (row["exportedName"]+".dat")).read_bytes()
        if hashlib.sha256(src).hexdigest()!=row["rawSha256"]:
            raise ValueError(f"scene {scene}: raw SHA256 mismatch")
        payload=unwrap_mihoyo_bin_data(src)
        if hashlib.sha256(payload).hexdigest()!=row["payloadSha256"]:
            raise ValueError(f"scene {scene}: payload SHA256 mismatch")
        original.append(scan_tree(decode_world_area(payload),scene))
    original.sort(key=lambda x:x["sceneID"])
    keys = {(scene["sceneID"], witness["areaID2"])
            for scene in original for witness in scene["witnesses"]}
    result={
        "status":"EXACT_NATIVE_7_1_WORLD_AREA_XZ_PARENT_CONFLICT_WITNESSES",
        "source":"13 official 7.1 WorldArea payloads, per-file SHA256 and full read verified",
        "method":"Native polygon edge splitting + inward offsets; min 0.25 XZ world-units clearance",
        "sceneCount":len(original),
        "parentRecords":sum(s["nativeParentRecords"] for s in original),
        "childRecords":sum(s["nativeChildRecords"] for s in original),
        "positiveCrossingRecords":sum(s["positiveCrossingRecords"] for s in original),
        "positiveDistinctChildIds":len(keys),
        "nativeCrossingIDs":[{"sceneID":sid,"areaID2":aid} for sid,aid in sorted(keys)],
        "scenes":original,
        "limitations":[
            "These are positive X/Z interior witnesses; a missing hit does not prove polygon containment.",
            "Y checks are independently verified in client. Y midpoint is attached when original minY/maxY are present; no runtime packet is captured.",
            "This audit exercises spatial geometry, not all higher-level area-state or event transitions.",
        ],
    }
    if historical_path:
        history=json.loads(historical_path.read_text(encoding="utf-8"))
        h={(c["sceneID"],c["areaID2"]) for c in
           history["cross_scene_parent_gate_geometry"]["interior_witnesses"]}
        result["historicalComparison"]={
            "historicalCrossingIDs":[{"sceneID":s,"areaID2":a} for s,a in sorted(h)],
            "persistingIDs":[{"sceneID":s,"areaID2":a} for s,a in sorted(keys&h)],
            "resolvedOrNotDetectedIDs":[{"sceneID":s,"areaID2":a} for s,a in sorted(h-keys)],
            "newlyDetectedIDs":[{"sceneID":s,"areaID2":a} for s,a in sorted(keys-h)],
            "notice":"Not detected means no positive witness at this scan resolution; it is not a containment proof.",
        }
    return result


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--world-export",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    result=audit(
        args.world_export,
        REPORT_DIR/"7.1-native-world-area-raw-assets.json",
        REPORT_DIR/"7.1-all-world-area-scene-coverage.json",
    )
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("WORLD_AREA_NATIVE_CROSSINGS_BEGIN")
    print(json.dumps({
        "sceneCount":result["sceneCount"],
        "parentRecords":result["parentRecords"],
        "childRecords":result["childRecords"],
        "positiveCrossingRecords":result["positiveCrossingRecords"],
        "byScene":[{"sceneID":s["sceneID"],"count":s["positiveCrossingRecords"],
                    "ids":s["positiveChildIds"]} for s in result["scenes"]],
        "historicalComparison":result.get("historicalComparison"),
    },indent=2,ensure_ascii=False))
    print("WORLD_AREA_NATIVE_CROSSINGS_END")


if __name__=="__main__":
    main()
