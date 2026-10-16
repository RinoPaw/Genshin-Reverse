#!/usr/bin/env python3
"""Independent, exact-original WorldArea containment topology check.

Target only IDs 5502 and 5602, which lost the historical positive
parent-crossing witness after decoding the exact 7.1 source. We use
validated simple polygons; invalid input is reported rather than repaired.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.worldareabin import decode_world_area


TARGETS = ((55, 5502), (56, 5602))
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"versions/7.1.0-global/analyses/progression/world/7.1-native-world-area-raw-assets.json"


def points(shape: dict | None):
    vertices = (((shape or {}).get("offset_0x10_shape") or {})
                .get("offset_0x18_vertices") or {}).get("points") or []
    coords=[]
    for row in vertices:
        xyz=row["coordinates"]
        if xyz.get("x") is None or xyz.get("z") is None:
            raise ValueError("missing original X/Z coordinate; native topology unresolved")
        coords.append((float(xyz["x"]),float(xyz["z"])))
    return coords


def analyze(tree: dict) -> dict:
    from shapely.geometry import Polygon
    from shapely.validation import explain_validity
    parents = {}
    for outer in tree["parents"]:
        head=outer["area_record"]
        pid=head["offset_0x18_u32"]
        parents[pid]=outer
    rows=[]
    for area1,area2 in TARGETS:
        if area1 not in parents:
            raise ValueError(f"native parent {area1} is missing")
        block=parents[area1]
        matches=[c for c in (block.get("child_array") or {}).get("values",[])
                 if c.get("offset_0x1C_u32")==area2]
        if len(matches)!=1:
            raise ValueError(f"native polygon {area1}/{area2} not unique: {len(matches)}")
        parent=Polygon(points(block["area_record"]))
        child=Polygon(points(matches[0]))
        record={
            "areaID1":area1, "areaID2":area2,
            "nativeParentValid":parent.is_valid,
            "nativeChildValid":child.is_valid,
            "parentValidity":explain_validity(parent),
            "childValidity":explain_validity(child),
            "parentAreaXZ":parent.area,
            "childAreaXZ":child.area,
        }
        if not parent.is_valid or not child.is_valid or parent.is_empty or child.is_empty:
            record["status"]="TOPOLOGY_UNRESOLVED_INVALID_OR_EMPTY_POLYGON"
        else:
            outside=child.difference(parent)
            record["nativeChildCoveredByDeclaredParent"]=child.covered_by(parent)
            record["childAreaOutsideDeclaredParentXZ"]=outside.area
            record["uncoveredFractionOfChildAreaXZ"]=(outside.area/child.area if child.area else None)
            record["status"]=(
                "GEOMETRICALLY_COVERED_BY_PARENT_XZ"
                if child.covered_by(parent) else "CHILD_REMAINS_PARTLY_OUTSIDE_PARENT_XZ"
            )
            if not outside.is_empty and outside.area>0:
                witness=outside.representative_point()
                record["exampleOutsideXZ"]={"x":witness.x,"z":witness.y}
        rows.append(record)
    return {
        "status":"EXACT_NATIVE_7_1_TARGETED_PARENT_TOPOLOGY",
        "method":"Shapely validity+2D Polygon.covered_by; invalid polygons are not repaired or promoted",
        "sceneID":3, "targets":rows,
        "limits":["No Y-dependent child selection or area event packet is simulated.",
                  "A 2D planar polygon containment result does not independently prove all runtime area transitions."],
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--world-export",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    native=json.loads(SOURCE.read_text(encoding="utf-8"))
    entry=next(x for x in native["assets"] if x["sceneID"]==3)
    raw=(args.world_export/"MiHoYoBinData"/(entry["exportedName"]+".dat")).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=entry["rawSha256"]:
        raise ValueError("Scene 3 exact raw SHA256 mismatch")
    wire=unwrap_mihoyo_bin_data(raw)
    if hashlib.sha256(wire).hexdigest()!=entry["payloadSha256"]:
        raise ValueError("Scene 3 exact decoded payload SHA256 mismatch")
    output=analyze(decode_world_area(wire))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(output,indent=2)+"\n",encoding="utf-8")
    print("WORLD_AREA_NATIVE_TOPOLOGY_BEGIN")
    print(json.dumps(output,indent=2))
    print("WORLD_AREA_NATIVE_TOPOLOGY_END")


if __name__=="__main__":
    main()
