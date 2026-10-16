#!/usr/bin/env python3
"""Source-pinned Genshin 7.1 WorldArea boundary reconciliation.

Checks actual polygons, not approximate regions or generated replacements.
The outcome is a static resource observation; it does not establish the
client's precedence when level-1 and level-2 shapes overlap.

Examples:
  python scripts/audit-7.1-world-areas.py --resources ../AstaPS-Resource --check
  python scripts/audit-7.1-world-areas.py --resources ../AstaPS-Resource --output report.json

Optional --historic-resource-root reads a prior community resource checkout;
its identity is reported but not silently promoted to 7.1 evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

PINNED_GIT_BLOBS = {
    "config": "ca05682b11a4cc742c4f98d4f610bf11c9ffe980",
    "bin": "d2687fe28c350d9c4684b0a29a5b24f3f6260936",
    "script": "dfbc7f896a56f53d2260d0706cc15587ac0e51ce",
}
MISSING_7_1 = frozenset({
    4105, 4107, 2501, 3120, 3512, 3602, 3912, 4301,
    4805, 4807, 4808, 7301, 7503,
})
PARENT_CENTROID_CONFLICTS_7_1 = frozenset({3302, 3205, 4104, 5210})
GRID_CROSSINGS_7_1 = frozenset({
    201, 2102, 2504, 3003, 3004, 3204, 3205, 3302, 3407, 3408,
    3604, 4004, 4005, 4103, 4104, 4109, 4702, 5209, 5210, 5602,
})
GRID_RESOLUTION = 17
# Unlike the finite grid, this probes *all child edges* after splitting each
# edge at the parent's transverse intersections. 0.25 units of clearance to
# both polygon boundaries filters coincident edges and float32-size slivers.
EDGE_CLEARANCE = 0.25
EDGE_CROSSINGS_7_1 = frozenset({
    201, 202, 2102, 2504, 3003, 3004, 3204, 3205, 3302, 3407,
    3408, 3604, 3606, 4004, 4005, 4103, 4104, 4109, 4702,
    5209, 5210, 5502, 5602,
})


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def source_file(path: Path, expected_sha: str | None = None) -> tuple[object, str]:
    raw = path.read_bytes()
    actual = blob_sha(raw)
    if expected_sha is not None and actual != expected_sha:
        raise ValueError(f"{path}: expected Git blob {expected_sha}, got {actual}")
    return json.loads(raw), actual


def contains(points: list[dict], x: float, z: float) -> bool:
    """Even-odd polygon containment, matching the Java server implementation."""
    if len(points) < 3:
        return False
    answer = False
    j = len(points) - 1
    for i, a in enumerate(points):
        b = points[j]
        if (a["_z"] > z) != (b["_z"] > z):
            boundary = (b["_x"] - a["_x"]) * (z - a["_z"]) / (b["_z"] - a["_z"]) + a["_x"]
            if x < boundary:
                answer = not answer
        j = i
    return answer


def bin_polygons(data: dict) -> tuple[list[dict], list[dict]]:
    parents = []
    children = []
    for block in data.get("OBKNAJCIHEA", []):
        parent = block.get("LKBLPFHOAFB") or {}
        parent_id = parent.get("BBLLBIOLMHP")
        parent_outline = (parent.get("JLFEAGHGCLP") or {}).get("BFLLDPOAJGD") or []
        parents.append({"id": parent_id, "points": parent_outline})
        for row in block.get("OPHHFKKPLDI") or []:
            outline = row.get("JLFEAGHGCLP") or {}
            children.append({
                "areaID1": row.get("BBLLBIOLMHP"),
                "areaID2": row.get("EOIFEEDBAFJ"),
                "points": outline.get("BFLLDPOAJGD") or [],
                "minY": (outline.get("MHLOLALFHHF") or {}).get("_y"),
                "maxY": (outline.get("NFFDCMLAAFO") or {}).get("_y"),
                "parent_points": parent_outline,
                "record_parent": parent_id,
            })
    return parents, children


def normalized_geometry(data: dict) -> list[dict]:
    """Canonicalize the *coordinates* of both obfuscated 7.1 and older 7.0 JSON.

    Later resource exports use {_x,_z}; historical exports use {x,z}.
    Compare numeric values and source order, not field-name spelling or bytes.
    """
    def point(p: dict) -> tuple[float | None, float | None]:
        return p.get("_x", p.get("x")), p.get("_z", p.get("z"))

    def y(obj: dict | None) -> float | None:
        return None if obj is None else obj.get("_y", obj.get("y"))

    def geometry(outline: dict) -> dict:
        return {
            "points": [point(p) for p in outline.get("BFLLDPOAJGD") or []],
            "minY": y(outline.get("MHLOLALFHHF")),
            "maxY": y(outline.get("NFFDCMLAAFO")),
        }

    result = []
    for block in data.get("OBKNAJCIHEA", []):
        parent = block["LKBLPFHOAFB"]
        result.append({
            "areaID1": parent["BBLLBIOLMHP"],
            "geometry": geometry(parent.get("JLFEAGHGCLP") or {}),
            "level2": [{
                "areaID1": child["BBLLBIOLMHP"],
                "areaID2": child["EOIFEEDBAFJ"],
                "geometry": geometry(child.get("JLFEAGHGCLP") or {}),
            } for child in block.get("OPHHFKKPLDI") or []],
        })
    return result


def interior_grid_crossings(parents: list[dict], children: list[dict],
                            resolution: int = GRID_RESOLUTION) -> list[dict]:
    """Find actual *interior* child witnesses outside the recorded level-1 polygon.

    A fixed grid over each child bounding box yields reproducible positive
    witnesses, but is not an exhaustive topology test. In particular an empty
    result does NOT prove the child is wholly contained by its parent.
    """
    if resolution < 1:
        raise ValueError("grid resolution must be positive")
    results = []
    for child in children:
        points = child["points"]
        parent = child["parent_points"]
        if len(points) < 3 or len(parent) < 3:
            continue
        min_x, max_x = min(p["_x"] for p in points), max(p["_x"] for p in points)
        min_z, max_z = min(p["_z"] for p in points), max(p["_z"] for p in points)
        in_parent = out_parent = 0
        first_outside = None
        for i in range(resolution):
            x = min_x + (max_x - min_x) * (i + 0.5) / resolution
            for j in range(resolution):
                z = min_z + (max_z - min_z) * (j + 0.5) / resolution
                if not contains(points, x, z):
                    continue
                if contains(parent, x, z):
                    in_parent += 1
                else:
                    out_parent += 1
                    if first_outside is None:
                        first_outside = {
                            "x": round(x, 2),
                            "z": round(z, 2),
                            "other_level1_ids": sorted(
                                p["id"] for p in parents
                                if p["id"] != child["record_parent"]
                                and contains(p["points"], x, z)
                            ),
                        }
        if out_parent:
            results.append({
                "areaID1": child["record_parent"],
                "areaID2": child["areaID2"],
                "inside_parent_samples": in_parent,
                "outside_parent_samples": out_parent,
                "witness": first_outside,
                "no_inside_parent_grid_samples": in_parent == 0,
            })
    return sorted(results, key=lambda row: row["areaID2"])


def intersection_fraction(a: dict, b: dict, c: dict, d: dict) -> float | None:
    """Fraction along AB crossing CD, or None for parallel/outside segments."""
    rx, rz = b["_x"] - a["_x"], b["_z"] - a["_z"]
    sx, sz = d["_x"] - c["_x"], d["_z"] - c["_z"]
    denominator = rx * sz - rz * sx
    if abs(denominator) < 1e-10:
        return None
    qx, qz = c["_x"] - a["_x"], c["_z"] - a["_z"]
    t = (qx * sz - qz * sx) / denominator
    u = (qx * rz - qz * rx) / denominator
    return t if 0 < t < 1 and 0 <= u <= 1 else None


def boundary_distance(points: list[dict], x: float, z: float) -> float:
    """Distance from X/Z to the closest polygon edge (world units)."""
    import math
    best = float("inf")
    for a, b in zip(points, points[1:] + points[:1]):
        dx, dz = b["_x"] - a["_x"], b["_z"] - a["_z"]
        squared = dx * dx + dz * dz
        fraction = max(0.0, min(1.0, (
            ((x - a["_x"]) * dx + (z - a["_z"]) * dz) / squared
            if squared else 0.0
        )))
        best = min(best, math.hypot(
            x - a["_x"] - fraction * dx,
            z - a["_z"] - fraction * dz,
        ))
    return best


def edge_interior_crossings(parents: list[dict], children: list[dict],
                            clearance: float = EDGE_CLEARANCE) -> list[dict]:
    """Find interior points outside parents near split child edges.

    Split each child edge at every proper intersection with a parent edge.
    Nudge each interval midpoint into the child using its signed winding,
    testing both polygons and requiring clearance to both outlines.
    Positive hits establish interior disagreement; non-hits do not prove
    containment, particularly around collinear or near-degenerate edges.
    """
    import math
    if clearance < 0:
        raise ValueError("clearance must not be negative")
    result = []
    for child in children:
        points, parent = child["points"], child["parent_points"]
        if len(points) < 3 or len(parent) < 3:
            continue
        winding = sum(
            a["_x"] * b["_z"] - b["_x"] * a["_z"]
            for a, b in zip(points, points[1:] + points[:1])
        )
        side = 1 if winding >= 0 else -1
        best = None
        for edge_index, (a, b) in enumerate(zip(points, points[1:] + points[:1])):
            dx, dz = b["_x"] - a["_x"], b["_z"] - a["_z"]
            length = math.hypot(dx, dz)
            if length < 1e-8:
                continue
            fractions = [0.0, 1.0]
            for c, d in zip(parent, parent[1:] + parent[:1]):
                t = intersection_fraction(a, b, c, d)
                if t is not None:
                    fractions.append(t)
            fractions.sort()
            for left, right in zip(fractions, fractions[1:]):
                if right - left < 1e-5:
                    continue
                t = (left + right) / 2
                base_x, base_z = a["_x"] + dx * t, a["_z"] + dz * t
                for offset in (0.01, 0.1, 0.5, 1.0, 2.0, 5.0):
                    x = base_x - side * dz / length * offset
                    z = base_z + side * dx / length * offset
                    if not contains(points, x, z) or contains(parent, x, z):
                        continue
                    margin = min(
                        boundary_distance(points, x, z),
                        boundary_distance(parent, x, z),
                    )
                    if margin <= clearance:
                        continue
                    if best is None or margin > best["margin"]:
                        best = {
                            "x": round(x, 4),
                            "z": round(z, 4),
                            "margin": round(margin, 4),
                            "child_edge": edge_index,
                            "other_level1_ids": sorted(
                                p["id"] for p in parents
                                if p["id"] != child["record_parent"]
                                and contains(p["points"], x, z)
                            ),
                        }
        if best is not None:
            result.append({
                "areaID1": child["record_parent"],
                "areaID2": child["areaID2"],
                "witness": best,
            })
    return sorted(result, key=lambda row: row["areaID2"])


def analyze(config_rows: list[dict], bin_data: dict, script_data: dict | None = None) -> dict:
    config = {
        r["areaID2"]: r
        for r in config_rows
        if r.get("sceneID") == 3 and r.get("MBOHIOJBBHO") == "LEVEL_2"
    }
    parents, children = bin_polygons(bin_data)
    counts = Counter(c["areaID2"] for c in children)
    missing = [
        {
            "areaID1": config[i]["areaID1"],
            "areaID2": i,
            "configID": config[i].get("ID", config[i].get("id")),
            "areaNameTextMapHash": config[i]["areaNameTextMapHash"],
        }
        for i in sorted(config) if i not in counts
    ]
    centroid_warnings = []
    for child in children:
        points, parent = child["points"], child["parent_points"]
        if len(points) < 3 or len(parent) < 3:
            continue
        x = sum(point["_x"] for point in points) / len(points)
        z = sum(point["_z"] for point in points) / len(points)
        # A concave polygon's centroid can be outside its *own* outline.
        # Only flag usable centroid witnesses inside child but outside parent.
        if contains(points, x, z) and not contains(parent, x, z):
            centroid_warnings.append({
                "areaID1": child["record_parent"],
                "areaID2": child["areaID2"],
                "centroid": {"x": round(x, 1), "z": round(z, 1)},
                "child_vertices_inside_parent": sum(
                    contains(parent, p["_x"], p["_z"]) for p in points
                ),
                "child_vertices_total": len(points),
            })
    script_subareas = (
        {
            c.get("id2")
            for p in script_data.get("level1Areas", [])
            for c in p.get("level2Areas", [])
        }
        if script_data is not None else None
    )
    return {
        "scope": "scene 3; static resource identities and polygon witnesses only",
        "configured_level2_ids": len(config),
        "level1_geometry_records": len(parents),
        "level2_geometry_polygons": len(children),
        "distinct_level2_geometry_ids": len(counts),
        "no_geometry_in_current_binary_source": missing,
        "duplicate_area_ids": {str(k): v for k, v in sorted(counts.items()) if v > 1},
        "child_centroid_outside_declared_parent": sorted(
            centroid_warnings, key=lambda x: x["areaID2"]
        ),
        "child_interior_outside_declared_parent": interior_grid_crossings(parents, children),
        "interior_grid_resolution": GRID_RESOLUTION,
        "child_edge_interior_outside_declared_parent": edge_interior_crossings(parents, children),
        "edge_clearance": EDGE_CLEARANCE,
        "script_geometry_level2_ids": len(script_subareas) if script_subareas is not None else None,
        "missing_ids_found_in_script": (
            sorted(set(row["areaID2"] for row in missing) & script_subareas)
            if script_subareas is not None else None
        ),
        "parent_match_conflicts": sorted({
            c["areaID2"] for c in children
            if c["areaID2"] in config and config[c["areaID2"]]["areaID1"] != c["areaID1"]
        }),
        "interpretation": {
            "missing_boundaries": "Not recovered; absence from these resources does not prove disabled in client",
            "parent_crossings": "Static geometry conflicts; client area-selection precedence unverified",
            "grid_scan": "Positive internal witnesses only; grid non-detection does not prove containment",
            "edge_scan": "Positive interior witnesses with clearance margin; non-detection is not containment proof",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", type=Path, required=True,
                        help="Exact 7.1 AstaPS-Resource root")
    parser.add_argument("--historic-resource-root", type=Path,
                        help="Optional historical LunaGCR/LunaGC resource root")
    parser.add_argument("--check", action="store_true",
                        help="Fail if the exact source IDs/counts change")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    paths = {
        "config": args.resources / "ExcelBinOutput/WorldAreaConfigData.json",
        "bin": args.resources / "BinOutput/Scene/WorldArea/scene3_worldArea.json",
        "script": args.resources / "Scripts/Scene/3/scene3_world_areas.json",
    }
    data = {}
    fingerprints = {}
    for name, path in paths.items():
        data[name], fingerprints[name] = source_file(
            path, PINNED_GIT_BLOBS[name] if args.check else None
        )
    report = analyze(data["config"], data["bin"], data["script"])
    report["evidence"] = {
        "repo": "MeChen618/AstaPS-Resource",
        "git_blobs": fingerprints,
        "source_role": "Community resource dump; not client native code proof",
    }
    if args.historic_resource_root:
        old, fingerprint = source_file(
            args.historic_resource_root / "BinOutput/Scene/WorldArea/scene3_worldArea.json"
        )
        _, earlier = bin_polygons(old)
        old_ids = {c["areaID2"] for c in earlier}
        historic_same_geometry = normalized_geometry(old) == normalized_geometry(data["bin"])
        current_normalized = normalized_geometry(data["bin"])
        report["historic"] = {
            "git_blob": fingerprint,
            "polygon_count": len(earlier),
            "area_ids": len(old_ids),
            "all_polygons_and_height_ranges_identical_after_field_normalization": historic_same_geometry,
            "level1_polygons_compared": len(current_normalized),
            "level2_polygons_compared": sum(len(p["level2"]) for p in current_normalized),
            "vertices_compared": sum(
                len(p["geometry"]["points"]) + sum(len(c["geometry"]["points"]) for c in p["level2"])
                for p in current_normalized
            ),
            "missing_7_1_ids_recovered": sorted(MISSING_7_1 & old_ids),
            "four_geometry_ids_present": sorted(PARENT_CENTROID_CONFLICTS_7_1 & old_ids),
        }
        if args.check:
            if fingerprint != "954b5506217d7a3d9e43474465ef769040adc480":
                raise ValueError("Historical WorldArea source is not the pinned LunaGCR 7.0 blob")
            assert historic_same_geometry, "Normalized geometry no longer matches historical data"
            assert report["historic"]["vertices_compared"] == 7598

    if args.check:
        assert report["configured_level2_ids"] == 409
        assert report["level1_geometry_records"] == 65
        assert report["level2_geometry_polygons"] == 400
        assert report["distinct_level2_geometry_ids"] == 396
        assert {x["areaID2"] for x in report["no_geometry_in_current_binary_source"]} == MISSING_7_1
        assert {x["areaID2"] for x in report["child_centroid_outside_declared_parent"]} == PARENT_CENTROID_CONFLICTS_7_1
        assert {x["areaID2"] for x in report["child_interior_outside_declared_parent"]} == GRID_CROSSINGS_7_1
        whole = [x["areaID2"] for x in report["child_interior_outside_declared_parent"]
                 if x["no_inside_parent_grid_samples"]]
        assert whole == [4104]
        assert {x["areaID2"] for x in report["child_edge_interior_outside_declared_parent"]} == EDGE_CROSSINGS_7_1
        assert report["missing_ids_found_in_script"] == []
        assert report["parent_match_conflicts"] == []

    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
