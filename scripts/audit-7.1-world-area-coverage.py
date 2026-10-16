#!/usr/bin/env python3
"""Audit 7.1 WorldArea definition/geometry coverage across every scene.

Includes the hash-named files for scenes 100-103 and 51195. No guessed
polygon replacements and no inference about native-client area precedence.

python scripts/audit-7.1-world-area-coverage.py --resources ../AstaPS-Resource --check
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

# Exact resource Git blobs (not native client validation).
CONFIG_BLOB = "ca05682b11a4cc742c4f98d4f610bf11c9ffe980"
GEOMETRY_BLOBS = {
    "scene3_worldArea.json": "d2687fe28c350d9c4684b0a29a5b24f3f6260936",
    "scene4_worldArea.json": "fddcbf8729fae48fa9c57590986cdd6b6d4c708f",
    "scene5_worldArea.json": "eeac8c02db3d2e085a06c937070b535f82f74ec7",
    "scene6_worldArea.json": "4a15f33e4e8e471cf02a1da54c33175719e8b1fd",
    "scene7_worldArea.json": "6928804f42ea8e85221596ef96eed7bf7858bbd5",
    "scene9_worldArea.json": "75c155bc95e0c213e979dac7d9c1792c0137d6dc",
    "scene10_worldArea.json": "9e6ba15ce87419097add61ad4c2c0eab25ccef94",
    "scene11_worldArea.json": "5c847ebf95003dba46f965ed6da4eb0f8a8b0c75",
    "f0d16079.json": "957e89f53772242d3223d9c3174acb59a121fd19",
    "8a14d94c.json": "6b2a9e37837cf1f662928b8197e8cb2873ca06cc",
    "fe22afa9.json": "40d5b6b28087762122fa401946ddbc40e3fc9152",
    "22149916.json": "4c108b5dcc660f1d7d32c1c41c432a4a7ec738b8",
    "e0bf65b8.json": "b68e4fb64b8824cbaf7bc86916dd5be423262782",
}
HISTORIC_7_0_BLOBS = {
    "scene3_worldArea.json": "954b5506217d7a3d9e43474465ef769040adc480",
    "scene4_worldArea.json": "a30d2de8ad0c98e3eca6767da60eb0d3df821386",
    "scene5_worldArea.json": "cbd73f19adcd1cfe7d7a9ce0e276770f93930ee9",
    "scene6_worldArea.json": "bd9cd2e35374d0d5065d1bb475a832b24d2e7648",
    "scene7_worldArea.json": "f73a3d0fe71ad4d667879f452c5792624bf0322c",
    "scene9_worldArea.json": "56d6f6b2c74fe291bb7af76e0bf828798c40da95",
    "scene10_worldArea.json": "7177376d5603bcdd6a70de9e54df8ef05e710f4b",
    "scene11_worldArea.json": "259c464c55c55b98795fa6065561f1cdcd2d7a33",
    "f0d16079.json": "ff28ba50286190d288a3547850b98340f70f41fe",
    "8a14d94c.json": "f7184aafcdc26235888a69727a4aa779356893c2",
    "fe22afa9.json": "533e35a56d56bffd10ce2254227654aa05dbab0b",
    "22149916.json": "82269984f16d64f73a02574029efcebff34adb9f",
    "e0bf65b8.json": "fa23d5b687ee264732d64669b23d10138021c176",
}
EXPECTED_MISSING = {(3, i) for i in (
    2501, 3120, 3512, 3602, 3912, 4105, 4107, 4301,
    4805, 4807, 4808, 7301, 7503,
)} | {(101, 80011)}


def normalized_geometry(data: dict) -> list[dict]:
    """Keep IDs, every vertex X/Z/Y and height bounds across old/new spelling."""
    def point(p: dict) -> tuple[float | None, float | None, float | None]:
        return (p.get("_x", p.get("x")),
                p.get("_z", p.get("z")),
                p.get("_y", p.get("y")))

    def bound_y(p: dict | None) -> float | None:
        return None if p is None else p.get("_y", p.get("y"))

    def shape(area: dict | None) -> dict:
        area = area or {}
        return {
            "points": [point(p) for p in area.get("BFLLDPOAJGD") or []],
            "minY": bound_y(area.get("MHLOLALFHHF")),
            "maxY": bound_y(area.get("NFFDCMLAAFO")),
        }

    return [
        {
            "areaID1": block["LKBLPFHOAFB"]["BBLLBIOLMHP"],
            "geometry": shape(block["LKBLPFHOAFB"].get("JLFEAGHGCLP")),
            "children": [
                {
                    "areaID1": child["BBLLBIOLMHP"],
                    "areaID2": child["EOIFEEDBAFJ"],
                    "geometry": shape(child.get("JLFEAGHGCLP")),
                }
                for child in block.get("OPHHFKKPLDI") or []
            ],
        }
        for block in data["OBKNAJCIHEA"]
    ]


def compare_historic(current: dict[str, dict], historical: dict[str, dict]) -> dict:
    if set(current) != set(historical):
        raise ValueError("historical file set does not match current set")
    files = []
    for filename in sorted(current):
        old, now = normalized_geometry(historical[filename]), normalized_geometry(current[filename])
        vertices = sum(
            len(parent["geometry"]["points"])
            + sum(len(child["geometry"]["points"]) for child in parent["children"])
            for parent in now
        )
        files.append({
            "file": filename,
            "geometry_identical": old == now,
            "level1_polygons": len(now),
            "level2_polygons": sum(len(parent["children"]) for parent in now),
            "vertices": vertices,
        })
    return {
        "comparison": "7.1-labelled dump versus Merprose2/LunaGCR-Resources:7.0 after coordinate-key normalization",
        "all_files_identical": all(row["geometry_identical"] for row in files),
        "total_vertices": sum(row["vertices"] for row in files),
        "files": files,
    }


def collect(config_rows: list[dict], geometry: dict[str, dict]) -> dict:
    scenes: dict[int, dict[str, list[dict]]] = {}
    for row in config_rows:
        scene = row["sceneID"]
        level = row["MBOHIOJBBHO"]
        if level not in ("LEVEL_1", "LEVEL_2"):
            raise ValueError(f"unexpected area level {level!r} in scene {scene}")
        scenes.setdefault(scene, {"LEVEL_1": [], "LEVEL_2": []})[level].append(row)

    result = []
    claimed = set()
    for filename, data in sorted(geometry.items()):
        blocks = data["OBKNAJCIHEA"]
        parents = [block["LKBLPFHOAFB"]["BBLLBIOLMHP"] for block in blocks]
        if len(set(parents)) != len(parents):
            raise ValueError(f"{filename}: duplicate level-1 ID")
        matching = [
            scene for scene, levels in scenes.items()
            if set(parents) == {row["areaID1"] for row in levels["LEVEL_1"]}
        ]
        if len(matching) != 1:
            raise ValueError(f"{filename}: expected exactly one scene by parent IDs; got {matching}")
        scene = matching[0]
        if scene in claimed:
            raise ValueError(f"scene {scene}: multiple geometry files")
        claimed.add(scene)
        defs = scenes[scene]["LEVEL_2"]
        configured = {row["areaID2"]: row for row in defs}
        if len(configured) != len(defs):
            raise ValueError(f"scene {scene}: repeated level-2 configuration ID")
        polygons = [
            (child["BBLLBIOLMHP"], child["EOIFEEDBAFJ"])
            for block in blocks for child in block.get("OPHHFKKPLDI") or []
        ]
        observed = Counter(area_id for _, area_id in polygons)
        extras = sorted(set(observed) - configured.keys())
        parent_mismatch = sorted({
            id2 for id1, id2 in polygons
            if id2 in configured and configured[id2]["areaID1"] != id1
        })
        missing = [
            {
                "areaID1": configured[id2]["areaID1"],
                "areaID2": id2,
                "configID": configured[id2].get("ID", configured[id2].get("id")),
            }
            for id2 in sorted(set(configured) - observed.keys())
        ]
        result.append({
            "sceneID": scene,
            "geometry_file": filename,
            "configured_level1": len(parents),
            "configured_level2": len(defs),
            "level2_polygon_records": len(polygons),
            "distinct_level2_polygons": len(observed),
            "missing_level2_geometry": missing,
            "extra_level2_geometry": extras,
            "parent_id_mismatch": parent_mismatch,
            "repeated_level2_polygon_ids": {
                str(k): v for k, v in sorted(observed.items()) if v > 1
            },
        })
    if claimed != scenes.keys():
        raise ValueError(f"unmatched scene definitions: {sorted(scenes.keys() - claimed)}")
    result.sort(key=lambda item: item["sceneID"])
    return {
        "scope": "All 7.1 resource WorldArea scene files, static definitions and polygon records",
        "source": "MeChen618/AstaPS-Resource community dump (not independently native-extracted)",
        "scene_count": len(result),
        "configured_level1": sum(len(d["LEVEL_1"]) for d in scenes.values()),
        "configured_level2": sum(len(d["LEVEL_2"]) for d in scenes.values()),
        "level2_polygon_records": sum(row["level2_polygon_records"] for row in result),
        "distinct_level2_polygons": sum(row["distinct_level2_polygons"] for row in result),
        "missing_level2_geometry": [
            {"sceneID": row["sceneID"], **missing}
            for row in result for missing in row["missing_level2_geometry"]
        ],
        "scenes": result,
    }




def predict_native_ordered_area_from_dump(
    scene_data: dict, x: float, y: float, z: float, scene_module: object,
) -> dict:
    """Static *community-data* model of observed native 7.1 traversal.

    The native method scans parents in array order using X/Z; children
    of the first parent hit use X/Z plus inclusive minY/maxY. Missing
    height bounds yield uncertainty, never invented infinity/zero.
    This is not an authoritative prediction for real 7.1 assets or
    world-state event sequencing.
    """
    for block in scene_data["OBKNAJCIHEA"]:
        parent = block["LKBLPFHOAFB"]
        pshape = parent.get("JLFEAGHGCLP") or {}
        if not scene_module.contains(pshape.get("BFLLDPOAJGD") or [], x, z):
            continue
        pid = parent["BBLLBIOLMHP"]
        for child in block.get("OPHHFKKPLDI") or []:
            shape = child.get("JLFEAGHGCLP") or {}
            if not scene_module.contains(shape.get("BFLLDPOAJGD") or [], x, z):
                continue
            min_y = (shape.get("MHLOLALFHHF") or {}).get("_y")
            max_y = (shape.get("NFFDCMLAAFO") or {}).get("_y")
            if min_y is None or max_y is None:
                return {
                    "status": "UNKNOWN_CHILD_HEIGHT",
                    "areaID1": pid, "candidate_areaID2": child["EOIFEEDBAFJ"],
                }
            if min_y <= y <= max_y:
                return {
                    "status": "CHILD_MATCH", "areaID1": pid,
                    "areaID2": child["EOIFEEDBAFJ"],
                }
        return {"status": "PARENT_ONLY", "areaID1": pid}
    return {"status": "NO_PARENT"}



def scan_parent_gated_disagreements(
    report: dict, geometry: dict[str, dict], scene_module: object,
) -> dict:
    """Positive child-minus-parent X/Z witnesses across every mapped scene.

    Parent polygon membership is required by the exact 7.1 client method
    CEBMPFCJPGE.INENBAGNECA; these coordinates still come from
    historically unchanged 7.0-labelled community resource polygons.
    """
    rows = []
    by_scene = []
    for scene in report["scenes"]:
        scene_id = scene["sceneID"]
        parents, children = scene_module.bin_polygons(
            geometry[scene["geometry_file"]]
        )
        hits = scene_module.edge_interior_crossings(
            parents, children, clearance=scene_module.EDGE_CLEARANCE
        )
        for hit in hits:
            rows.append({"sceneID": scene_id, **hit})
        by_scene.append({
            "sceneID": scene_id,
            "geometry_file": scene["geometry_file"],
            "positive_child_polygon_records": len(hits),
            "positive_child_ids": sorted({row["areaID2"] for row in hits}),
        })
    return {
        "method": "Boundary-split child interior witnesses outside recorded parent polygon; finite inward offsets",
        "native_7_1_selection_anchor": "CEBMPFCJPGE.INENBAGNECA@0xD1F6C70 gates child traversal behind parent polygon test",
        "geometry_provenance": "Pinned community resources numerically identical to 7.0 (not independently native 7.1 geometry)",
        "min_clearance_units": scene_module.EDGE_CLEARANCE,
        "total_positive_child_polygon_records": len(rows),
        "positive_child_ids": [
            {"sceneID": scene_id, "areaID2": area_id}
            for scene_id, area_id in sorted(
                {(row["sceneID"], row["areaID2"]) for row in rows}
            )
        ],
        "by_scene": by_scene,
        "interior_witnesses": sorted(
            rows, key=lambda row: (row["sceneID"], row["areaID2"])
        ),
        "limitations": [
            "Positive inside-child/outside-parent witnesses only; non-detection does not prove containment",
            "2D X/Z scan omits Y; exact client boolean mode flags and runtime event behavior are separately investigated",
        ],
    }


def main() -> None:
    import importlib.util
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--historic-resource-root", type=Path,
                        help="Exact Merprose2/LunaGCR-Resources 7.0 checkout")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    # Reuse the pin-aware loader from the owning scene-3 research script.
    tool = Path(__file__).with_name("audit-7.1-world-areas.py")
    spec = importlib.util.spec_from_file_location("audit_world_area_71_scene3", tool)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config, config_sha = module.source_file(
        args.resources / "ExcelBinOutput/WorldAreaConfigData.json",
        CONFIG_BLOB if args.check else None,
    )
    directory = args.resources / "BinOutput/Scene/WorldArea"
    observed_files = {p.name for p in directory.glob("*.json")}
    if args.check and observed_files != set(GEOMETRY_BLOBS):
        raise ValueError(f"resource file set changed: {sorted(observed_files ^ set(GEOMETRY_BLOBS))}")
    geometry = {}
    source_blobs = {}
    for filename in sorted(observed_files):
        data, sha = module.source_file(
            directory / filename,
            GEOMETRY_BLOBS.get(filename) if args.check else None,
        )
        geometry[filename] = data
        source_blobs[filename] = sha
    report = collect(config, geometry)
    report["cross_scene_parent_gate_geometry"] = scan_parent_gated_disagreements(
        report, geometry, module,
    )
    report["source_pins"] = {"config_blob": config_sha, "geometry_blobs": source_blobs}
    if args.historic_resource_root:
        historic = {}
        blobs = {}
        root = args.historic_resource_root / "BinOutput/Scene/WorldArea"
        for filename in sorted(observed_files):
            data, sha = module.source_file(
                root / filename,
                HISTORIC_7_0_BLOBS.get(filename) if args.check else None,
            )
            historic[filename] = data
            blobs[filename] = sha
        report["historical_comparison"] = compare_historic(geometry, historic)
        report["source_pins"]["historic_7_0_geometry_blobs"] = blobs
    if args.check:
        assert report["scene_count"] == 13
        assert report["configured_level1"] == 90
        assert report["configured_level2"] == 488
        assert report["level2_polygon_records"] == 480
        assert report["distinct_level2_polygons"] == 474
        crossings = report["cross_scene_parent_gate_geometry"]
        assert crossings["total_positive_child_polygon_records"] == 24
        assert {(row["sceneID"], row["areaID2"]) for row in crossings["interior_witnesses"]} == (
            {(3, area_id) for area_id in (
                201, 202, 2102, 2504, 3003, 3004, 3204, 3205,
                3302, 3407, 3408, 3604, 3606, 4004, 4005, 4103,
                4104, 4109, 4702, 5209, 5210, 5502, 5602,
            )} | {(7, 21001)}
        )
        assert {(r["sceneID"], r["areaID2"]) for r in report["missing_level2_geometry"]} == EXPECTED_MISSING
        if args.historic_resource_root:
            assert set(HISTORIC_7_0_BLOBS) == set(GEOMETRY_BLOBS)
            assert report["historical_comparison"]["all_files_identical"]
            assert report["historical_comparison"]["total_vertices"] == 9167
        assert not any(row["extra_level2_geometry"] or row["parent_id_mismatch"]
                       for row in report["scenes"])
    value = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(value, encoding="utf-8")
    else:
        print(value, end="")


if __name__ == "__main__":
    main()
