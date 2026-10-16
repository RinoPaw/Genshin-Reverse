"""Audit native 7.1 decoded WorldArea against pinned 7.0-lineage JSON.

This is a read-only comparison. It does not silently replace native absent
fields, reorder vertices, or infer a polygon that is not in either source.
"""
from __future__ import annotations

from collections import Counter

EPSILON = 0.001


def get_number(row: dict | None, key: str) -> float | None:
    if row is None:
        return None
    return row.get("_" + key, row.get(key))


def compare_shape(native: dict | None, community: dict | None,
                  *, label: dict) -> dict | None:
    community = community or {}
    expected = community.get("BFLLDPOAJGD") or []
    observed = ((native or {}).get("offset_0x18_vertices") or {}).get("points") or []
    problems = []
    if len(expected) != len(observed):
        problems.append("vertex_count")
    compared = min(len(expected), len(observed))
    different_coords = 0
    first_diffs = []
    for i in range(compared):
        old = expected[i]
        now = observed[i]["coordinates"]
        for name in ("x", "y", "z"):
            want = get_number(old, name)
            have = now.get(name)
            # Older dumps omit polygon vertex Y. Its absence is not
            # evidence that the native source lacked that component.
            if name == "y" and want is None:
                continue
            if want is None and have is None:
                continue
            if want is None or have is None or abs(want - have) > EPSILON:
                different_coords += 1
                if len(first_diffs) < 4:
                    first_diffs.append({
                        "pointIndex": i, "axis": name,
                        "historical": want, "native7_1": have,
                    })
    bounds = []
    for native_key, historical_key, semantic in (
        ("offset_0x24_vector", "MHLOLALFHHF", "minY"),
        ("offset_0x30_vector", "NFFDCMLAAFO", "maxY"),
    ):
        old = get_number(community.get(historical_key), "y")
        record = (native or {}).get(native_key)
        val = None if record is None else record["coordinates"]["y"]
        if (old is None) != (val is None) or (
            old is not None and val is not None and abs(old-val) > EPSILON
        ):
            bounds.append({"field": semantic, "historical": old, "native7_1": val})
    if different_coords:
        problems.append("vertex_coordinates")
    if bounds:
        problems.append("height_bounds")
    if not problems:
        return None
    return {
        **label,
        "issues": problems,
        "historicalVertexCount": len(expected),
        "native7_1VertexCount": len(observed),
        "differentCoordinateCount": different_coords,
        "sampleCoordinateDiffs": first_diffs,
        "heightDiffs": bounds,
    }


def compare_scene(native_tree: dict, community: dict, scene_id: int) -> dict:
    old_parents = community["OBKNAJCIHEA"]
    new_parents = native_tree["parents"]
    mismatches = []
    id_problems = []
    old_child_ids = []
    native_child_ids = []
    old_total = 0
    native_total = 0
    old_child_count = 0
    native_child_count = 0
    for i in range(max(len(old_parents),len(new_parents))):
        if i >= len(old_parents) or i >= len(new_parents):
            id_problems.append({"index":i,"reason":"parent array length mismatch"})
            continue
        old=old_parents[i]
        p=old["LKBLPFHOAFB"]
        old_pid=p["BBLLBIOLMHP"]
        record=new_parents[i]["area_record"]
        native_pid=None if record is None else record["offset_0x18_u32"]
        if old_pid != native_pid:
            id_problems.append({"parentIndex":i,"communityId":old_pid,"nativeId":native_pid})
        old_shape=p.get("JLFEAGHGCLP") or {}
        native_shape=None if record is None else record["offset_0x10_shape"]
        mismatch=compare_shape(native_shape,old_shape,label={
            "level":1,"areaID1":old_pid,"areaID2":None
        })
        if mismatch:
            mismatches.append(mismatch)
        old_total+=len(old_shape.get("BFLLDPOAJGD") or [])
        native_total+=len(((native_shape or {}).get("offset_0x18_vertices") or {}).get("points") or [])
        old_children=old.get("OPHHFKKPLDI") or []
        native_children=(new_parents[i]["child_array"] or {}).get("values") or []
        old_child_count+=len(old_children)
        native_child_count+=len(native_children)
        for c in old_children:
            old_child_ids.append((old_pid,c["EOIFEEDBAFJ"]))
        for c in native_children:
            native_child_ids.append((native_pid,c["offset_0x1C_u32"]))
        for ci in range(max(len(old_children),len(native_children))):
            if ci>=len(old_children) or ci>=len(native_children):
                id_problems.append({"parentID":old_pid,"childIndex":ci,
                                   "reason":"child array length mismatch"})
                continue
            left=old_children[ci]
            right=native_children[ci]
            old_id1=left["BBLLBIOLMHP"]
            old_id2=left["EOIFEEDBAFJ"]
            if (old_id1,old_id2)!=(right["offset_0x18_u32"],right["offset_0x1C_u32"]):
                id_problems.append({
                    "parentID":old_pid, "childIndex":ci,
                    "communityIds":[old_id1,old_id2],
                    "nativeIds":[right["offset_0x18_u32"],right["offset_0x1C_u32"]],
                })
            old_shape=left.get("JLFEAGHGCLP") or {}
            right_shape=right.get("offset_0x10_shape")
            mismatch=compare_shape(right_shape,old_shape,label={
                "level":2,"areaID1":old_pid,"areaID2":old_id2
            })
            if mismatch:
                mismatches.append(mismatch)
            old_total+=len(old_shape.get("BFLLDPOAJGD") or [])
            native_total+=len(((right_shape or {}).get("offset_0x18_vertices") or {}).get("points") or [])
    community_ids=Counter(old_child_ids)
    original_ids=Counter(native_child_ids)
    native_extras=list((original_ids-community_ids).elements())
    community_extras=list((community_ids-original_ids).elements())
    return {
        "sceneID":scene_id,
        "rootRecords":{"community":len(old_parents),"native7_1":len(new_parents)},
        "childRecords":{"community":old_child_count,"native7_1":native_child_count},
        "vertices":{"community":old_total,"native7_1":native_total,"delta":native_total-old_total},
        "parentChildIdSequenceMatches":not id_problems,
        "nativeExtraChildIds":[list(x) for x in sorted(native_extras)],
        "communityExtraChildIds":[list(x) for x in sorted(community_extras)],
        "idProblems":id_problems[:40],
        "changedGeometryCount":len(mismatches),
        "changedGeometry":mismatches[:50],
        "changedGeometryTruncated":len(mismatches)>50,
        "allComparedCoordinatesWithinTolerance":not mismatches,
        "coordinateToleranceWorldUnits":EPSILON,
    }
