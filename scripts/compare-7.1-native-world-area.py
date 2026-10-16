#!/usr/bin/env python3
"""Compare fully decoded official 7.1 WorldArea with pinned community JSON.

Per-source SHA-256/Git-blob validation and strict binary full consumption
precede all comparisons. Reports are metadata/difference summaries, never
copies of original client polygon assets.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import urllib.request

from genshinre.assetindex import unwrap_mihoyo_bin_data
from genshinre.worldareabin import decode_world_area

HERE = Path(__file__).resolve().parents[1]
ANALYSIS = HERE / "versions/7.1.0-global/analyses/progression/world"
RESOURCE_COMMIT = "85b81a691fcf3d9e8e7db50a8febc8f9043bc084"
GEOMETRY_AUDITOR = HERE / "scripts/audit-7.1-world-area-coverage.py"
TOLERANCE = 0.0001


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def source_pins() -> dict:
    spec = importlib.util.spec_from_file_location("world_area_pinned_geometry_71", GEOMETRY_AUDITOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.GEOMETRY_BLOBS


def native_shape(record: dict | None) -> dict:
    shape = (record or {}).get("offset_0x10_shape") or {}
    vertices = (shape.get("offset_0x18_vertices") or {}).get("points", [])
    def bound(key):
        return ((shape.get(key) or {}).get("coordinates") or {}).get("y")
    return {
        "vertices": [p["coordinates"] for p in vertices],
        "minY": bound("offset_0x24_vector"),
        "maxY": bound("offset_0x30_vector"),
    }


def community_shape(record: dict | None) -> dict:
    shape = (record or {}).get("JLFEAGHGCLP") or {}
    pts = shape.get("BFLLDPOAJGD") or []
    return {
        "vertices": [
            {"x": point.get("_x"), "y": point.get("_y"), "z": point.get("_z")}
            for point in pts
        ],
        "minY": ((shape.get("MHLOLALFHHF") or {}).get("_y")),
        "maxY": ((shape.get("NFFDCMLAAFO") or {}).get("_y")),
    }


def shape_differences(native: dict, legacy: dict, label: str) -> list[dict]:
    a, b = native_shape(native), community_shape(legacy)
    changes: list[dict] = []
    if len(a["vertices"]) != len(b["vertices"]):
        changes.append({
            "record": label, "kind": "VERTEX_COUNT",
            "native": len(a["vertices"]), "community": len(b["vertices"]),
        })
    for bound in ("minY", "maxY"):
        old, new = b[bound], a[bound]
        if (old is None) != (new is None) or (
            old is not None and new is not None and abs(float(old) - float(new)) > TOLERANCE
        ):
            changes.append({"record": label, "kind": "HEIGHT_BOUND",
                            "field": bound, "native": new, "community": old})
    changed_components = Counter()
    first_diff = None
    for i, (p, q) in enumerate(zip(a["vertices"], b["vertices"])):
        for axis in ("x", "y", "z"):
            old, new = q[axis], p[axis]
            if (old is None) != (new is None) or (
                old is not None and new is not None and abs(float(old) - float(new)) > TOLERANCE
            ):
                changed_components[axis] += 1
                if first_diff is None:
                    first_diff = {"vertexIndex": i, "axis": axis,
                                  "native": new, "community": old}
    if changed_components:
        changes.append({
            "record": label, "kind": "VERTEX_COORDINATES",
            "changedComponents": dict(changed_components), "firstDifference": first_diff,
        })
    return changes


def group_records(items: list[dict], key):
    result = defaultdict(list)
    for item in items:
        result[key(item)].append(item)
    return result


def compare_scene(native_tree: dict, source: dict, scene_id: int) -> dict:
    native_parents = native_tree["parents"]
    legacy_parents = source["OBKNAJCIHEA"]
    def native_id(p): return (p.get("area_record") or {}).get("offset_0x18_u32")
    def legacy_id(p): return p["LKBLPFHOAFB"]["BBLLBIOLMHP"]
    ni = [native_id(p) for p in native_parents]
    oi = [legacy_id(p) for p in legacy_parents]
    ng, og = group_records(native_parents, native_id), group_records(legacy_parents, legacy_id)
    differences = []
    if ni != oi:
        differences.append({
            "kind": "PARENT_ORDER_OR_ID", "native": ni, "community": oi,
        })
    for parent_id in sorted(set(ng) | set(og), key=lambda x: (-1 if x is None else x)):
        na, oa = ng.get(parent_id, []), og.get(parent_id, [])
        if len(na) != len(oa):
            differences.append({"kind": "PARENT_OCCURRENCE", "areaID1": parent_id,
                                "native": len(na), "community": len(oa)})
        for occurrence, (np, op) in enumerate(zip(na, oa)):
            label = f"parent:{parent_id}:{occurrence}"
            differences += shape_differences(np["area_record"], op["LKBLPFHOAFB"], label)
            nc = (np.get("child_array") or {}).get("values", [])
            oc = op.get("OPHHFKKPLDI") or []
            def nk(q): return (q.get("offset_0x18_u32"), q.get("offset_0x1C_u32"))
            def ok(q): return (q.get("BBLLBIOLMHP"), q.get("EOIFEEDBAFJ"))
            nids, oids = list(map(nk, nc)), list(map(ok, oc))
            if nids != oids:
                differences.append({
                    "kind": "CHILD_ORDER_OR_ID", "parent": parent_id,
                    "native": nids, "community": oids,
                })
            nn, oo = group_records(nc, nk), group_records(oc, ok)
            for cid in sorted(set(nn) | set(oo)):
                nv, ov = nn.get(cid, []), oo.get(cid, [])
                if len(nv) != len(ov):
                    differences.append({
                        "kind": "CHILD_OCCURRENCE", "parent": parent_id,
                        "areaID1": cid[0], "areaID2": cid[1],
                        "native": len(nv), "community": len(ov),
                    })
                for cidx, (cr, co) in enumerate(zip(nv, ov)):
                    differences += shape_differences(
                        cr, co, f"child:{parent_id}:{cid[1]}:{cidx}"
                    )
    nchild = sum(len((p.get("child_array") or {}).get("values", [])) for p in native_parents)
    ochild = sum(len(p.get("OPHHFKKPLDI") or []) for p in legacy_parents)
    nverts = sum(len(native_shape(p["area_record"])["vertices"]) +
                 sum(len(native_shape(c)["vertices"]) for c in
                     (p.get("child_array") or {}).get("values", []))
                 for p in native_parents)
    overts = sum(len(community_shape(p["LKBLPFHOAFB"])["vertices"]) +
                 sum(len(community_shape(c)["vertices"]) for c in p.get("OPHHFKKPLDI") or [])
                 for p in legacy_parents)
    return {
        "sceneID": scene_id,
        "nativeParentCount": len(native_parents),
        "communityParentCount": len(legacy_parents),
        "nativeChildCount": nchild,
        "communityChildCount": ochild,
        "nativeVertexCount": nverts,
        "communityVertexCount": overts,
        "differenceCount": len(differences),
        "differenceByKind": dict(sorted(Counter(x["kind"] for x in differences).items())),
        "differences": differences,
    }


def compare_all(native_export: Path, coverage_file: Path, manifest_file: Path,
                *, source_root: Path | None = None) -> dict:
    coverage = json.loads(coverage_file.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    pins = source_pins()
    scene_files = {x["sceneID"]: x["geometry_file"] for x in coverage["scenes"]}
    rows = []
    for entry in manifest["assets"]:
        scene = entry["sceneID"]
        src_name = scene_files[scene]
        path = native_export / "MiHoYoBinData" / (entry["exportedName"] + ".dat")
        original = path.read_bytes()
        if hashlib.sha256(original).hexdigest() != entry["rawSha256"]:
            raise ValueError(f"official raw SHA-256 mismatch scene {scene}")
        payload = unwrap_mihoyo_bin_data(original)
        if hashlib.sha256(payload).hexdigest() != entry["payloadSha256"]:
            raise ValueError(f"official payload SHA-256 mismatch scene {scene}")
        native = decode_world_area(payload)
        if source_root is None:
            url = (
                f"https://raw.githubusercontent.com/MeChen618/AstaPS-Resource/"
                f"{RESOURCE_COMMIT}/BinOutput/Scene/WorldArea/{src_name}"
            )
            with urllib.request.urlopen(url, timeout=45) as response:
                source_bytes = response.read()
        else:
            source_bytes = (source_root / src_name).read_bytes()
        if blob_sha(source_bytes) != pins[src_name]:
            raise ValueError(f"community source Git blob changed for {src_name}")
        source = json.loads(source_bytes)
        row = compare_scene(native, source, scene)
        row["nativePayloadSha256"] = entry["payloadSha256"]
        row["communityGitBlob"] = pins[src_name]
        row["sourceFilename"] = src_name
        rows.append(row)
    rows.sort(key=lambda x: x["sceneID"])
    return {
        "status": "NATIVE_7_1_GEOMETRY_COMPARED_WITH_PINNED_COMMUNITY_DUMP",
        "sourceRef": f"MeChen618/AstaPS-Resource@{RESOURCE_COMMIT}",
        "originalPayloadManifest": str(manifest_file),
        "comparisonTolerance": TOLERANCE,
        "sceneCount": len(rows),
        "changedSceneCount": sum(x["differenceCount"] > 0 for x in rows),
        "nativeVertexCount": sum(x["nativeVertexCount"] for x in rows),
        "communityVertexCount": sum(x["communityVertexCount"] for x in rows),
        "differenceCount": sum(x["differenceCount"] for x in rows),
        "scenes": rows,
        "limitations": [
            "Object member aliases (area IDs, polygon vertices, height bounds) are corroborated from decoded values but remain subject to independent native loader semantics.",
            "Numeric comparison uses 1e-4 absolute tolerance to accommodate source float rendering.",
            "Only exactly paired polygon records are coordinate-compared; unmatched area keys are preserved as separate differences.",
            "No native original polygons or source assets are redistributed in this report.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--world-export", type=Path, required=True)
    p.add_argument("--source-root", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = compare_all(
        args.world_export,
        ANALYSIS / "7.1-all-world-area-scene-coverage.json",
        ANALYSIS / "7.1-native-world-area-raw-assets.json",
        source_root=args.source_root,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("WORLD_AREA_NATIVE_GEOMETRY_COMPARISON_BEGIN")
    print(json.dumps({
        "status": result["status"], "nativeVertexCount": result["nativeVertexCount"],
        "communityVertexCount": result["communityVertexCount"],
        "changedSceneCount": result["changedSceneCount"],
        "differenceCount": result["differenceCount"],
        "scenes": [
            {"sceneID": x["sceneID"], "nativeChildCount": x["nativeChildCount"],
             "communityChildCount": x["communityChildCount"],
             "nativeVertexCount": x["nativeVertexCount"],
             "communityVertexCount": x["communityVertexCount"],
             "differenceCount": x["differenceCount"],
             "differences": x["differences"]}
            for x in result["scenes"]
        ],
    }, indent=2))
    print("WORLD_AREA_NATIVE_GEOMETRY_COMPARISON_END")


if __name__ == "__main__":
    main()
