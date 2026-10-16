#!/usr/bin/env python3
"""Join authored chest gadgets to WorldArea, with source and ambiguity diagnostics.

Reuses AstaPS's existing scene gadget parser; does not allocate chest rewards.
Run with --server pointing at the audited AstaPS checkout and --resources at
the matching AstaPS-Resource checkout. The geometry is the community copy:
eight 7.1 native-changed child areas are explicitly marked uncertain.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import importlib.util
import json
from pathlib import Path
import re
from typing import Any

SCENE = re.compile(r"scene(\d+)_group")
POS = re.compile(r"\bpos\s*=\s*\{\s*x\s*=\s*([+-]?\d+(?:\.\d+)?)\s*,\s*y\s*=\s*([+-]?\d+(?:\.\d+)?)\s*,\s*z\s*=\s*([+-]?\d+(?:\.\d+)?)")
NATIVE_CHANGED = {5502, 5602, 5608, 5701, 5702, 5703, 5802, 5804}
SOURCE_REGIONS = ("蒙德", "璃月", "稻妻", "须弥", "枫丹", "纳塔", "至冬", "挪德卡莱", "诺德克莱", "雪山")
GRADE_NAMES = ("低级", "中级", "高级", "超级")
FIELDS = ("scene", "file", "config_id", "gadget_id", "x", "y", "z",
          "source", "drop_tag", "chest_drop_id", "lua_area_id",
          "city_id", "area1", "area2", "lookup_status", "source_region",
          "source_grade", "is_oneoff", "persistent", "explore_chest")


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def previous_scanner(server: Path):
    path = server / "tools/audit_chest_scene_exceptions.py"
    if not path.is_file():
        raise FileNotFoundError("Existing chest scanner missing: " + str(path))
    spec = importlib.util.spec_from_file_location("asta_chest_scene_scan", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inside(points: list[dict], x: float, z: float) -> bool:
    if len(points) < 3:
        return False
    if x < min(p["_x"] for p in points) or x > max(p["_x"] for p in points):
        return False
    if z < min(p["_z"] for p in points) or z > max(p["_z"] for p in points):
        return False
    hit = False
    j = len(points) - 1
    for i, p in enumerate(points):
        q = points[j]
        if (p["_z"] > z) != (q["_z"] > z) and x < (
            (q["_x"] - p["_x"]) * (z - p["_z"]) / (q["_z"] - p["_z"]) + p["_x"]
        ):
            hit = not hit
        j = i
    return hit


def shape(entry: dict) -> dict:
    return entry.get("JLFEAGHGCLP") or {}


def points_of(entry: dict) -> list[dict]:
    return shape(entry).get("BFLLDPOAJGD") or []


def world_index(resources: Path, definitions: list[dict]) -> dict[int, list[dict]]:
    """Map hashed geometry exports to scenes by exact parent-ID set."""
    by_scene = defaultdict(set)
    for row in definitions:
        if row["MBOHIOJBBHO"] == "LEVEL_1":
            by_scene[row["sceneID"]].add(row["areaID1"])
    found = {}
    for path in sorted((resources / "BinOutput/Scene/WorldArea").glob("*.json")):
        data = load(path)
        blocks = data.get("OBKNAJCIHEA") or []
        actual = {b["LKBLPFHOAFB"]["BBLLBIOLMHP"] for b in blocks}
        matches = [s for s, expected in by_scene.items() if actual == expected]
        if len(matches) != 1:
            raise ValueError(f"Cannot uniquely attribute WorldArea file {path}: {matches}")
        scene = matches[0]
        if scene in found:
            raise ValueError(f"Duplicate geometry for scene {scene}")
        found[scene] = blocks
    if found.keys() != by_scene.keys():
        raise ValueError(f"Missing geometry scenes: {sorted(by_scene.keys() - found.keys())}")
    return found


def choose(blocks: list[dict] | None, x: float, y: float, z: float) -> dict:
    if blocks is None:
        return {"area1": 0, "area2": 0, "lookup_status": "unmapped_scene"}
    for block in blocks:
        parent = block["LKBLPFHOAFB"]
        if not inside(points_of(parent), x, z):
            continue
        area1 = parent["BBLLBIOLMHP"]
        for sub in block.get("OPHHFKKPLDI") or []:
            if not inside(points_of(sub), x, z):
                continue
            height = shape(sub)
            lower = (height.get("MHLOLALFHHF") or {}).get("_y")
            upper = (height.get("NFFDCMLAAFO") or {}).get("_y")
            if lower is None or upper is None:
                return {"area1": area1, "area2": 0,
                        "lookup_status": "uncertain_height", "candidate_area2": sub["EOIFEEDBAFJ"]}
            if lower <= y <= upper:
                child = sub["EOIFEEDBAFJ"]
                return {"area1": area1, "area2": child,
                        "lookup_status": ("changed_native_geometry" if child in NATIVE_CHANGED and area1 in (55, 56, 57, 58) else "matched")}
        return {"area1": area1, "area2": 0, "lookup_status": "parent_only"}
    return {"area1": 0, "area2": 0, "lookup_status": "no_parent"}


def city_index(cities: list[dict], definitions: list[dict]) -> dict[int, int]:
    by_parent = {}
    for row in cities:
        for aid in row["areaIdVec"]:
            if aid in by_parent:
                raise ValueError(f"Duplicate city assignment for area1={aid}")
            by_parent[aid] = row["cityId"]
    defined = {row["areaID1"] for row in definitions if row["MBOHIOJBBHO"] == "LEVEL_1"}
    if by_parent.keys() != defined:
        raise ValueError("City entries and WorldArea parents differ")
    return by_parent


def collect(resources: Path, server: Path):
    scanner = previous_scanner(server)
    definitions = load(resources / "ExcelBinOutput/WorldAreaConfigData.json")
    cities = load(resources / "ExcelBinOutput/CityConfigData.json")
    by_parent = city_index(cities, definitions)
    geometry = world_index(resources, definitions)
    valid_gadgets = scanner.chest_types(load(resources / "ExcelBinOutput/GadgetExcelConfigData.json"))
    records = []
    counters = Counter()
    for path in sorted((resources / "Scripts/Scene").rglob("*.lua")):
        counters["lua_files"] += 1
        matched = SCENE.search(path.name)
        scene = int(matched.group(1)) if matched else 0
        text = path.read_text(encoding="utf-8", errors="replace")
        for entry in scanner.gadget_entries(text):
            gadget = scanner.num(entry, "gadget_id")
            if gadget not in valid_gadgets or "boss_chest" in entry:
                if gadget in valid_gadgets and "boss_chest" in entry:
                    counters["excluded_boss"] += 1
                continue
            counters["ordinary_chests"] += 1
            pos_match = POS.search(entry)
            position = [float(v) for v in pos_match.groups()] if pos_match else None
            lookup = choose(geometry.get(scene), *position) if position else {
                "area1": 0, "area2": 0, "lookup_status": "no_position"}
            lua_area_id = scanner.num(entry, "area_id")
            id_root = scanner.num(entry, "chest_drop_id")
            tag_match = scanner.TAG_RE.search(entry)
            tag = tag_match.group(1) if tag_match else ""
            source = "explicit_id" if id_root else ("drop_tag" if tag else "no_metadata")
            source_region = next((s for s in SOURCE_REGIONS if s in tag), "")
            grade = next((s for s in GRADE_NAMES if s in tag), "")
            row = {
                "scene": scene, "file": str(path.relative_to(resources)).replace("\\", "/"),
                "config_id": scanner.num(entry, "config_id"), "gadget_id": gadget,
                "x": position[0] if position else None,
                "y": position[1] if position else None,
                "z": position[2] if position else None,
                "source": source, "drop_tag": tag, "chest_drop_id": id_root,
                "lua_area_id": lua_area_id, "city_id": by_parent.get(lookup["area1"], 0),
                **lookup, "source_region": source_region, "source_grade": grade,
                "is_oneoff": bool(scanner.TRUE_RE("isOneoff").search(entry)),
                "persistent": bool(scanner.TRUE_RE("persistent").search(entry)),
                "explore_chest": bool(scanner.CHEST_EXPLORE_RE.search(entry)),
            }
            records.append(row)
            counters["source_" + source] += 1
            counters["lookup_" + row["lookup_status"]] += 1
            if lua_area_id and row["area1"] and lua_area_id != row["area1"]:
                counters["lua_area_id_differs_from_polygon"] += 1
    return records, counters


def summarize(records: list[dict], counts: Counter) -> dict:
    city_counts, area1_counts, area2_counts, sources_by_city = Counter(), Counter(), Counter(), Counter()
    area_disagreements = []
    changed = []
    unresolved = []
    tag_region_diffs = []
    low_area_counts = Counter()
    def region_expected(city: int) -> str:
        return {1: "蒙德", 2: "璃月", 3: "稻妻", 4: "须弥", 5: "枫丹", 6: "纳塔", 7: "挪德卡莱", 8: "至冬"}.get(city, "")
    for row in records:
        city, scene, a1, a2 = row["city_id"], row["scene"], row["area1"], row["area2"]
        city_counts[str(city)] += 1
        area1_counts[f"{scene}:{a1}"] += 1
        area2_counts[f"{scene}:{a1}:{a2}"] += 1
        sources_by_city[f"{city}:{row['source']}"] += 1
        if row["lua_area_id"] and a1 and row["lua_area_id"] != a1:
            if len(area_disagreements) < 50: area_disagreements.append(row)
        if row["lookup_status"] == "changed_native_geometry":
            if len(changed) < 100: changed.append(row)
        if row["lookup_status"] not in ("matched", "changed_native_geometry"):
            if len(unresolved) < 100: unresolved.append(row)
        named = row["source_region"]
        expected = region_expected(city)
        if expected and named and named not in (expected, "雪山") and not (
            expected == "挪德卡莱" and named in ("诺德克莱", "挪德卡莱")
        ):
            if len(tag_region_diffs) < 50: tag_region_diffs.append(row)
        if city in (1, 2):
            low_area_counts[f"{city}:{a1}:{row['source']}"] += 1
    def sorted_counts(c: Counter) -> dict:
        return dict(sorted(c.items(), key=lambda item: (-item[1], str(item[0]))))
    return {
        "status": "COMMUNITY_GEOMETRY_STATIC_CHEST_CLASSIFICATION_NOT_REWARD_PROOF",
        "totals": dict(counts),
        "city_counts": sorted_counts(city_counts),
        "area1_counts": sorted_counts(area1_counts),
        "area2_counts": sorted_counts(area2_counts),
        "sources_by_city": sorted_counts(sources_by_city),
        "mondstadt_liyue_candidates_by_area1_and_source": sorted_counts(low_area_counts),
        "lua_polygon_conflicts_samples": area_disagreements,
        "tag_region_conflict_samples": tag_region_diffs,
        "changed_native_geometry_samples": changed,
        "unresolved_geometry_samples": unresolved,
        "limits": [
            "Source metadata, GadgetExcel Chest type and position do not prove an ordinary treasure chest or Primogem payout.",
            "Area2 geometry is the 7.0-lineage community export; eight known changed native 7.1 child IDs are flagged, and results near their boundaries may change.",
            "14 absent original WorldArea child IDs are not synthesized.",
            "No low/high Primogem tier assigned without chest-specific or named-area evidence.",
            "Synthetic marker chest population is excluded and must be analyzed separately."
        ]
    }



def enrich_with_area_names(report: dict, records: list[dict], resources: Path) -> None:
    """Attach TextMap labels and audit grade distribution; never infer a payout."""
    config = load(resources / "ExcelBinOutput/WorldAreaConfigData.json")
    text_map = load(resources / "TextMap/TextMapCHS.json")
    if not isinstance(text_map, dict):
        raise ValueError("Expected TextMapCHS mapping")
    expected = {str(r["areaNameTextMapHash"]) for r in config
                if "areaNameTextMapHash" in r}
    candidates = [("(root)", text_map)]
    candidates.extend((str(key), value) for key, value in text_map.items()
                      if isinstance(value, dict))
    source_name, text_map = max(
        candidates, key=lambda candidate: sum(h in candidate[1] for h in expected))
    resolved_hashes = sum(h in text_map for h in expected)
    if resolved_hashes == 0:
        print("TEXTMAP_FORMAT_DIAGNOSTIC", json.dumps({
            "root_keys": [str(k) for k in list(candidates[0][1])[:12]],
            "candidate_names": [item[0] for item in candidates[:12]],
            "expected_hash_example": sorted(expected)[:8],
        }, ensure_ascii=False))
    def name_of(row: dict) -> str:
        value = text_map.get(str(row.get("areaNameTextMapHash", "")), "")
        return value if isinstance(value, str) else ""
    level1 = {(r["sceneID"], r["areaID1"]): r for r in config if r["MBOHIOJBBHO"] == "LEVEL_1"}
    level2 = {(r["sceneID"], r["areaID1"], r["areaID2"]): r
              for r in config if r["MBOHIOJBBHO"] == "LEVEL_2"}
    city_area_grade = Counter()
    city_grade = Counter()
    for row in records:
        city = row["city_id"]
        grade = row["source_grade"] or "(no_grade)"
        city_grade[f"{city}:{grade}"] += 1
        city_area_grade[f"{city}:{row['scene']}:{row['area1']}:{grade}"] += 1
    result = []
    for (scene, area1), config_row in sorted(level1.items()):
        count = report["area1_counts"].get(f"{scene}:{area1}", 0)
        city = next((r["city_id"] for r in records if r["scene"] == scene and r["area1"] == area1), 0)
        result.append({
            "scene": scene, "area1": area1, "cityId": city,
            "name": name_of(config_row), "chests": count,
            "tag_grades": {g: city_area_grade.get(f"{city}:{scene}:{area1}:{g}", 0)
                           for g in (*GRADE_NAMES, "(no_grade)")},
        })
    detail2 = []
    for (scene, area1, area2), config_row in sorted(level2.items()):
        detail2.append({
            "scene": scene, "area1": area1, "area2": area2,
            "name": name_of(config_row),
            "chests": report["area2_counts"].get(f"{scene}:{area1}:{area2}", 0),
        })
    labels = ("望风山地", "龙脊雪山", "雪山", "孤云阁", "璃沙郊", "层岩巨渊", "鹤观")
    candidates = []
    for entry in (*result, *detail2):
        hits = [k for k in labels if k in entry["name"]]
        if hits:
            candidates.append({**entry, "matched_keywords": hits})
    report["city_grade_counts"] = dict(sorted(city_grade.items()))
    report["level1_named_counts"] = result
    report["level2_named_counts"] = detail2
    report["named_reward_exception_candidates"] = candidates
    report["text_map_mapping"] = {"location": source_name, "resolved_hashes": resolved_hashes}
    report["area_names_resolved"] = {
        "level1": sum(bool(r["name"]) for r in result),
        "level2": sum(bool(r["name"]) for r in detail2),
    }
    report["pinned_source"] = {
        "resource_repository": "MeChen618/AstaPS-Resource",
        "resource_commit": "85b81a691fcf3d9e8e7db50a8febc8f9043bc084",
        "scanner_repository": "RinoPaw/AstaPS",
        "scanner_commit": "e2541630f5ae4d4c95b81f7440293d3419a776d1",
    }
    report["limits"].append(
        "TextMap name matches are geographical candidates, not validated Primogem-rate boundaries."
    )



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    args = parser.parse_args()
    records, counts = collect(args.resources, args.server)
    report = summarize(records, counts)
    enrich_with_area_names(report, records, args.resources)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.records.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with args.records.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    print("CHEST_REGION_AUDIT_BEGIN")
    print(json.dumps({
        "totals": report["totals"],
        "city_counts": report["city_counts"],
        "sources_by_city": report["sources_by_city"],
        "top_area1": list(report["area1_counts"].items())[:20],
        "sample_lua_conflicts": report["lua_polygon_conflicts_samples"][:5],
        "sample_tag_conflicts": report["tag_region_conflict_samples"][:5],
    }, ensure_ascii=False))
    print("CHEST_REGION_AUDIT_END")
    print("CHEST_REGION_FULL_SUMMARY_BEGIN")
    print(json.dumps({
        "totals": report["totals"], "city_counts": report["city_counts"],
        "city_grade_counts": report["city_grade_counts"],
        "area_names_resolved": report["area_names_resolved"],
        "level1_named_counts": report["level1_named_counts"],
        "named_reward_exception_candidates": report["named_reward_exception_candidates"],
    }, ensure_ascii=False))
    print("CHEST_REGION_FULL_SUMMARY_END")


if __name__ == "__main__":
    main()
