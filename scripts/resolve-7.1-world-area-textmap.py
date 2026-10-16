#!/usr/bin/env python3
"""Resolve 7.1 WorldArea names against both independent TextMap hash spaces.

Inputs are pinned to Genshin 7.1.0 and must not be mixed across builds.
Output retains absent hashes without guessing strings.
"""
from __future__ import annotations
import argparse
import json
from collections import Counter
from pathlib import Path

def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))

def resolve(areas, cities, plain, medium, independent_areas):
    if not all(isinstance(d, dict) for d in (plain, medium)):
        raise ValueError("TextMap source is not a flat hash -> string dictionary")
    collision = set(plain).intersection(medium)
    if collision:
        raise ValueError(f"TextMap plain/Medium share {len(collision)} hashes")
    key = lambda r: (r["sceneID"], r["areaID1"], r.get("areaID2", 0))
    own = {key(r): r for r in areas}
    other = {key(r): r for r in independent_areas}
    if own.keys() != other.keys():
        raise ValueError(f"WorldArea ID inventories differ (ours {len(own)}, independent {len(other)})")
    for idx, row in own.items():
        compare = other[idx]
        if row["areaNameTextMapHash"] != compare["areaNameTextMapHash"]:
            raise ValueError(f"WorldArea name hash differs for {idx}")
    city_ids = {}
    for city in cities:
        for aid in city["areaIdVec"]:
            if aid in city_ids:
                raise ValueError(f"Ambiguous city assignment for {aid}")
            city_ids[aid] = city["cityId"]
    if {x["areaID1"] for x in own.values() if x["MBOHIOJBBHO"] == "LEVEL_1"} != city_ids.keys():
        raise ValueError("CityConfig does not cover all level-1 ID records")
    resolved = []
    hits = Counter()
    for idx, row in sorted(own.items()):
        h = str(row["areaNameTextMapHash"])
        source = "plain" if h in plain else "medium" if h in medium else "missing"
        value = plain.get(h) if source == "plain" else medium.get(h) if source == "medium" else None
        hits[source] += 1
        resolved.append({"sceneID":idx[0], "areaID1":idx[1], "areaID2":idx[2],
                         "level":row["MBOHIOJBBHO"],"cityId":city_ids[idx[1]],
                         "nameTextMapHash":int(h), "name":value, "textMapSource":source})
    return {"status":"EXACT_7_1_WORLD_AREA_CROSS_CHECKED", "total":len(resolved),
            "nameSources":dict(hits), "areas":resolved}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--resource-root",type=Path,required=True)
    p.add_argument("--independent-root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    resource=args.resource_root
    independent=args.independent_root
    result=resolve(
        read(resource/"ExcelBinOutput/WorldAreaConfigData.json"),
        read(resource/"ExcelBinOutput/CityConfigData.json"),
        read(independent/"TextMap/TextMapCHS.json"),
        read(independent/"TextMap/TextMap_MediumCHS.json"),
        read(independent/"ExcelBinOutput/WorldAreaConfigData.json"))
    result["provenance"]={
        "areaConfig":"MeChen618/AstaPS-Resource@85b81a691fcf3d9e8e7db50a8febc8f9043bc084",
        "textMap":"DimbreathBot/AnimeGameData@792978e5503ecfba73dcb3562ed44a0d35a2abe2",
        "locale":"CHS",
        "warning":"TextMap is 7.1 CNREL; scene IDs and hashes are compared row-by-row against server WorldArea before acceptance"}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("WORLD_AREA_NAME_RESULT",json.dumps({"status":result["status"],
        "total":result["total"],"nameSources":result["nameSources"],
        "unresolved": [r for r in result["areas"] if r["name"] is None][:30]},ensure_ascii=False))
    print("WORLD_AREA_EXCEPTION_LABELS_BEGIN")
    print(json.dumps([r for r in result["areas"] if r["cityId"] in (1,2,3)
                      and r["name"] is not None],ensure_ascii=False))
    print("WORLD_AREA_EXCEPTION_LABELS_END")
    print("WORLD_AREA_COMPACT_ALL_BEGIN")
    print(json.dumps(result,ensure_ascii=False,separators=(",",":")))
    print("WORLD_AREA_COMPACT_ALL_END")

if __name__=="__main__":
    main()
