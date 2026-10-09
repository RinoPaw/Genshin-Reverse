#!/usr/bin/env python3
"""Collect 7.1 daily/boss Dungeon reward previews, NOT actual drop yields."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "versions/7.1.0-global/analyses/progression/7.1-dungeon-reward-previews.json"
SOURCE = "RinoPaw/AstaPS-Resource"
COMMIT = "b0f3a2791607cab2a4c24cb9ef249dd2d94d7ffd"
BLOBS = {
    "DungeonExcelConfigData.json": "92983c5d9d46bccf486b803b7cf65f2cdf9088cb",
    "RewardPreviewExcelConfigData.json": "a72b299e29c19007c48ed78b2e11aa33e274f98c",
}
TYPES = {"DUNGEON_DAILY_FIGHT", "DUNGEON_BOSS"}


def load_resources(directory: Path) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    data, evidence = {}, {}
    for filename, expected in BLOBS.items():
        raw = (directory / filename).read_bytes()
        actual = hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()
        if actual != expected:
            raise ValueError(f"{filename}: expected Git blob {expected}, got {actual}")
        rows = json.loads(raw)
        if not isinstance(rows, list):
            raise ValueError(f"{filename}: expected a JSON array")
        data[filename.removesuffix(".json")] = rows
        evidence[filename] = {"gitBlobSha": actual, "rowCount": len(rows)}
    return data, evidence


def build_snapshot(tables: dict[str, list[dict]], evidence: dict[str, dict]) -> dict:
    dungeons = tables["DungeonExcelConfigData"]
    previews = tables["RewardPreviewExcelConfigData"]
    indexed = {r["id"]: r for r in previews if r.get("id")}
    if len(indexed) != sum(bool(p.get("id")) for p in previews):
        raise ValueError("duplicate RewardPreview IDs")
    rows = []
    for row in sorted((x for x in dungeons if x.get("type") in TYPES),
                      key=lambda x: x["id"]):
        preview_id = row.get("passRewardPreviewID")
        preview = indexed[preview_id] if preview_id else None
        items = [
            {"itemId": item["id"], "displayCount": item.get("count") or None}
            for item in (preview.get("previewItems", []) if preview else [])
            if isinstance(item.get("id"), int) and item["id"] > 0
        ]
        rows.append({
            "dungeonId": row["id"],
            "type": row["type"],
            "subType": row.get("subType") or None,
            "stateType": row.get("stateType") or None,
            "sceneId": row["sceneId"],
            "cityId": row.get("cityID") or None,
            "showLevel": row.get("showLevel") or None,
            "limitLevel": row.get("limitLevel") or None,
            "resourceCostItemId": row.get("statueCostID") or None,
            "resourceCostCount": row.get("statueCostCount") or None,
            "dayEnterCount": row.get("dayEnterCount") or None,
            "passRewardPreviewId": preview_id or None,
            "previewDescription": preview.get("Desc") or None if preview else None,
            "previewItems": items,
        })
    daily = [r for r in rows if r["type"] == "DUNGEON_DAILY_FIGHT"]
    boss = [r for r in rows if r["type"] == "DUNGEON_BOSS"]
    subtypes = {
        str(k) if k is not None else "null": sum(r["subType"] == k for r in daily)
        for k in sorted(set(r["subType"] for r in daily), key=lambda x: x or "null")
    }
    unlinked = [r["dungeonId"] for r in rows if not r["passRewardPreviewId"]]
    if (len(daily), len(boss), unlinked) != (307, 66, [5116]):
        raise ValueError("unexpected Dungeon coverage or missing preview rows")
    if any(r["resourceCostItemId"] != 106 or r["resourceCostCount"] != 20
           for r in daily):
        raise ValueError("daily dungeon source cost differs from pinned rows")
    return {
        "schemaVersion": 1,
        "target": "Genshin Impact 7.1.0 Global",
        "scope": "DungeonExcel.passRewardPreviewID -> RewardPreviewExcel.id; preview only, not actual drops or runtime claim enforcement",
        "source": {
            "repository": SOURCE,
            "commit": COMMIT,
            "basePath": "ExcelBinOutput",
            "files": evidence,
        },
        "summary": {
            "dailyFightRows": len(daily),
            "dailyFightSubtypes": subtypes,
            "bossRows": len(boss),
            "linkedPreviewRows": len(rows) - len(unlinked),
            "noPreviewDungeonIds": unlinked,
            "dailyFightCostSourceRowsWithItem106Count20": sum(
                r["resourceCostItemId"] == 106 and r["resourceCostCount"] == 20
                for r in daily
            ),
        },
        "dungeons": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    tables, evidence = load_resources(args.resources)
    snapshot = build_snapshot(tables, evidence)
    if args.check:
        if json.loads(args.output.read_text(encoding="utf-8")) != snapshot:
            raise SystemExit("dungeon reward previews differ from pinned sources")
        print("PASS: pinned 7.1 dungeon preview rows match")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
